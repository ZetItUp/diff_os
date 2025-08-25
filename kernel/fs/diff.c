#include "diff.h"
#include "stdio.h"
#include "string.h"
#include "stddef.h"
#include "heap.h"
#include "drivers/ata.h"
#include "system/spinlock.h"

// Local helpers without locks
static int find_entry_by_path_nolock(const FileTable* table, const char* path);
static int path_next_token(char** it, char* out, size_t out_sz);

// Global filesystem state
SuperBlock superblock;
FileTable* file_table;
static uint8_t* file_bitmap;
static uint8_t* sector_bitmap;
static spinlock_t file_table_lock;
static spinlock_t sector_bitmap_lock;

extern volatile int g_in_irq;

// Low level disk I/O

int disk_read(uint32_t sector, uint32_t count, void* buffer)
{
    int r = ata_read(sector, count, buffer);

    return r;
}

int disk_write(uint32_t sector, uint32_t count, const void* buffer)
{
    int r = ata_write(sector, count, buffer);

    return r;
}

// Superblock and tables

int read_file_table(const SuperBlock* sb)
{
    size_t table_bytes;
    size_t bitmap_bytes_disk;
    size_t bitmap_bytes_mem;
    size_t bitmap_bytes_alloc;
    size_t on_disk_entries;
    FileTable* new_table;
    uint8_t* new_bitmap;
    int r;

    // Sizes on disk in bytes
    table_bytes = (size_t)sb->file_table_size * SECTOR_SIZE;
    bitmap_bytes_disk = (size_t)sb->file_table_bitmap_size * SECTOR_SIZE;

    // Each FileEntry is packed 320 bytes; require at least one and exact multiple
    if (table_bytes < sizeof(FileEntry) || (table_bytes % sizeof(FileEntry)) != 0)
    {
        printf("[Diff FS] ERROR: file_table size invalid on disk (bytes=%u, entry=%u)\n",
               (unsigned)table_bytes, (unsigned)sizeof(FileEntry));

        return -1;
    }

    on_disk_entries = table_bytes / sizeof(FileEntry);

#ifdef DIFF_DEBUG
    printf("FileTable sizeof=%u, on-disk bytes=%u (%u entries)\n",
           (unsigned)sizeof(FileTable), (unsigned)table_bytes, (unsigned)on_disk_entries);
#endif
    // Always allocate full in-memory table (for MAX_FILES), zero it,
    // then read the smaller on-disk table into the beginning.
    new_table = (FileTable*)kmalloc(sizeof(FileTable));

    if (!new_table)
    {
        printf("[Diff FS] ERROR: OOM for file_table (%u bytes)\n", (unsigned)sizeof(FileTable));

        return -1;
    }

    memset(new_table, 0, sizeof(FileTable));

    // Read only what exists on disk (table_bytes)
    r = disk_read(sb->file_table_sector, sb->file_table_size, new_table);

    if (r < 0)
    {
        printf("[Diff FS] ERROR: disk_read(file_table) failed\n");
        kfree(new_table);

        return -1;
    }

    // Prepare file entry bitmap:
    // - in-memory we want enough bits for MAX_FILES
    // - but we must be able to read however many bytes exist on disk
    bitmap_bytes_mem = (size_t)((MAX_FILES + 7) / 8);
    bitmap_bytes_alloc = (bitmap_bytes_disk > bitmap_bytes_mem) ? bitmap_bytes_disk : bitmap_bytes_mem;

    if (bitmap_bytes_alloc == 0)
    {
        printf("[Diff FS] ERROR: file_table bitmap size is zero on disk\n");
        kfree(new_table);

        return -1;
    }

    new_bitmap = (uint8_t*)kmalloc(bitmap_bytes_alloc);

    if (!new_bitmap)
    {
        printf("[Diff FS] ERROR: OOM for file_bitmap (%u bytes)\n", (unsigned)bitmap_bytes_alloc);
        kfree(new_table);

        return -1;
    }

    memset(new_bitmap, 0, bitmap_bytes_alloc);

    r = disk_read(sb->file_table_bitmap_sector, sb->file_table_bitmap_size, new_bitmap);

    if (r < 0)
    {
        printf("[Diff FS] ERROR: disk_read(file_bitmap) failed\n");
        kfree(new_bitmap);
        kfree(new_table);

        return -1;
    }

    // Publish atomically
    spin_lock(&file_table_lock);
    file_table = new_table;
    file_bitmap = new_bitmap;
    spin_unlock(&file_table_lock);

    return 0;
}

int read_superblock(SuperBlock* sb)
{
    // Superblock is at a fixed sector
    int r = disk_read(2048, 1, sb);

    if (r < 0)
    {
        return -1;
    }

    return 0;
}

int init_filesystem(void)
{
    int r;

    // Init locks before touching globals
    spinlock_init(&file_table_lock);
    spinlock_init(&sector_bitmap_lock);

    // Load superblock first
    r = read_superblock(&superblock);

    if (r < 0)
    {
        printf("[Diff FS] ERROR: Unable to read superblock!\n");

        return -1;
    }

    // Then load file table and its bitmap
    r = read_file_table(&superblock);

    if (r != 0)
    {
        printf("[Diff FS] ERROR: Unable to read file table!\n");

        return -1;
    }

    return 0;
}

// ASCII case insensitive compare

static int ascii_stricmp(const char* a, const char* b)
{
    // Fold to lowercase and compare
    unsigned char ca;
    unsigned char cb;

    for (;;)
    {
        ca = (unsigned char)*a++;
        cb = (unsigned char)*b++;

        if (ca >= 'A' && ca <= 'Z')
        {
            ca = (unsigned char)(ca - 'A' + 'a');
        }

        if (cb >= 'A' && cb <= 'Z')
        {
            cb = (unsigned char)(cb - 'A' + 'a');
        }

        if (ca != cb || ca == '\0' || cb == '\0')
        {
            int diff = (int)ca - (int)cb;

            return diff;
        }
    }
}

// Directory and path helpers

static uint32_t detect_root_id(const FileTable* table)
{
    // Prefer explicit root id if provided by superblock
    if (superblock.root_dir_id != 0)
    {
        return superblock.root_dir_id;
    }

    // Find an entry that looks like root
    for (int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry* fe = &table->entries[i];

        if (fe->entry_id != 0 && fe->parent_id == 0 && fe->type == ENTRY_TYPE_DIR)
        {
            return fe->entry_id;
        }
    }

    // Fallback used by some images
    return 1;
}

int find_entry_in_dir(const FileTable* table, uint32_t parent_id, const char* filename)
{
    // Linear scan works for small tables
    for (int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry* fe = &table->entries[i];

        if (fe->entry_id == 0)
        {
            continue;
        }

        if (fe->parent_id == parent_id &&
            (strncmp(fe->filename, filename, MAX_FILENAME_LEN) == 0 ||
             ascii_stricmp(fe->filename, filename) == 0))
        {
            return i;
        }
    }

    return -1;
}

static void rstrip_token(char* s)
{
    // Trim trailing spaces and tabs
    if (!s)
    {
        return;
    }

    size_t n = 0;

    while (s[n] != '\0')
    {
        n++;
    }

    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
    {
        s[--n] = '\0';
    }
}

static int find_entry_by_path_nolock(const FileTable* table, const char* path)
{
    // Walk path like "/a/b/c" one token at a time
    char buf[512];
    char* cursor;
    uint32_t current_parent;
    int index;
    char token[MAX_FILENAME_LEN];

    if (!path || !*path)
    {
        return -1;
    }

    (void)strlcpy(buf, path, sizeof(buf));
    rstrip_token(buf);

    // Trim leading whitespace
    {
        char* s = buf;
        char* dst = buf;

        while (*s == ' ' || *s == '\t')
        {
            s++;
        }

        if (s != buf)
        {
            while (*s)
            {
                *dst++ = *s++;
            }

            *dst = '\0';
        }
    }

    cursor = buf;
    current_parent = detect_root_id(table);
    index = -1;

    while (path_next_token(&cursor, token, sizeof(token)))
    {
        // Find child under current parent
        index = find_entry_in_dir(table, current_parent, token);

        if (index == -1)
        {
            return -1;
        }

        const FileEntry* fe = &table->entries[index];

        // If there is more of the path left we must be in a directory
        char* peek = cursor;

        while (*peek == '/')
        {
            peek++;
        }

        if (*peek != '\0')
        {
            if (fe->type != ENTRY_TYPE_DIR)
            {
                return -1;
            }

            current_parent = fe->entry_id;
        }
    }

    return index;
}

static int path_next_token(char** it, char* out, size_t out_sz)
{
    // Parse next path component into out
    if (!it || !*it || !out || out_sz == 0)
    {
        return 0;
    }

    char* p = *it;

    while (*p == '/')
    {
        p++;
    }

    if (*p == '\0')
    {
        *it = p;
        out[0] = '\0';

        return 0;
    }

    size_t n = 0;

    while (*p != '\0' && *p != '/' && (n + 1) < out_sz)
    {
        out[n++] = *p++;
    }

    out[n] = '\0';
    *it = p;

    rstrip_token(out);

    // Trim leading whitespace
    {
        char* s = out;

        while (*s == ' ' || *s == '\t')
        {
            s++;
        }

        if (s != out)
        {
            char* dst = out;

            while (*s)
            {
                *dst++ = *s++;
            }

            *dst = '\0';
        }
    }

    // Skip empty and single dot
    if (out[0] == '\0' || (out[0] == '.' && out[1] == '\0'))
    {
        return path_next_token(it, out, out_sz);
    }

    return 1;
}

int find_entry_by_path(const FileTable* table, const char* path)
{
    // Lock wrapper around the no lock helper
    int idx;

    spin_lock(&file_table_lock);
    idx = find_entry_by_path_nolock(table, path);
    spin_unlock(&file_table_lock);

    return idx;
}

// File I/O

int read_file(const FileTable* table, const char* path, void* buffer)
{
    // Read a whole file by path into caller buffer
    int index;
    uint32_t start_sector;
    uint32_t sector_count;
    uint32_t file_size_bytes;
    uint8_t temp[SECTOR_SIZE];
    uint8_t* buf_ptr;
    uint32_t bytes_left;
    uint32_t s;

    spin_lock(&file_table_lock);

    index = find_entry_by_path_nolock(table, path);

    if (index == -1)
    {
        spin_unlock(&file_table_lock);

        return -1;
    }

    if (table->entries[index].type != ENTRY_TYPE_FILE)
    {
        spin_unlock(&file_table_lock);

        return -1;
    }

    start_sector = table->entries[index].start_sector;
    sector_count = table->entries[index].sector_count;
    file_size_bytes = table->entries[index].file_size_bytes;

    spin_unlock(&file_table_lock);

    buf_ptr = (uint8_t*)buffer;
    bytes_left = file_size_bytes;

    for (s = 0; s < sector_count; s++)
    {
        int rr = disk_read(start_sector + s, 1, temp);

        if (rr < 0)
        {
            return -2;
        }

        uint32_t to_copy = (bytes_left > SECTOR_SIZE) ? SECTOR_SIZE : bytes_left;

        memcpy(buf_ptr, temp, to_copy);
        buf_ptr += to_copy;
        bytes_left -= to_copy;

        if (bytes_left == 0)
        {
            break;
        }
    }

    return (int)file_size_bytes;
}

// Allocation bitmaps

void set_bitmap_bit(uint8_t* bitmap, int index)
{
    // Mark taken
    bitmap[index / 8] |= (uint8_t)(1 << (index % 8));
}

void clear_bitmap_bit(uint8_t* bitmap, int index)
{
    // Mark free
    bitmap[index / 8] &= (uint8_t)~(1 << (index % 8));
}

int is_bitmap_bit_set(const uint8_t* bitmap, int index)
{
    // True if taken
    int v = (bitmap[index / 8] & (uint8_t)(1 << (index % 8))) != 0;

    return v;
}

int find_free_entry(const uint8_t* bitmap, int max_files)
{
    // First fit scan
    for (int i = 0; i < max_files; i++)
    {
        if (!is_bitmap_bit_set(bitmap, i))
        {
            return i;
        }
    }

    return -1;
}

int allocate_file_entry(const char* name, EntryType type, int max_files)
{
    // Grab a free slot and fill a new entry
    int index;
    FileEntry* entry;

    spin_lock(&file_table_lock);

    index = find_free_entry(file_bitmap, max_files);

    if (index == -1)
    {
        spin_unlock(&file_table_lock);

        return -1;
    }

    set_bitmap_bit(file_bitmap, index);

    entry = &file_table->entries[index];
    memset(entry, 0, sizeof(FileEntry));
    entry->entry_id = (uint32_t)(index + 1);
    entry->type = type;
    (void)strlcpy(entry->filename, name, MAX_FILENAME_LEN);

    spin_unlock(&file_table_lock);

    return index;
}

// Sector bitmap

int read_sector_bitmap(const SuperBlock* sb)
{
    // Load the on disk sector allocation bitmap
    size_t bitmap_bytes;
    uint8_t* new_sector_bitmap;
    int r;

    bitmap_bytes = sb->sector_bitmap_size * SECTOR_SIZE;

    new_sector_bitmap = (uint8_t*)kmalloc(bitmap_bytes);

    if (!new_sector_bitmap)
    {
        printf("[Diff FS] ERROR: OOM for sector_bitmap (%u bytes)\n", (unsigned)bitmap_bytes);

        return -1;
    }

    r = disk_read(sb->sector_bitmap_sector, sb->sector_bitmap_size, new_sector_bitmap);

    if (r < 0)
    {
        kfree(new_sector_bitmap);

        return r;
    }

    spin_lock(&sector_bitmap_lock);
    sector_bitmap = new_sector_bitmap;
    spin_unlock(&sector_bitmap_lock);

    return 0;
}

int allocate_sectors(uint32_t count, uint32_t* first_sector, const SuperBlock* sb)
{
    // First fit over the sector bitmap
    uint32_t i;
    uint32_t allocated;

    spin_lock(&sector_bitmap_lock);

    allocated = 0;

    for (i = 0; i < sb->total_sectors && allocated < count; i++)
    {
        if (!is_bitmap_bit_set(sector_bitmap, (int)i))
        {
            if (allocated == 0)
            {
                *first_sector = i;
            }

            set_bitmap_bit(sector_bitmap, (int)i);
            allocated++;
        }
    }

    spin_unlock(&sector_bitmap_lock);

    return (allocated == count) ? 0 : -1;
}

void free_sectors(uint32_t start, uint32_t count)
{
    // Clear a run of bits in the sector bitmap
    uint32_t i;

    spin_lock(&sector_bitmap_lock);

    for (i = 0; i < count; i++)
    {
        clear_bitmap_bit(sector_bitmap, (int)(start + i));
    }

    spin_unlock(&sector_bitmap_lock);
}

int write_file_table(const SuperBlock* sb)
{
    // Flush the file table back to disk
    int bytes;

    spin_lock(&file_table_lock);
    bytes = disk_write(sb->file_table_sector, sb->file_table_size, file_table);
    spin_unlock(&file_table_lock);

    return (bytes <= 0) ? -1 : 0;
}

int write_sector_bitmap(const SuperBlock* sb)
{
    // Flush the sector bitmap back to disk
    int bytes;

    spin_lock(&sector_bitmap_lock);
    bytes = disk_write(sb->sector_bitmap_sector, sb->sector_bitmap_size, sector_bitmap);
    spin_unlock(&sector_bitmap_lock);

    return (bytes <= 0) ? -1 : 0;
}

