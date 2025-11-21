// diff.c: (filesystem)

#include "diff.h"
#include "stdio.h"
#include "string.h"
#include "stddef.h"
#include "heap.h"
#include "drivers/ata.h"
#include "system/spinlock.h"
#include "system/usercopy.h"
#include "paging.h"
#include "debug.h"

#define LOOKS_LIKE_KMAP_WIN(p) ((((uintptr_t)(p)) & 0xFFF00000u) == 0xD0000000u)

// If USER_MIN/USER_MAX are not provided by headers, set sane defaults
#ifndef USER_MIN
#define USER_MIN 0x00400000u
#endif
#ifndef USER_MAX
#define USER_MAX 0x7FFF0000u
#endif

#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512u
#endif

// Upper bound for how many sectors we move per I/O batch
#define MAX_SECTORS_PER_OP 32u

// Local helpers without locks
static int find_entry_by_path_nolock(const FileTable* table, const char* path);
static int path_next_token(char** it, char* out, size_t out_sz);

// Demand-fault helpers provided by paging
extern int paging_check_user_range(uint32_t va, uint32_t len);
extern int paging_handle_demand_fault(uint32_t va);

// Global filesystem state
SuperBlock superblock;
FileTable* file_table;

static uint8_t* file_bitmap;
static uint8_t* sector_bitmap;
static spinlock_t file_table_lock;
static spinlock_t sector_bitmap_lock;
static FileHandle s_fd_table[FILESYSTEM_MAX_OPEN];

extern volatile int g_in_irq;

// ---------------------------------------------------------------------------
// Pointer and range helpers
// ---------------------------------------------------------------------------

static inline int is_user_range(const void* ptr, size_t n)
{
    uintptr_t a = (uintptr_t)ptr;

    if (n == 0)
    {
        return 0;
    }
    if (a < (uintptr_t)USER_MIN)
    {
        return 0;
    }
    if (a > (uintptr_t)USER_MAX)
    {
        return 0;
    }
    if ((uintptr_t)USER_MAX - a < n - 1)
    {
        return 0;
    }

    return 1;
}

// Prefault user span for writes (kernel -> user)
static int prefault_user_write_range(void* dst, uint32_t n)
{
    if (n == 0)
    {
        return 0;
    }

    uint32_t start = (uint32_t)(uintptr_t)dst;
    uint32_t end = start + (n - 1);

    if (end < start)
    {
        end = 0xFFFFFFFFu; // Handle wrap
    }

    uint32_t page = start & ~0xFFFu;

    while (page <= end)
    {
        if (!paging_check_user_range(page, 1))
        {
            if (paging_handle_demand_fault(page) != 0)
            {
                return -1;
            }
            // On success, loop continues and re-checks next page
        }

        if (page > 0xFFFFF000u)
        {
            break;
        }

        page += 4096u;
    }

    return 0;
}

// Prefault user span for reads (user -> kernel)
static int prefault_user_read_range(const void* src, uint32_t n)
{
    if (n == 0)
    {
        return 0;
    }

    uint32_t start = (uint32_t)(uintptr_t)src;
    uint32_t end = start + (n - 1);

    if (end < start)
    {
        end = 0xFFFFFFFFu;
    }

    uint32_t page = start & ~0xFFFu;

    while (page <= end)
    {
        if (!paging_check_user_range(page, 1))
        {
            if (paging_handle_demand_fault(page) != 0)
            {
                return -1;
            }
        }

        if (page > 0xFFFFF000u)
        {
            break;
        }

        page += 4096u;
    }

    return 0;
}

static int safe_copy_out(void* dst, const void* src, uint32_t n)
{
    if (n == 0)
    {
        return 0;
    }
    if (!dst || !src)
    {
        return -1;
    }

    if (is_user_range(dst, n))
    {
        if (prefault_user_write_range(dst, n) != 0)
        {
            return -3; // EFAULT
        }

        if(copy_to_user(dst, src, n) != 0)
        {
            return -4;
        }

        return 0;
    }

    if(copy_to_user(dst, src, n) != 0)
    {
        return -5;
    }

    return 0;
}

static int safe_copy_in(void* dst, const void* src, uint32_t n)
{
    if (n == 0)
    {
        return 0;
    }
    if (!dst || !src)
    {
        return -1;
    }

    if (is_user_range(src, n))
    {
        if (prefault_user_read_range(src, n) != 0)
        {
            return -3; // EFAULT
        }

        if(copy_from_user(dst, src, n) != 0)
        {
            return -4;
        }

        return 0;
    }

    if(copy_from_user(dst, src, n) != 0)
    {
        return -5;
    }

    return 0;
}

// ---------------------------------------------------------------------------

static int filesystem_fd_is_valid(int fd)
{
    if (fd < 0 || fd >= FILESYSTEM_MAX_OPEN)
    {
        return 0;
    }

    return s_fd_table[fd].in_use ? 1 : 0;
}

static const FileEntry* filesystem_get_entry_for_fd(int fd)
{
    if (fd < 0 || fd >= FILESYSTEM_MAX_OPEN)
    {
        return NULL;
    }

    if (!s_fd_table[fd].in_use)
    {
        return NULL;
    }

    int idx = s_fd_table[fd].entry_index;

    if (!file_table || idx < 0 || idx >= file_table->count)
    {
        return NULL;
    }

    return &file_table->entries[idx];
}

static uint32_t filesystem_get_offset_for_fd(int fd)
{
    if (!filesystem_fd_is_valid(fd))
    {
        return 0;
    }

    return s_fd_table[fd].offset;
}

static void filesystem_set_offset_for_fd(int fd, uint32_t off)
{
    if (!filesystem_fd_is_valid(fd))
    {
        return;
    }

    s_fd_table[fd].offset = off;
}

// Read a byte range from a file entry at a given offset
static int read_at_entry(const FileEntry* fe, uint32_t offset, void* buffer, uint32_t count)
{
    if (!fe || !buffer || count == 0)
    {
        return 0;
    }

    uint32_t file_size = fe->file_size_bytes;

    if (offset >= file_size)
    {
        return 0;
    }

    uint32_t max_can_read = file_size - offset;

    if (count > max_can_read)
    {
        count = max_can_read;
    }

    // Clamp to allocated sectors if file_size_bytes claims too much
    uint64_t capacity_bytes = (uint64_t)fe->sector_count * (uint64_t)SECTOR_SIZE;

    if ((uint64_t)fe->file_size_bytes > capacity_bytes)
    {
        uint32_t cap_left = (uint32_t)(capacity_bytes > offset ? (capacity_bytes - offset) : 0);

        if (count > cap_left)
        {
            count = cap_left;
        }
    }

    uint32_t sector_index_in_file = offset / SECTOR_SIZE;
    uint32_t sector_byte_offset = offset % SECTOR_SIZE;

    if (sector_index_in_file >= fe->sector_count)
    {
        return 0;
    }

    uint32_t first_sector_lba = fe->start_sector + sector_index_in_file;

    // Hard bounds against disk
    if (superblock.total_sectors && (first_sector_lba >= superblock.total_sectors))
    {
        return -2;
    }

    uint8_t* out = (uint8_t*)buffer;
    uint32_t bytes_left = count;

    while (bytes_left > 0)
    {
        if (superblock.total_sectors && (first_sector_lba >= superblock.total_sectors))
        {
            break;
        }

        uint8_t temp[SECTOR_SIZE];

        int rr = ata_read(first_sector_lba, 1, temp);
        if (rr < 0)
        {
            return -2;
        }

        uint32_t start_in_sector = sector_byte_offset;
        uint32_t available_in_sector = SECTOR_SIZE - start_in_sector;
        uint32_t to_copy = (bytes_left < available_in_sector) ? bytes_left : available_in_sector;

        if (safe_copy_out(out, temp + start_in_sector, to_copy) < 0)
        {
            return -3;
        }

        out += to_copy;
        bytes_left -= to_copy;

        sector_byte_offset = 0;
        first_sector_lba++;

        if ((first_sector_lba - fe->start_sector) >= fe->sector_count)
        {
            break;
        }
    }

    int read_bytes = (int)(count - bytes_left);

    if (read_bytes != (int)count)
    {
        DDBG("[Diff FS] read_at_entry short read: wanted=%u got=%d\n", count, read_bytes);
    }

    return read_bytes;
}

// Initializes file descriptor table
static void filesystem_fd_init(void)
{
    for (int i = 0; i < FILESYSTEM_MAX_OPEN; i++)
    {
        s_fd_table[i].entry_index = 0;
        s_fd_table[i].offset = 0;
        s_fd_table[i].in_use = 0;
    }
}

// ---------------------------------------------------------------------------
// Low-level disk I/O with chunking and user-safe copies
// ---------------------------------------------------------------------------

int disk_read(uint32_t sector, uint32_t count, void* buffer)
{
    if (count == 0)
    {
        return 0;
    }
    if (!buffer)
    {
        return -1;
    }

    if (superblock.total_sectors != 0)
    {
        if (sector >= superblock.total_sectors)
        {
            DDBG("[Diff FS] disk_read OOR: sector=%u total=%u\n", sector, superblock.total_sectors);
            return -2;
        }

        uint32_t max_here = superblock.total_sectors - sector;

        if (count > max_here)
        {
            count = max_here;
        }
        if (count == 0)
        {
            return 0;
        }
    }

    // IRQ or user buffer path: per-sector with small bounce and safe copy
    if (g_in_irq || is_user_range(buffer, (size_t)count * SECTOR_SIZE))
    {
        uint8_t tmp[SECTOR_SIZE];
        uint8_t* out = (uint8_t*)buffer;
        uint32_t done = 0;

        for (uint32_t i = 0; i < count; i++)
        {
            int r = ata_read(sector + i, 1, tmp);
            if (r < 0)
            {
                return (int)(done ? (int)(done * SECTOR_SIZE) : -2);
            }

            if (safe_copy_out(out + done * SECTOR_SIZE, tmp, SECTOR_SIZE) < 0)
            {
                return (int)(done ? (int)(done * SECTOR_SIZE) : -3);
            }

            done++;
        }

        return (int)(done * SECTOR_SIZE);
    }

    // Kernel buffer path: chunk with a reusable bounce
    const uint32_t max_sectors = MAX_SECTORS_PER_OP;
    const size_t bounce_bytes = (size_t)max_sectors * SECTOR_SIZE;

    uint8_t* bounce = (uint8_t*)kmalloc(bounce_bytes);
    if (!bounce)
    {
        // Fallback: per-sector copy if allocation fails
        uint8_t tmp[SECTOR_SIZE];
        uint8_t* out = (uint8_t*)buffer;
        uint32_t done = 0;

        for (uint32_t i = 0; i < count; i++)
        {
            int r = ata_read(sector + i, 1, tmp);
            if (r < 0)
            {
                return (int)(done ? (int)(done * SECTOR_SIZE) : -2);
            }

            memcpy(out + done * SECTOR_SIZE, tmp, SECTOR_SIZE);
            done++;
        }

        return (int)(done * SECTOR_SIZE);
    }

    uint32_t lba = sector;
    uint32_t left = count;
    uint8_t* out = (uint8_t*)buffer;
    uint32_t bytes_done = 0;

    while (left > 0)
    {
        uint32_t chunk = (left > max_sectors) ? max_sectors : left;
        uint32_t bytes = chunk * SECTOR_SIZE;

        int rr = ata_read(lba, chunk, bounce);
        if (rr < 0)
        {
            kfree(bounce);
            return (int)(bytes_done ? (int)bytes_done : -2);
        }

        memcpy(out + bytes_done, bounce, bytes);

        bytes_done += bytes;
        lba += chunk;
        left -= chunk;
    }

    kfree(bounce);

    return (int)bytes_done;
}

int disk_write(uint32_t sector, uint32_t count, const void* buffer)
{
    if (count == 0)
    {
        return 0;
    }
    if (!buffer)
    {
        return -1;
    }

    if (superblock.total_sectors != 0)
    {
        if (sector >= superblock.total_sectors)
        {
            DDBG("[Diff FS] disk_write OOR: sector=%u total=%u\n", sector, superblock.total_sectors);
            return -2;
        }

        uint32_t max_here = superblock.total_sectors - sector;

        if (count > max_here)
        {
            count = max_here;
        }
        if (count == 0)
        {
            return 0;
        }
    }

    // IRQ or user buffer path: per-sector with small bounce and safe copy
    if (g_in_irq || is_user_range(buffer, (size_t)count * SECTOR_SIZE))
    {
        uint8_t tmp[SECTOR_SIZE];
        const uint8_t* in = (const uint8_t*)buffer;
        uint32_t done = 0;

        if (prefault_user_read_range(in, count * SECTOR_SIZE) != 0)
        {
            return -3;
        }

        for (uint32_t i = 0; i < count; i++)
        {
            memcpy(tmp, in + done * SECTOR_SIZE, SECTOR_SIZE);

            int r = ata_write(sector + i, 1, tmp);
            if (r < 0)
            {
                return (int)(done ? (int)(done * SECTOR_SIZE) : -2);
            }

            done++;
        }

        return (int)(done * SECTOR_SIZE);
    }

    // Kernel buffer path with reusable bounce buffer
    const uint32_t max_sectors = MAX_SECTORS_PER_OP;
    const size_t bounce_bytes = (size_t)max_sectors * SECTOR_SIZE;

    uint8_t* bounce = (uint8_t*)kmalloc(bounce_bytes);
    if (!bounce)
    {
        // Fallback to per-sector without large allocation
        const uint8_t* in = (const uint8_t*)buffer;
        uint8_t tmp[SECTOR_SIZE];
        uint32_t done = 0;

        for (uint32_t i = 0; i < count; i++)
        {
            memcpy(tmp, in + done * SECTOR_SIZE, SECTOR_SIZE);

            int r = ata_write(sector + i, 1, tmp);
            if (r < 0)
            {
                return (int)(done ? (int)(done * SECTOR_SIZE) : -2);
            }

            done++;
        }

        return (int)(done * SECTOR_SIZE);
    }

    uint32_t lba = sector;
    uint32_t left = count;
    const uint8_t* in = (const uint8_t*)buffer;
    uint32_t bytes_done = 0;

    while (left > 0)
    {
        uint32_t chunk = (left > max_sectors) ? max_sectors : left;
        uint32_t bytes = chunk * SECTOR_SIZE;

        memcpy(bounce, in + bytes_done, bytes);

        int rr = ata_write(lba, chunk, bounce);
        if (rr < 0)
        {
            kfree(bounce);
            return (int)(bytes_done ? (int)bytes_done : -2);
        }

        bytes_done += bytes;
        lba += chunk;
        left -= chunk;
    }

    kfree(bounce);

    return (int)bytes_done;
}

// ---------------------------------------------------------------------------
// Superblock and tables
// ---------------------------------------------------------------------------

static int validate_span(uint32_t start, uint32_t count, const char* what)
{
    if (count == 0)
    {
        DDBG("[Diff FS] WARN: %s count=0\n", what);
        return 0;
    }

    if (superblock.total_sectors == 0)
    {
        return 0;
    }

    if (start >= superblock.total_sectors)
    {
        printf("[Diff FS] ERROR: %s start OOR (start=%u total=%u)\n", what, start, superblock.total_sectors);
        return -1;
    }

    if ((uint64_t)start + (uint64_t)count > (uint64_t)superblock.total_sectors)
    {
        printf("[Diff FS] ERROR: %s span OOR (start=%u count=%u total=%u)\n", what, start, count, superblock.total_sectors);
        return -1;
    }

    return 0;
}

int read_file_table(const SuperBlock* sb)
{
    size_t table_bytes;
    size_t bitmap_bytes_disk;
    size_t bitmap_bytes_mem;
    size_t bitmap_bytes_alloc;
    FileTable* new_table;
    uint8_t* new_bitmap;
    int r;

    if (!sb)
    {
        printf("[Diff FS] ERROR: read_file_table: sb=NULL\n");
        return -1;
    }

    if (validate_span(sb->file_table_sector, sb->file_table_size, "file_table") != 0)
    {
        return -1;
    }
    if (validate_span(sb->file_table_bitmap_sector, sb->file_table_bitmap_size, "file_table_bitmap") != 0)
    {
        return -1;
    }

    table_bytes = (size_t)sb->file_table_size * SECTOR_SIZE;
    bitmap_bytes_disk = (size_t)sb->file_table_bitmap_size * SECTOR_SIZE;

    if (table_bytes < sizeof(FileEntry) || (table_bytes % sizeof(FileEntry)) != 0)
    {
        printf("[Diff FS] ERROR: file_table size invalid on disk (bytes=%u, entry=%u)\n",
               (unsigned)table_bytes, (unsigned)sizeof(FileEntry));
        return -1;
    }

    new_table = (FileTable*)kmalloc(sizeof(FileTable));
    if (!new_table)
    {
        printf("[Diff FS] ERROR: OOM for file_table (%u bytes)\n", (unsigned)sizeof(FileTable));
        return -1;
    }

    memset(new_table, 0, sizeof(FileTable));

    // Only read as much as fits into our FileTable struct
    size_t max_sectors_for_mem = sizeof(FileTable) / SECTOR_SIZE;
    uint32_t want_sectors = sb->file_table_size;

    if ((size_t)want_sectors > max_sectors_for_mem)
    {
        printf("[Diff FS] WARN: on-disk file_table larger than memory capacity, truncating read\n");
        want_sectors = (uint32_t)max_sectors_for_mem;
    }

    if (want_sectors > 0)
    {
        r = disk_read(sb->file_table_sector, want_sectors, new_table);
        if (r < 0)
        {
            printf("[Diff FS] ERROR: disk_read(file_table) failed\n");
            kfree(new_table);
            return -1;
        }
    }

    // Bitmap
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

    if (sb->file_table_bitmap_size > 0)
    {
        r = disk_read(sb->file_table_bitmap_sector, sb->file_table_bitmap_size, new_bitmap);
        if (r < 0)
        {
            printf("[Diff FS] ERROR: disk_read(file_bitmap) failed\n");
            kfree(new_bitmap);
            kfree(new_table);
            return -1;
        }
    }

    int count = 0;

    for (int i = 0; i < MAX_FILES; i++)
    {
        if (new_table->entries[i].entry_id != 0)
        {
            count++;
        }
    }

    new_table->count = count;

    spin_lock(&file_table_lock);
    file_table = new_table;
    file_bitmap = new_bitmap;
    spin_unlock(&file_table_lock);

    return 0;
}

int read_superblock(SuperBlock* sb)
{
    if (!sb)
    {
        return -1;
    }

    // Use disk_read so we exercise the same safety path everywhere
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

    spinlock_init(&file_table_lock);
    spinlock_init(&sector_bitmap_lock);

    r = read_superblock(&superblock);
    if (r < 0)
    {
        printf("[Diff FS] ERROR: Unable to read superblock!\n");
        return -1;
    }

    r = read_file_table(&superblock);
    if (r != 0)
    {
        printf("[Diff FS] ERROR: Unable to read file table!\n");
        return -1;
    }

    // Load sector bitmap (optional but helpful before allocations)
    if (validate_span(superblock.sector_bitmap_sector,
                      superblock.sector_bitmap_size,
                      "sector_bitmap") == 0)
    {
        (void)read_sector_bitmap(&superblock);
    }

    filesystem_fd_init();

    return 0;
}

// ---------------------------------------------------------------------------
// ASCII case-insensitive compare
// ---------------------------------------------------------------------------

static int ascii_stricmp(const char* a, const char* b)
{
    unsigned char ca;
    unsigned char cb;

    for (;;)
    {
        ca = (unsigned char)*a++;
        cb = (unsigned char)*b++;

        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');

        if (ca != cb || ca == '\0' || cb == '\0')
        {
            return (int)ca - (int)cb;
        }
    }
}

// ---------------------------------------------------------------------------
// Directory and path helpers
// ---------------------------------------------------------------------------

static uint32_t detect_root_id(const FileTable* table)
{
    if (!table)
    {
        return 0;
    }

    if (superblock.root_dir_id != 0)
    {
        return superblock.root_dir_id;
    }

    for (int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry* fe = &table->entries[i];

        if (fe->entry_id != 0 && fe->parent_id == 0 && fe->type == ENTRY_TYPE_DIR)
        {
            return fe->entry_id;
        }
    }

    return 1;
}

int find_entry_in_dir(const FileTable* table, uint32_t parent_id, const char* filename)
{
    if (!table || !filename)
    {
        return -1;
    }

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
    if (!s)
    {
        return;
    }

    size_t n = 0;

    while (s[n] != '\0') n++;

    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
    {
        s[--n] = '\0';
    }
}

static int find_entry_by_path_nolock(const FileTable* table, const char* path)
{
    char buf[512];
    char* cursor;
    uint32_t current_parent;
    int index;
    char token[MAX_FILENAME_LEN];

    if (!table || !path || !*path)
    {
        return -1;
    }

    (void)strlcpy(buf, path, sizeof(buf));
    rstrip_token(buf);

    {
        char* s = buf;
        char* dst = buf;

        while (*s == ' ' || *s == '\t') s++;

        if (s != buf)
        {
            while (*s) *dst++ = *s++;
            *dst = '\0';
        }
    }

    cursor = buf;
    current_parent = detect_root_id(table);
    index = -1;

    while (path_next_token(&cursor, token, sizeof(token)))
    {
        index = find_entry_in_dir(table, current_parent, token);
        if (index == -1)
        {
            return -1;
        }

        const FileEntry* fe = &table->entries[index];

        char* peek = cursor;
        while (*peek == '/') peek++;

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
    if (!it || !*it || !out || out_sz == 0)
    {
        return 0;
    }

    char* p = *it;

    while (*p == '/') p++;

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

    {
        char* s = out;

        while (*s == ' ' || *s == '\t') s++;

        if (s != out)
        {
            char* dst = out;

            while (*s) *dst++ = *s++;
            *dst = '\0';
        }
    }

    if (out[0] == '\0' || (out[0] == '.' && out[1] == '\0'))
    {
        return path_next_token(it, out, out_sz);
    }

    return 1;
}

int find_entry_by_path(const FileTable* table, const char* path)
{
    int idx;

    spin_lock(&file_table_lock);
    idx = find_entry_by_path_nolock(table, path);
    spin_unlock(&file_table_lock);

    return idx;
}

// ---------------------------------------------------------------------------
// High-level file read
// ---------------------------------------------------------------------------

int read_file(const FileTable* table, const char* path, void* buffer)
{
    int index;
    uint32_t start_sector;
    uint32_t sector_count;
    uint32_t file_size_bytes;

    if (!table || !path || !buffer)
    {
        return -1;
    }

    // Lookup entry under lock
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

    // Bounds checks against disk
    if (superblock.total_sectors && start_sector >= superblock.total_sectors)
    {
        DDBG("[Diff FS] read_file: start_sector OOR path='%s' start=%u total=%u\n",
             path, start_sector, superblock.total_sectors);
        return -2;
    }

    if (superblock.total_sectors &&
        (uint64_t)start_sector + (uint64_t)sector_count > (uint64_t)superblock.total_sectors)
    {
        DDBG("[Diff FS] read_file: clamping sector_count (path='%s')\n", path);
        sector_count = superblock.total_sectors - start_sector;
    }

    // Clamp file size to allocated sectors
    uint64_t capacity_bytes = (uint64_t)sector_count * (uint64_t)SECTOR_SIZE;

    if ((uint64_t)file_size_bytes > capacity_bytes)
    {
        file_size_bytes = (uint32_t)capacity_bytes;
    }

    DDBG("[Diff FS] read_file '%s': LBA=%u count=%u size=%u\n",
         path, start_sector, sector_count, file_size_bytes);

    uint8_t* dst = (uint8_t*)buffer;

    if (LOOKS_LIKE_KMAP_WIN(dst))
    {
        printf("[Diff FS] ERROR: Destination looks like KMAP window (%p)\n", dst);
        return -3;
    }

    uint32_t full_sectors = file_size_bytes / SECTOR_SIZE;
    uint32_t tail_bytes = file_size_bytes % SECTOR_SIZE;

    const size_t bounce_bytes = (size_t)MAX_SECTORS_PER_OP * SECTOR_SIZE;
    uint8_t* bounce = (uint8_t*)kmalloc(bounce_bytes);

    if (!bounce)
    {
        // Fallback: sector-by-sector into a small stack temp
        uint8_t temp[SECTOR_SIZE];
        uint32_t lba = start_sector;
        uint32_t left = full_sectors;
        uint32_t read_total = 0;

        while (left > 0)
        {
            int rr = ata_read(lba, 1, temp);
            if (rr < 0)
            {
                return -2;
            }

            if (safe_copy_out(dst + read_total, temp, SECTOR_SIZE) < 0)
            {
                return -3;
            }

            read_total += SECTOR_SIZE;
            lba++;
            left--;
        }

        if (tail_bytes)
        {
            int rr = ata_read(lba, 1, temp);
            if (rr < 0)
            {
                return -2;
            }

            if (safe_copy_out(dst + read_total, temp, tail_bytes) < 0)
            {
                return -3;
            }
        }

        return (int)file_size_bytes;
    }

    uint32_t lba = start_sector;

    // Full sector batches
    while (full_sectors > 0)
    {
        uint32_t chunk = (full_sectors > MAX_SECTORS_PER_OP) ? MAX_SECTORS_PER_OP : full_sectors;
        uint32_t bytes = chunk * SECTOR_SIZE;

        int rr = ata_read(lba, chunk, bounce);
        if (rr < 0)
        {
            DDBG("[Diff FS] read_file: ata_read failed at LBA=%u (chunk=%u)\n", lba, chunk);
            kfree(bounce);
            return -2;
        }

        if (safe_copy_out(dst, bounce, bytes) < 0)
        {
            kfree(bounce);
            return -3;
        }

        dst += bytes;
        lba += chunk;
        full_sectors -= chunk;
    }

    // Tail bytes
    if (tail_bytes)
    {
        uint8_t temp[SECTOR_SIZE];

        int rr = ata_read(lba, 1, temp);
        if (rr < 0)
        {
            DDBG("[Diff FS] read_file: ata_read tail failed at LBA=%u\n", lba);
            kfree(bounce);
            return -2;
        }

        if (safe_copy_out(dst, temp, tail_bytes) < 0)
        {
            kfree(bounce);
            return -3;
        }
    }

    kfree(bounce);

    return (int)file_size_bytes;
}

// ---------------------------------------------------------------------------
// Allocation bitmaps
// ---------------------------------------------------------------------------

void set_bitmap_bit(uint8_t* bitmap, int index)
{
    if (!bitmap || index < 0)
    {
        return;
    }

    bitmap[index / 8] |= (uint8_t)(1 << (index % 8));
}

void clear_bitmap_bit(uint8_t* bitmap, int index)
{
    if (!bitmap || index < 0)
    {
        return;
    }

    bitmap[index / 8] &= (uint8_t)~(1 << (index % 8));
}

int is_bitmap_bit_set(const uint8_t* bitmap, int index)
{
    if (!bitmap || index < 0)
    {
        return 0;
    }

    int v = (bitmap[index / 8] & (uint8_t)(1 << (index % 8))) != 0;

    return v;
}

int find_free_entry(const uint8_t* bitmap, int max_files)
{
    if (!bitmap || max_files <= 0)
    {
        return -1;
    }

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
    int index;
    FileEntry* entry;

    if (!name || max_files <= 0)
    {
        return -1;
    }

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

// ---------------------------------------------------------------------------
// Sector bitmap
// ---------------------------------------------------------------------------

int read_sector_bitmap(const SuperBlock* sb)
{
    size_t bitmap_bytes;
    uint8_t* new_sector_bitmap;
    int r;

    if (!sb)
    {
        return -1;
    }

    if (validate_span(sb->sector_bitmap_sector, sb->sector_bitmap_size, "sector_bitmap") != 0)
    {
        return -1;
    }

    bitmap_bytes = (size_t)sb->sector_bitmap_size * SECTOR_SIZE;
    if (bitmap_bytes == 0)
    {
        return -1;
    }

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
    uint32_t i;
    uint32_t allocated;

    if (!first_sector || !sb)
    {
        return -1;
    }
    if (count == 0)
    {
        *first_sector = 0;
        return 0;
    }

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
    uint32_t i;

    if (count == 0)
    {
        return;
    }

    spin_lock(&sector_bitmap_lock);

    for (i = 0; i < count; i++)
    {
        clear_bitmap_bit(sector_bitmap, (int)(start + i));
    }

    spin_unlock(&sector_bitmap_lock);
}

// ---------------------------------------------------------------------------
// Write-back
// ---------------------------------------------------------------------------

int write_file_table(const SuperBlock* sb)
{
    int bytes;

    if (!sb || !file_table)
    {
        return -1;
    }

    if (validate_span(sb->file_table_sector, sb->file_table_size, "file_table(write)") != 0)
    {
        return -1;
    }

    spin_lock(&file_table_lock);
    bytes = disk_write(sb->file_table_sector, sb->file_table_size, file_table);
    spin_unlock(&file_table_lock);

    return (bytes <= 0) ? -1 : 0;
}

int write_sector_bitmap(const SuperBlock* sb)
{
    int bytes;

    if (!sb || !sector_bitmap)
    {
        return -1;
    }

    if (validate_span(sb->sector_bitmap_sector, sb->sector_bitmap_size, "sector_bitmap(write)") != 0)
    {
        return -1;
    }

    spin_lock(&sector_bitmap_lock);
    bytes = disk_write(sb->sector_bitmap_sector, sb->sector_bitmap_size, sector_bitmap);
    spin_unlock(&sector_bitmap_lock);

    return (bytes <= 0) ? -1 : 0;
}

// ---------------------------------------------------------------------------
// Simple FD API
// ---------------------------------------------------------------------------

int filesystem_open(const char* path)
{
    if (!path || !path[0] || !file_table)
    {
        return -1;
    }

    int idx = find_entry_by_path(file_table, path);
    if (idx < 0)
    {
        return -1;
    }

    for (int i = 0; i < FILESYSTEM_MAX_OPEN; i++)
    {
        if (!s_fd_table[i].in_use)
        {
            s_fd_table[i].entry_index = (uint32_t)idx;
            s_fd_table[i].offset = 0;
            s_fd_table[i].in_use = 1;
            return i;
        }
    }

    return -1;
}

int filesystem_close(int fd)
{
    if (fd < 0 || fd >= FILESYSTEM_MAX_OPEN)
    {
        return -1;
    }

    if (!s_fd_table[fd].in_use)
    {
        return -1;
    }

    // Write back the file table to persist any size changes made during writes
    write_file_table(&superblock);

    s_fd_table[fd].entry_index = (uint32_t)-1;
    s_fd_table[fd].offset = 0;
    s_fd_table[fd].in_use = 0;

    return 0;
}

int filesystem_read(int fd, void* buffer, uint32_t count)
{
    if (!buffer || count == 0 || !filesystem_fd_is_valid(fd))
    {
        return -1;
    }

    const FileEntry* fe = filesystem_get_entry_for_fd(fd);
    uint32_t off = filesystem_get_offset_for_fd(fd);

    if (!fe)
    {
        return -1;
    }

    if (off >= fe->file_size_bytes)
    {
        return 0;
    }

    uint32_t remain = fe->file_size_bytes - off;

    if (count > remain)
    {
        count = remain;
    }

    int r = read_at_entry(fe, off, buffer, count);
    if (r < 0)
    {
        return -1;
    }

    filesystem_set_offset_for_fd(fd, off + (uint32_t)r);
// i filesystem_read() (diff.c)
//printf("[FS] read fd=%d off=%u cnt=%u -> r=%d\n", fd, off, count, r);

    return r;
}

int32_t filesystem_lseek(int fd, int32_t off, int whence)
{
    if (!filesystem_fd_is_valid(fd))
    {
        return -1;
    }

    const FileEntry* fe = filesystem_get_entry_for_fd(fd);
    if (!fe)
    {
        return -1;
    }

    uint32_t cur = filesystem_get_offset_for_fd(fd);
    int64_t base = 0;

    if (whence == SEEK_SET)
    {
        base = 0;
    }
    else if (whence == SEEK_CUR)
    {
        base = (int64_t)cur;
    }
    else if (whence == SEEK_END)
    {
        base = (int64_t)fe->file_size_bytes;
    }
    else
    {
        return -1;
    }

    int64_t proposed = base + (int64_t)off;

    if (proposed < 0)
    {
        proposed = 0;
    }
    if (proposed > (int64_t)fe->file_size_bytes)
    {
        proposed = (int64_t)fe->file_size_bytes;
    }

    uint32_t new_off = (uint32_t)proposed;
    filesystem_set_offset_for_fd(fd, new_off);

    return (int32_t)new_off;
}

int filesystem_stat(const char* path, filesystem_stat_t* st)
{
    if (!path || !path[0] || !st || !file_table)
    {
        return -1;
    }

    int idx = find_entry_by_path(file_table, path);
    if (idx < 0)
    {
        return -1;
    }

    const FileEntry* fe = &file_table->entries[idx];
    st->size = fe->file_size_bytes;

    return 0;
}

int filesystem_fstat(int fd, filesystem_stat_t* st)
{
    if (!st || !filesystem_fd_is_valid(fd))
    {
        return -1;
    }

    const FileEntry* fe = filesystem_get_entry_for_fd(fd);
    if (!fe)
    {
        return -1;
    }

    st->size = fe->file_size_bytes;

    return 0;
}

// ---------------------------------------------------------------------------
// File creation and writing
// ---------------------------------------------------------------------------

// Helper to split a path into parent directory and filename
static int split_path(const char* path, char* parent_buf, size_t parent_sz,
                      char* name_buf, size_t name_sz)
{
    if (!path || !parent_buf || !name_buf || parent_sz == 0 || name_sz == 0)
    {
        return -1;
    }

    // Find last '/' in path
    const char* last_slash = NULL;
    const char* p = path;

    while (*p)
    {
        if (*p == '/')
        {
            last_slash = p;
        }
        p++;
    }

    // No slash found - file is in current directory
    if (!last_slash)
    {
        parent_buf[0] = '/';
        parent_buf[1] = '\0';
        (void)strlcpy(name_buf, path, name_sz);
        return 0;
    }

    // Copy parent path
    size_t parent_len = (size_t)(last_slash - path);
    if (parent_len == 0)
    {
        // Path starts with '/' - parent is root
        parent_buf[0] = '/';
        parent_buf[1] = '\0';
    }
    else
    {
        if (parent_len >= parent_sz)
        {
            parent_len = parent_sz - 1;
        }
        memcpy(parent_buf, path, parent_len);
        parent_buf[parent_len] = '\0';
    }

    // Copy filename
    (void)strlcpy(name_buf, last_slash + 1, name_sz);

    return 0;
}

int filesystem_create(const char* path, uint32_t initial_size)
{
    char parent_path[512];
    char filename[MAX_FILENAME_LEN];
    int parent_idx;
    uint32_t parent_id;
    int entry_idx;
    uint32_t sectors_needed;
    uint32_t first_sector;
    FileEntry* entry;

    if (!path || !path[0] || !file_table)
    {
        return -1;
    }

    // Split path into parent directory and filename
    if (split_path(path, parent_path, sizeof(parent_path),
                   filename, sizeof(filename)) != 0)
    {
        DDBG("[Diff FS] filesystem_create: failed to split path '%s'\n", path);
        return -1;
    }

    // Find parent directory
    spin_lock(&file_table_lock);

    if (parent_path[0] == '/' && parent_path[1] == '\0')
    {
        // Root directory
        parent_id = detect_root_id(file_table);
    }
    else
    {
        parent_idx = find_entry_by_path_nolock(file_table, parent_path);
        if (parent_idx < 0)
        {
            spin_unlock(&file_table_lock);
            DDBG("[Diff FS] filesystem_create: parent dir '%s' not found\n", parent_path);
            return -1;
        }

        if (file_table->entries[parent_idx].type != ENTRY_TYPE_DIR)
        {
            spin_unlock(&file_table_lock);
            DDBG("[Diff FS] filesystem_create: parent '%s' is not a directory\n", parent_path);
            return -1;
        }

        parent_id = file_table->entries[parent_idx].entry_id;
    }

    // Check if file already exists
    if (find_entry_in_dir(file_table, parent_id, filename) >= 0)
    {
        spin_unlock(&file_table_lock);
        DDBG("[Diff FS] filesystem_create: file '%s' already exists\n", path);
        return -2; // Already exists
    }

    // Allocate file entry
    entry_idx = find_free_entry(file_bitmap, MAX_FILES);
    if (entry_idx < 0)
    {
        spin_unlock(&file_table_lock);
        DDBG("[Diff FS] filesystem_create: no free file entries\n");
        return -1;
    }

    spin_unlock(&file_table_lock);

    // Allocate sectors if needed
    sectors_needed = (initial_size + SECTOR_SIZE - 1) / SECTOR_SIZE;
    first_sector = 0;

    if (sectors_needed > 0)
    {
        if (allocate_sectors(sectors_needed, &first_sector, &superblock) != 0)
        {
            DDBG("[Diff FS] filesystem_create: failed to allocate %u sectors\n", sectors_needed);
            return -1;
        }
    }

    // Create the file entry
    spin_lock(&file_table_lock);

    set_bitmap_bit(file_bitmap, entry_idx);
    entry = &file_table->entries[entry_idx];
    memset(entry, 0, sizeof(FileEntry));

    entry->entry_id = (uint32_t)(entry_idx + 1);
    entry->parent_id = parent_id;
    entry->type = ENTRY_TYPE_FILE;
    (void)strlcpy(entry->filename, filename, MAX_FILENAME_LEN);
    entry->start_sector = first_sector;
    entry->sector_count = sectors_needed;
    entry->file_size_bytes = 0; // Start with 0, will grow as data is written
    entry->created_timestamp = 0;  // TODO: Add timestamp support
    entry->modified_timestamp = 0;

    file_table->count++;

    spin_unlock(&file_table_lock);

    // Write file table and sector bitmap to disk
    if (write_file_table(&superblock) != 0)
    {
        DDBG("[Diff FS] filesystem_create: failed to write file table\n");
        return -1;
    }

    if (sectors_needed > 0)
    {
        if (write_sector_bitmap(&superblock) != 0)
        {
            DDBG("[Diff FS] filesystem_create: failed to write sector bitmap\n");
            return -1;
        }
    }

    DDBG("[Diff FS] filesystem_create: created '%s' (idx=%d, sectors=%u)\n",
         path, entry_idx, sectors_needed);

    return 0;
}

int filesystem_mkdir(const char *path)
{
    char parent_path[512];
    char dirname[MAX_FILENAME_LEN];
    uint32_t parent_id;
    int entry_idx;
    FileEntry *entry;

    if (!path || !path[0] || !file_table)
    {
        return -1;
    }

    if (split_path(path, parent_path, sizeof(parent_path),
                   dirname, sizeof(dirname)) != 0)
    {
        return -1;
    }

    if (dirname[0] == '\0' ||
        strcmp(dirname, ".") == 0 ||
        strcmp(dirname, "..") == 0)
    {
        return -1;
    }

    spin_lock(&file_table_lock);

    if (parent_path[0] == '/' && parent_path[1] == '\0')
    {
        parent_id = detect_root_id(file_table);
    }
    else
    {
        int parent_idx = find_entry_by_path_nolock(file_table, parent_path);
        if (parent_idx < 0)
        {
            spin_unlock(&file_table_lock);
            return -1;
        }

        if (file_table->entries[parent_idx].type != ENTRY_TYPE_DIR)
        {
            spin_unlock(&file_table_lock);
            return -1;
        }

        parent_id = file_table->entries[parent_idx].entry_id;
    }

    if (find_entry_in_dir(file_table, parent_id, dirname) >= 0)
    {
        spin_unlock(&file_table_lock);
        return -2;
    }

    entry_idx = find_free_entry(file_bitmap, MAX_FILES);
    if (entry_idx < 0)
    {
        spin_unlock(&file_table_lock);
        return -1;
    }

    set_bitmap_bit(file_bitmap, entry_idx);
    entry = &file_table->entries[entry_idx];
    memset(entry, 0, sizeof(FileEntry));
    entry->entry_id = (uint32_t)(entry_idx + 1);
    entry->parent_id = parent_id;
    entry->type = ENTRY_TYPE_DIR;
    (void)strlcpy(entry->filename, dirname, MAX_FILENAME_LEN);
    entry->created_timestamp = 0;
    entry->modified_timestamp = 0;
    file_table->count++;

    spin_unlock(&file_table_lock);

    if (write_file_table(&superblock) != 0)
    {
        return -1;
    }

    return 0;
}

// Write data to a file at current offset
static int write_at_entry(FileEntry* fe, uint32_t offset, const void* buffer, uint32_t count)
{
    uint8_t temp[SECTOR_SIZE];
    const uint8_t* in;
    uint32_t sector_index_in_file;
    uint32_t sector_byte_offset;
    uint32_t first_sector_lba;
    uint32_t bytes_left;
    uint32_t bytes_written;

    if (!fe || !buffer || count == 0)
    {
        return 0;
    }

    // Check if we need to expand the file
    uint32_t end_offset = offset + count;
    uint64_t needed_bytes = (uint64_t)end_offset;
    uint64_t capacity_bytes = (uint64_t)fe->sector_count * (uint64_t)SECTOR_SIZE;

    if (needed_bytes > capacity_bytes)
    {
        // Need to allocate more sectors
        uint32_t needed_sectors = (uint32_t)((needed_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE);
        uint32_t additional_sectors = needed_sectors - fe->sector_count;

        if (additional_sectors > 0)
        {
            DDBG("[Diff FS] write_at_entry: file needs expansion from %u to %u sectors\n",
                 fe->sector_count, needed_sectors);

            // Try to allocate contiguous sectors right after the current file
            uint32_t expected_sector = fe->start_sector + fe->sector_count;
            uint32_t new_start;

            // Check if the next sectors are free
            int can_extend_contiguous = 1;
            for (uint32_t i = 0; i < additional_sectors; i++)
            {
                uint32_t check_sector = expected_sector + i;
                if (check_sector >= superblock.total_sectors ||
                    is_bitmap_bit_set(sector_bitmap, check_sector))
                {
                    can_extend_contiguous = 0;
                    break;
                }
            }

            if (can_extend_contiguous)
            {
                // Mark the additional sectors as used
                for (uint32_t i = 0; i < additional_sectors; i++)
                {
                    set_bitmap_bit(sector_bitmap, expected_sector + i);
                }

                // Update file entry
                fe->sector_count = needed_sectors;

                DDBG("[Diff FS] write_at_entry: expanded file to %u sectors\n", needed_sectors);

                // Write updated sector bitmap
                if (write_sector_bitmap(&superblock) != 0)
                {
                    DDBG("[Diff FS] write_at_entry: failed to write sector bitmap\n");
                    return -1;
                }
            }
            else
            {
                // Cannot expand contiguously - would need to relocate file
                DDBG("[Diff FS] write_at_entry: cannot expand file contiguously\n");
                return -1;
            }
        }
    }

    sector_index_in_file = offset / SECTOR_SIZE;
    sector_byte_offset = offset % SECTOR_SIZE;

    if (sector_index_in_file >= fe->sector_count)
    {
        return 0;
    }

    first_sector_lba = fe->start_sector + sector_index_in_file;

    // Bounds check
    if (superblock.total_sectors && (first_sector_lba >= superblock.total_sectors))
    {
        return -2;
    }

    in = (const uint8_t*)buffer;
    bytes_left = count;
    bytes_written = 0;

    while (bytes_left > 0)
    {
        if (superblock.total_sectors && (first_sector_lba >= superblock.total_sectors))
        {
            break;
        }

        uint32_t start_in_sector = sector_byte_offset;
        uint32_t available_in_sector = SECTOR_SIZE - start_in_sector;
        uint32_t to_write = (bytes_left < available_in_sector) ? bytes_left : available_in_sector;

        // If we're doing a partial sector write, we need to read-modify-write
        if (to_write < SECTOR_SIZE || start_in_sector > 0)
        {
            // Read existing sector
            int rr = ata_read(first_sector_lba, 1, temp);
            if (rr < 0)
            {
                return -2;
            }

            // Modify the relevant bytes
            if (safe_copy_in(temp + start_in_sector, in, to_write) < 0)
            {
                return -3;
            }

            // Write back
            int wr = ata_write(first_sector_lba, 1, temp);
            if (wr < 0)
            {
                return -2;
            }
        }
        else
        {
            // Full sector write - copy from user and write directly
            if (safe_copy_in(temp, in, SECTOR_SIZE) < 0)
            {
                return -3;
            }

            int wr = ata_write(first_sector_lba, 1, temp);
            if (wr < 0)
            {
                return -2;
            }
        }

        in += to_write;
        bytes_left -= to_write;
        bytes_written += to_write;

        sector_byte_offset = 0;
        first_sector_lba++;

        if ((first_sector_lba - fe->start_sector) >= fe->sector_count)
        {
            break;
        }
    }

    // Update file size if we extended it
    if (end_offset > fe->file_size_bytes)
    {
        fe->file_size_bytes = end_offset;
    }

    return (int)bytes_written;
}

int filesystem_write(int fd, const void* buffer, uint32_t count)
{
    FileEntry* fe;
    uint32_t off;
    int r;

    if (!buffer || count == 0 || !filesystem_fd_is_valid(fd))
    {
        DDBG("[Diff FS] filesystem_write: invalid params fd=%d buf=%p count=%u\n", fd, buffer, count);
        return -1;
    }

    // Get the file entry (non-const because we may modify it)
    if (fd < 0 || fd >= FILESYSTEM_MAX_OPEN)
    {
        DDBG("[Diff FS] filesystem_write: fd out of range %d\n", fd);
        return -1;
    }

    if (!s_fd_table[fd].in_use)
    {
        DDBG("[Diff FS] filesystem_write: fd %d not in use\n", fd);
        return -1;
    }

    int idx = s_fd_table[fd].entry_index;

    if (!file_table || idx < 0 || idx >= MAX_FILES)
    {
        DDBG("[Diff FS] filesystem_write: invalid idx=%d (count=%d)\n", idx, file_table ? file_table->count : -1);
        return -1;
    }

    spin_lock(&file_table_lock);
    fe = &file_table->entries[idx];
    off = filesystem_get_offset_for_fd(fd);

    DDBG("[Diff FS] filesystem_write: fd=%d idx=%d off=%u count=%u sectors=%u\n",
         fd, idx, off, count, fe->sector_count);

    r = write_at_entry(fe, off, buffer, count);

    DDBG("[Diff FS] filesystem_write: wrote %d bytes\n", r);

    if (r > 0)
    {
        filesystem_set_offset_for_fd(fd, off + (uint32_t)r);
    }

    spin_unlock(&file_table_lock);

    // Don't write file table on every write - defer until file close for performance
    // The file size is updated in memory, will be persisted when file is closed

    return r;
}

int filesystem_delete(const char* path)
{
    int idx;
    FileEntry* entry;

    if (!path || !path[0] || !file_table)
    {
        return -1;
    }

    spin_lock(&file_table_lock);

    idx = find_entry_by_path_nolock(file_table, path);
    if (idx < 0)
    {
        spin_unlock(&file_table_lock);
        DDBG("[Diff FS] filesystem_delete: file '%s' not found\n", path);
        return -1;
    }

    entry = &file_table->entries[idx];

    // Don't allow deleting directories (for now)
    if (entry->type == ENTRY_TYPE_DIR)
    {
        spin_unlock(&file_table_lock);
        DDBG("[Diff FS] filesystem_delete: cannot delete directory '%s'\n", path);
        return -1;
    }

    // Free the sectors
    uint32_t start_sector = entry->start_sector;
    uint32_t sector_count = entry->sector_count;

    // Clear the file entry
    memset(entry, 0, sizeof(FileEntry));
    clear_bitmap_bit(file_bitmap, idx);

    file_table->count--;

    spin_unlock(&file_table_lock);

    // Free sectors
    if (sector_count > 0)
    {
        free_sectors(start_sector, sector_count);

        if (write_sector_bitmap(&superblock) != 0)
        {
            DDBG("[Diff FS] filesystem_delete: failed to write sector bitmap\n");
            return -1;
        }
    }

    // Write updated file table
    if (write_file_table(&superblock) != 0)
    {
        DDBG("[Diff FS] filesystem_delete: failed to write file table\n");
        return -1;
    }

    DDBG("[Diff FS] filesystem_delete: deleted '%s'\n", path);

    return 0;
}

int filesystem_rmdir(const char *path)
{
    int idx;
    FileEntry *entry;

    if (!path || !path[0] || !file_table)
    {
        return -1;
    }

    spin_lock(&file_table_lock);

    idx = find_entry_by_path_nolock(file_table, path);
    if (idx < 0)
    {
        spin_unlock(&file_table_lock);
        return -1;
    }

    entry = &file_table->entries[idx];
    if (entry->type != ENTRY_TYPE_DIR)
    {
        spin_unlock(&file_table_lock);
        return -3;
    }

    if (entry->entry_id == detect_root_id(file_table))
    {
        spin_unlock(&file_table_lock);
        return -1;
    }

    for (int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *child = &file_table->entries[i];
        if (child->entry_id != 0 && child->parent_id == entry->entry_id)
        {
            spin_unlock(&file_table_lock);
            return -2;
        }
    }

    memset(entry, 0, sizeof(FileEntry));
    clear_bitmap_bit(file_bitmap, idx);
    file_table->count--;

    spin_unlock(&file_table_lock);

    if (write_file_table(&superblock) != 0)
    {
        return -1;
    }

    return 0;
}

int filesystem_rename(const char* old_path, const char* new_path)
{
    char old_parent[512];
    char old_name[MAX_FILENAME_LEN];
    char new_parent[512];
    char new_name[MAX_FILENAME_LEN];
    int idx;
    FileEntry* entry;
    uint32_t new_parent_id;

    if (!old_path || !old_path[0] || !new_path || !new_path[0] || !file_table)
    {
        return -1;
    }

    // Split both paths
    if (split_path(old_path, old_parent, sizeof(old_parent),
                   old_name, sizeof(old_name)) != 0)
    {
        return -1;
    }

    if (split_path(new_path, new_parent, sizeof(new_parent),
                   new_name, sizeof(new_name)) != 0)
    {
        return -1;
    }

    spin_lock(&file_table_lock);

    // Find the old file
    idx = find_entry_by_path_nolock(file_table, old_path);
    if (idx < 0)
    {
        spin_unlock(&file_table_lock);
        DDBG("[Diff FS] filesystem_rename: source '%s' not found\n", old_path);
        return -1;
    }

    entry = &file_table->entries[idx];

    // Check if destination already exists
    if (find_entry_by_path_nolock(file_table, new_path) >= 0)
    {
        spin_unlock(&file_table_lock);
        DDBG("[Diff FS] filesystem_rename: destination '%s' already exists\n", new_path);
        return -1;
    }

    // Find new parent directory
    if (new_parent[0] == '/' && new_parent[1] == '\0')
    {
        new_parent_id = detect_root_id(file_table);
    }
    else
    {
        int parent_idx = find_entry_by_path_nolock(file_table, new_parent);
        if (parent_idx < 0 || file_table->entries[parent_idx].type != ENTRY_TYPE_DIR)
        {
            spin_unlock(&file_table_lock);
            DDBG("[Diff FS] filesystem_rename: new parent '%s' not found or not a directory\n", new_parent);
            return -1;
        }
        new_parent_id = file_table->entries[parent_idx].entry_id;
    }

    // Update the entry
    entry->parent_id = new_parent_id;
    (void)strlcpy(entry->filename, new_name, MAX_FILENAME_LEN);

    spin_unlock(&file_table_lock);

    // Write updated file table
    if (write_file_table(&superblock) != 0)
    {
        DDBG("[Diff FS] filesystem_rename: failed to write file table\n");
        return -1;
    }

    DDBG("[Diff FS] filesystem_rename: renamed '%s' to '%s'\n", old_path, new_path);

    return 0;
}
