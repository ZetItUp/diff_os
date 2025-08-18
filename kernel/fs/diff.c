#include "diff.h"
#include "stdio.h"
#include "string.h"
#include "stddef.h"
#include "heap.h"
#include "drivers/ata.h"

/*
 * Diff FS (safe, rules-compliant)
 * - No strtok/strchr/strrchr.
 * - All copies via strlcpy (bounded).
 * - Tolerant path tokenizer: collapses //, skips ".", trims spaces.
 * - ASCII case-insensitive matching (but exact also accepted).
 * - Auto-detect root directory (parent_id == 0), fallback to 1.
 * - Allman brace style; declarations at start of each block; English comments.
 */

SuperBlock superblock;
FileTable *file_table;
static uint8_t *file_bitmap;
static uint8_t *sector_bitmap;

/* ---------- Low-level I/O ---------- */

int disk_read(uint32_t sector, uint32_t count, void *buffer)
{
    return ata_read(sector, count, buffer);
}

int disk_write(uint32_t sector, uint32_t count, const void *buffer)
{
    return ata_write(sector, count, buffer);
}

/* ---------- Superblock / tables ---------- */

int read_superblock(SuperBlock *sb)
{
    return disk_read(2048, 1, sb);
}

int init_filesystem(void)
{
    int r;

    r = read_superblock(&superblock);
    if (r <= 0)
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

    return 0;
}

int read_file_table(const SuperBlock *sb)
{
    size_t table_size_bytes;
    size_t bitmap_size_bytes;
    int r;

    table_size_bytes = sb->file_table_size * SECTOR_SIZE;
    file_table = (FileTable *)kmalloc(table_size_bytes);
    if (!file_table)
    {
        printf("[Diff FS] ERROR: OOM for file_table (%u bytes)\n", (unsigned)table_size_bytes);
        return -1;
    }

    r = disk_read(sb->file_table_sector, sb->file_table_size, file_table);
    if (r <= 0)
    {
        printf("[Diff FS] ERROR: disk_read(file_table) failed\n");
        return -1;
    }

    bitmap_size_bytes = sb->file_table_bitmap_size * SECTOR_SIZE;
    file_bitmap = (uint8_t *)kmalloc(bitmap_size_bytes);
    if (!file_bitmap)
    {
        printf("[Diff FS] ERROR: OOM for file_bitmap (%u bytes)\n", (unsigned)bitmap_size_bytes);
        return -1;
    }

    r = disk_read(sb->file_table_bitmap_sector, sb->file_table_bitmap_size, file_bitmap);
    if (r <= 0)
    {
        printf("[Diff FS] ERROR: disk_read(file_bitmap) failed\n");
        return -1;
    }

    return 0;
}

/* ---------- Case-insensitive compare (ASCII) ---------- */

static int ascii_stricmp(const char *a, const char *b)
{
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
            return (int)ca - (int)cb;
        }
    }
}

/* ---------- Directory / path helpers ---------- */

static uint32_t detect_root_id(const FileTable *table)
{
    int i;

    for (i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *fe;

        fe = &table->entries[i];

        if (fe->entry_id != 0 && fe->parent_id == 0 && fe->type == ENTRY_TYPE_DIR)
        {
            return fe->entry_id;
        }
    }

    return 1; /* fallback */
}

int find_entry_in_dir(const FileTable *table, uint32_t parent_id, const char *filename)
{
    int i;

    for (i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *fe;

        fe = &table->entries[i];
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

/* Right-trim spaces/tabs in-place. */
static void rstrip_token(char *s)
{
    size_t n;

    if (!s)
    {
        return;
    }

    n = 0;
    while (s[n] != '\0')
    {
        n++;
    }

    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
    {
        s[--n] = '\0';
    }
}

/*
 * Tokenizer (tolerant):
 * - Collapses multiple '/'.
 * - Trims spaces around component.
 * - Skips "." and empty components.
 * - Writes next component into 'out' and returns 1; 0 if none left.
 */
static int path_next_token(char **it, char *out, size_t out_sz)
{
    char *p;
    size_t n;

    if (!it || !*it || !out || out_sz == 0)
    {
        return 0;
    }

    p = *it;

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

    n = 0;
    while (*p != '\0' && *p != '/' && (n + 1) < out_sz)
    {
        out[n++] = *p++;
    }
    out[n] = '\0';

    *it = p;

    /* trim around token */
    rstrip_token(out);
    {
        char *s;
        char *dst;

        s = out;
        while (*s == ' ' || *s == '\t')
        {
            s++;
        }
        if (s != out)
        {
            dst = out;
            while (*s)
            {
                *dst++ = *s++;
            }
            *dst = '\0';
        }
    }

    if (out[0] == '\0' || (out[0] == '.' && out[1] == '\0'))
    {
        return path_next_token(it, out, out_sz);
    }

    return 1;
}

int find_entry_by_path(const FileTable *table, const char *path)
{
    char buf[512];
    char *cursor;
    uint32_t current_parent;
    int index;
    char token[MAX_FILENAME_LEN];

    if (!path || !*path)
    {
        return -1;
    }

    (void)strlcpy(buf, path, sizeof(buf));
    rstrip_token(buf);
    {
        char *s;
        char *dst;

        s = buf;
        while (*s == ' ' || *s == '\t')
        {
            s++;
        }
        if (s != buf)
        {
            dst = buf;
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
        const FileEntry *fe;
        char *peek;

        index = find_entry_in_dir(table, current_parent, token);
        if (index == -1)
        {
            return -1;
        }

        fe = &table->entries[index];

        peek = cursor;
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

/* ---------- File I/O ---------- */

int read_file(const FileTable *table, const char *path, void *buffer)
{
    int index;
    const FileEntry *fe;
    uint8_t temp[SECTOR_SIZE];
    uint8_t *buf_ptr;
    uint32_t bytes_left;
    uint32_t s;

    index = find_entry_by_path(table, path);
    if (index == -1)
    {
        return -1;
    }

    fe = &table->entries[index];
    if (fe->type != ENTRY_TYPE_FILE)
    {
        return -1;
    }

    buf_ptr = (uint8_t *)buffer;
    bytes_left = fe->file_size_bytes;

    for (s = 0; s < fe->sector_count; s++)
    {
        int rr;
        uint32_t to_copy;

        rr = disk_read(fe->start_sector + s, 1, temp);
        if (rr < 0)
        {
            return -2;
        }

        to_copy = (bytes_left > SECTOR_SIZE) ? SECTOR_SIZE : bytes_left;
        memcpy(buf_ptr, temp, to_copy);
        buf_ptr += to_copy;
        bytes_left -= to_copy;

        if (bytes_left == 0)
        {
            break;
        }
    }

    return fe->file_size_bytes;
}

/* ---------- Allocation bitmaps ---------- */

void set_bitmap_bit(uint8_t *bitmap, int index)
{
    bitmap[index / 8] |= (uint8_t)(1 << (index % 8));
}

void clear_bitmap_bit(uint8_t *bitmap, int index)
{
    bitmap[index / 8] &= (uint8_t)~(1 << (index % 8));
}

int is_bitmap_bit_set(const uint8_t *bitmap, int index)
{
    return (bitmap[index / 8] & (uint8_t)(1 << (index % 8))) != 0;
}

int find_free_entry(const uint8_t *bitmap, int max_files)
{
    int i;

    for (i = 0; i < max_files; i++)
    {
        if (!is_bitmap_bit_set(bitmap, i))
        {
            return i;
        }
    }

    return -1;
}

int allocate_file_entry(const char *name, EntryType type, int max_files)
{
    int index;
    FileEntry *entry;

    index = find_free_entry(file_bitmap, max_files);
    if (index == -1)
    {
        return -1;
    }

    set_bitmap_bit(file_bitmap, index);

    entry = &file_table->entries[index];
    memset(entry, 0, sizeof(FileEntry));
    entry->entry_id = (uint32_t)(index + 1); /* Never use 0 */
    entry->type = type;
    (void)strlcpy(entry->filename, name, MAX_FILENAME_LEN);

    return index;
}

/* ---------- Sector bitmap ---------- */

int read_sector_bitmap(const SuperBlock *sb)
{
    size_t bitmap_bytes;
    int r;

    bitmap_bytes = sb->sector_bitmap_size * SECTOR_SIZE;
    sector_bitmap = (uint8_t *)kmalloc(bitmap_bytes);
    if (!sector_bitmap)
    {
        printf("[Diff FS] ERROR: OOM for sector_bitmap (%u bytes)\n", (unsigned)bitmap_bytes);
        return -1;
    }

    r = disk_read(sb->sector_bitmap_sector, sb->sector_bitmap_size, sector_bitmap);
    return (r < 0) ? r : 0;
}

int allocate_sectors(uint32_t count, uint32_t *first_sector, const SuperBlock *sb)
{
    uint32_t i;
    uint32_t allocated;

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

    return (allocated == count) ? 0 : -1;
}

void free_sectors(uint32_t start, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++)
    {
        clear_bitmap_bit(sector_bitmap, (int)(start + i));
    }
}

int write_file_table(const SuperBlock *sb)
{
    int bytes;

    bytes = disk_write(sb->file_table_sector, sb->file_table_size, file_table);
    return (bytes <= 0) ? -1 : 0;
}

int write_sector_bitmap(const SuperBlock *sb)
{
    int bytes;

    bytes = disk_write(sb->sector_bitmap_sector, sb->sector_bitmap_size, sector_bitmap);
    return (bytes <= 0) ? -1 : 0;
}

