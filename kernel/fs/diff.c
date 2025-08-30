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

        memcpy(dst, src, n);
        return 0;
    }

    memcpy(dst, src, n);
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

        memcpy(dst, src, n);
        return 0;
    }

    memcpy(dst, src, n);
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

#ifdef DIFF_DEBUG
    if (read_bytes != (int)count)
    {
        printf("[Diff FS] read_at_entry short read: wanted=%u got=%d\n", count, read_bytes);
    }
#endif

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
#ifdef DIFF_DEBUG
            printf("[Diff FS] disk_read OOR: sector=%u total=%u\n", sector, superblock.total_sectors);
#endif
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
#ifdef DIFF_DEBUG
            printf("[Diff FS] disk_write OOR: sector=%u total=%u\n", sector, superblock.total_sectors);
#endif
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
#ifdef DIFF_DEBUG
        printf("[Diff FS] WARN: %s count=0\n", what);
#endif
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
#ifdef DIFF_DEBUG
        printf("[Diff FS] read_file: start_sector OOR path='%s' start=%u total=%u\n",
               path, start_sector, superblock.total_sectors);
#endif
        return -2;
    }

    if (superblock.total_sectors &&
        (uint64_t)start_sector + (uint64_t)sector_count > (uint64_t)superblock.total_sectors)
    {
#ifdef DIFF_DEBUG
        printf("[Diff FS] read_file: clamping sector_count (path='%s')\n", path);
#endif
        sector_count = superblock.total_sectors - start_sector;
    }

    // Clamp file size to allocated sectors
    uint64_t capacity_bytes = (uint64_t)sector_count * (uint64_t)SECTOR_SIZE;

    if ((uint64_t)file_size_bytes > capacity_bytes)
    {
        file_size_bytes = (uint32_t)capacity_bytes;
    }

#ifdef DIFF_DEBUG
    printf("[Diff FS] read_file '%s': LBA=%u count=%u size=%u\n",
           path, start_sector, sector_count, file_size_bytes);
#endif

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
#ifdef DIFF_DEBUG
            printf("[Diff FS] read_file: ata_read failed at LBA=%u (chunk=%u)\n", lba, chunk);
#endif
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
#ifdef DIFF_DEBUG
            printf("[Diff FS] read_file: ata_read tail failed at LBA=%u\n", lba);
#endif
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
printf("[FS] read fd=%d off=%u cnt=%u -> r=%d\n", fd, off, count, r);

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

