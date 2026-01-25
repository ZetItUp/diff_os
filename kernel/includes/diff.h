#pragma once
#include <stdint.h>
#include <stddef.h>

// Types

#define MAX_FILENAME_LEN 256
#define MAX_FILES 256

#ifndef FILESYSTEM_MAX_OPEN
#define FILESYSTEM_MAX_OPEN 64
#endif

#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_CUR
#define SEEK_CUR 1
#endif
#ifndef SEEK_END
#define SEEK_END 2
#endif

typedef enum
{
    ENTRY_TYPE_INVALID = 0,
    ENTRY_TYPE_FILE    = 1,
    ENTRY_TYPE_DIR     = 2,
    ENTRY_TYPE_SYMLINK = 3
} EntryType;

/* Feature flags for superblock */
#define DIFF_FEATURE_SYMLINKS  0x00000001

/* Maximum symlink target length (inline in FileEntry) */
#define MAX_SYMLINK_TARGET 48

typedef struct
{
    uint32_t entry_id;
    uint32_t parent_id;
    EntryType type;
    char filename[MAX_FILENAME_LEN];

    union {
        /* For ENTRY_TYPE_FILE and ENTRY_TYPE_DIR */
        struct {
            uint32_t start_sector;
            uint32_t sector_count;
            uint32_t file_size_bytes;
        } file;

        /* For ENTRY_TYPE_SYMLINK */
        struct {
            char target[MAX_SYMLINK_TARGET];  /* Target path (null-terminated) */
        } symlink;
    } data;

    uint32_t created_timestamp;
    uint32_t modified_timestamp;
    uint8_t reserved[20];  /* Reduced from 32 to maintain struct size */
} __attribute__((packed)) FileEntry;

/* Compatibility macros for accessing file fields */
#define fe_start_sector(fe)    ((fe)->data.file.start_sector)
#define fe_sector_count(fe)    ((fe)->data.file.sector_count)
#define fe_file_size_bytes(fe) ((fe)->data.file.file_size_bytes)
#define fe_symlink_target(fe)  ((fe)->data.symlink.target)

typedef struct
{
    uint32_t magic;
    uint32_t version;
    uint32_t total_sectors;
    uint32_t file_table_sector;
    uint32_t file_table_size;
    uint32_t file_table_bitmap_sector;
    uint32_t file_table_bitmap_size;
    uint32_t sector_bitmap_sector;
    uint32_t sector_bitmap_size;
    uint32_t root_dir_id;
    uint32_t feature_flags;
    uint8_t reserved[480];
} __attribute__((packed)) SuperBlock;

typedef struct
{
    FileEntry entries[MAX_FILES];
    int count;
} FileTable;

typedef struct FileHandle
{
    uint32_t entry_index;  // Index into file_table entries
    uint32_t offset;       // Current read offset
    int in_use;            // 1 if slot is allocated
    uint8_t *cache_buf;    // Read cache buffer
    uint32_t cache_start;  // Cache start offset
    uint32_t cache_valid;  // Valid bytes in cache
} FileHandle;

typedef struct filesystem_stat_t
{
    uint32_t size; // File size in bytes
} filesystem_stat_t;

// Globals

extern FileTable* file_table;
extern SuperBlock superblock;

// Low-level I/O

int disk_read(uint32_t sector, uint32_t count, void* buffer);
int disk_write(uint32_t sector, uint32_t count, const void* buffer);
void diff_set_module_image(const void *base, uint32_t bytes);

// Superblock / tables

int read_superblock(SuperBlock* sb);
int read_file_table(const SuperBlock* sb);
int init_filesystem(void);

// Lookup

int find_entry_in_dir(const FileTable* table, uint32_t parent_id, const char* filename);
int find_entry_by_path(const FileTable* table, const char* path);

// File I/O

int read_file(const FileTable* table, const char* path, void* buffer); // returns bytes read or negative error

int filesystem_close(int fd);
int filesystem_open(const char *path);
int filesystem_read(int fd, void *buffer, uint32_t count);
int filesystem_write(int fd, const void *buffer, uint32_t count);
int32_t filesystem_lseek(int fd, int32_t off, int whence);
int filesystem_stat(const char *path, filesystem_stat_t *st);
int filesystem_fstat(int fd, filesystem_stat_t *st);

// File creation and deletion
int filesystem_create(const char *path, uint32_t initial_size);
int filesystem_delete(const char *path);
int filesystem_rename(const char *old_path, const char *new_path);
int filesystem_mkdir(const char *path);
int filesystem_rmdir(const char *path);

// Symlink operations
int filesystem_symlink(const char *target, const char *linkpath);
int filesystem_readlink(const char *path, char *buf, size_t bufsize);
int filesystem_is_symlink(const char *path);

// Bitmaps

void set_bitmap_bit(uint8_t* bitmap, int index);
void clear_bitmap_bit(uint8_t* bitmap, int index);
int is_bitmap_bit_set(const uint8_t* bitmap, int index);
int find_free_entry(const uint8_t* bitmap, int max_files);

// Allocation

int allocate_file_entry(const char* name, EntryType type, int max_files);
int read_sector_bitmap(const SuperBlock* sb);
int allocate_sectors(uint32_t count, uint32_t* first_sector, const SuperBlock* sb);
void free_sectors(uint32_t start, uint32_t count);

// Write-back

int write_file_table(const SuperBlock* sb);
int write_sector_bitmap(const SuperBlock* sb);
