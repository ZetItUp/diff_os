#ifndef DIFF_FS_H
#define DIFF_FS_H

#include <stdint.h>

#define MAX_FILENAME_LEN    64
#define MAX_FILES           256

typedef enum
{
    ENTRY_TYPE_INVALID = 0,
    ENTRY_TYPE_FILE    = 1,
    ENTRY_TYPE_DIR     = 2,
} EntryType;

typedef struct
{
    uint32_t entry_id;                  // Unique ID for entry
    uint32_t parent_id;                 // ID of parent directory
    EntryType type;                     // File or Directory
    char filename[MAX_FILENAME_LEN];    // Name of file/directory
    uint32_t start_sector;              // Start LBA on disk
    uint32_t sector_count;              // Sectors occupied by file
    uint32_t file_size_bytes;           // Exact file size in bytes
    uint32_t created_timestamp;         // Creation time (UNIX)
    uint32_t modified_timestamp;        // Modified time (UNIX)
    uint8_t reserved[32];               // Padding / future
} __attribute__((packed)) FileEntry;

typedef struct
{
    uint32_t magic;                     // Signature "DIFF"
    uint32_t version;                   // Filesystem version
    uint32_t total_sectors;             // Disk size in sectors
    uint32_t file_table_sector;         // File table start sector
    uint32_t file_table_size;           // File table size in sectors
    uint32_t file_table_bitmap_sector;  // File table bitmap sector
    uint32_t file_table_bitmap_size;    // Bitmap size in sectors
    uint32_t sector_bitmap_sector;      // Sector bitmap sector
    uint32_t sector_bitmap_size;        // Sector bitmap size
    uint32_t root_dir_id;               // Root directory ID
    uint32_t feature_flags;             // Feature flags (future)
    uint8_t reserved[480];              // Padding to 512 bytes
} __attribute__((packed)) SuperBlock;

typedef struct
{
    FileEntry entries[MAX_FILES];
} FileTable;

extern FileTable *file_table;

// ATA driver must implement this (reads sectors)
int disk_read(uint32_t sector, uint32_t count, void *buffer);

// Read SuperBlock from FS (sector 2048)
int read_superblock(SuperBlock *sb);

// Read FileTable and bitmap into memory
int read_file_table(const SuperBlock *sb);

// Find entry index by parent_id and filename, or -1 if not found
int find_entry_in_dir(const FileTable *table, uint32_t parent_id, const char *filename);

// Find entry index by absolute path ("/system/drivers/xxx.ddf")
int find_entry_by_path(const FileTable *table, const char *path);

// Read a file's contents into buffer, returns 0 on success, -1 on fail
int read_file(const SuperBlock *sb, const FileTable *table, const char *path, void *buffer);

// Bitmap helpers
void set_bitmap_bit(uint8_t *bitmap, int index);
void clear_bitmap_bit(uint8_t *bitmap, int index);
int is_bitmap_bit_set(const uint8_t *bitmap, int index);

// Find first free entry in file bitmap, or -1 if full
int find_free_entry(const uint8_t *bitmap, int max_files);

// Allocate new file entry, returns index or -1 on fail
int allocate_file_entry(const char *name, EntryType type, int max_files);

// Read sector bitmap into memory
int read_sector_bitmap(const SuperBlock *sb);

// Allocate 'count' sectors, returns 0 on success, -1 on fail, sets *first_sector
int allocate_sectors(uint32_t count, uint32_t *first_sector, const SuperBlock *sb);

// Free sectors (mark as unused)
void free_sectors(uint32_t start, uint32_t count);

#endif // DIFF_FS_H

