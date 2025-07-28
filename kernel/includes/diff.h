#ifndef DIFF_FS_H
#define DIFF_FS_H

#include <stdint.h>

#define MAX_FILENAME_LEN    64
#define MAX_FILES           256

typedef enum
{
    ENTRY_TYPE_INVALID = 0,
    ENTRY_TYPE_FILE = 1,
    ENTRY_TYPE_DIR = 2,
} EntryType;

typedef struct
{
    uint32_t entry_id;                  // Unique ID for Post
    uint32_t parent_id;                 // ID to parent directory
    EntryType type;                     // File or Directory?
    char filename[MAX_FILENAME_LEN];    // Name of file/directory
    uint32_t start_sector;              // Startaddress (LBA) on disk
    uint32_t sector_count;              // Sectors occupied by file
    uint32_t file_size_bytes;           // Exact size in bytes
    uint32_t created_timestamp;         // Created time (UNIX timestamp)
    uint32_t modified_timestamp;        // Changed time (UNIX timestamp)
    uint8_t reserved[32];               // Future stuff
} FileEntry;

typedef struct
{
    uint32_t magic;                     // Signature 'DIFF_FS1'
    uint32_t version;                   // Filesystem version
    uint32_t total_sectors;             // Disksize in sectors
    uint32_t file_table_sector;         // File table start sector
    uint32_t file_table_size;           // File table sectors 
    uint32_t file_table_bitmap_sector;  // Start sector for file table bitmap
    uint32_t file_table_bitmap_size;    // File table bitmap size
    uint32_t sector_bitmap_sector;      // Start sector for sector bitmap
    uint32_t sector_bitmap_size;        // Size in sectors
    uint32_t root_dir_id;               // Root directory ID
    uint32_t feature_flags;             // Bitmask for future support
    uint8_t reserved[480];              // Padding to 512 bytes
} SuperBlock;

typedef struct
{
    FileEntry entries[MAX_FILES];       // Static list of entries (for now)
} FileTable;

// Read 'count' sectors from 'sector' into 'buffer'
extern int disk_read(uint32_t sector, uint64_t count, void *buffer);

// Read suberblock from disk
int read_superblock(SuperBlock *sb);

// Read filetable
int read_file_table(const SuperBlock *sb);

// Find post given parent_id and filename, returns index or -1
int find_entry_in_dir(const FileTable *table, uint32_t parent_id, const char *filename);

// Find file or directory through absolute path (ex. "/drivers/keyboard.drv")
// Returns index in the table or -1 if not found
int find_entry_by_path(const FileTable *table, const char *path);

// Read file content to buffer, returns 0 on success, -1 on fail
int read_file(const SuperBlock *sb, const FileTable *table, const char *path, void *buffer);

// Set a bit in a bitmap
void set_bitmap_bit(uint8_t *bitmap, int index);

// Clear a bit
void clear_bitmap_bit(uint8_t *bitmap, int index);

// Check if set
int is_bitmap_bit_set(const uint8_t *bitmap, int index);

//Find first free entry in File Table
int find_free_entry(const uint8_t *bitmap, int max_files);

// Allocate new file entry
int allocate_file_entry(const char *name, EntryType type, int max_files);

// Read a sector bitmap
int read_sector_bitmap(const SuperBlock *sb);

// Attempt to allocate sectors, returns start sector
int allocate_sectors(uint32_t count, uint32_t *first_sector, const SuperBlock *sb);

// Free sectors, from start to count
void free_sectors(uint32_t start, uint32_t count);
#endif
