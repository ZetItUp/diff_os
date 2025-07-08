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
    uint64_t entry_id;                  // Unique ID for Post
    uint64_t parent_id;                 // ID to parent directory
    EntryType type;                     // File or Directory?
    char filename[MAX_FILENAME_LEN];    // Name of file/directory
    uint64_t start_sector;              // Startaddress (LBA) on disk
    uint64_t sector_count;              // Sectors occupied by file
    uint64_t file_size_bytes;           // Exact size in bytes
    uint64_t created_timestamp;         // Created time (UNIX timestamp)
    uint64_t modified_timestamp;        // Changed time (UNIX timestamp)
    uint8_t reserved[32];               // Future stuff
} FileEntry;

typedef struct
{
    uint32_t magic;                     // Signature 'DIFF_FS1'
    uint32_t version;                   // Filesystem version
    uint64_t total_sectors;             // Disksize in sectors
    uint64_t file_table_sector;         // File table start sector
    uint64_t file_table_size;           // File table sectors 
    uint64_t root_dir_id;               // Root directory ID
    uint64_t feature_flags;             // Bitmask for future support
    uint8_t reserved[400];              // Padding to 512 bytes
} SuperBlock;

typedef struct
{
    FileEntry entries[MAX_FILES];       // Static list of entries (for now)
} FileTable;

// Read 'count' sectors from 'sector' into 'buffer'
extern int disk_read(uint64_t sector, uint64_t count, void *buffer);

// Read suberblock from disk
int read_superblock(SuperBlock *sb);

// Read filetable
int read_file_table(const SuperBlock *sb, FileTable *table);

// Find post given parent_id and filename, returns index or -1
int find_entry_in_dir(const FileTable *table, uint64_t parent_id, const char *filename);

// Find file or directory through absolute path (ex. "/drivers/keyboard.drv")
// Returns index in the table or -1 if not found
int find_entry_by_path(const FileTable *table, const char *path);

// Read file content to buffer, returns 0 on success, -1 on fail
int read_file(const SuperBlock *sb, const FileTable *table, const char *path, void *buffer);

#endif
