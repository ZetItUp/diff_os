#pragma once
#include <stdint.h>

// Types

#define MAX_FILENAME_LEN 64
#define MAX_FILES 256

typedef enum
{
    ENTRY_TYPE_INVALID = 0,
    ENTRY_TYPE_FILE = 1,
    ENTRY_TYPE_DIR = 2
} EntryType;

typedef struct
{
    uint32_t entry_id;
    uint32_t parent_id;
    EntryType type;
    char filename[MAX_FILENAME_LEN];
    uint32_t start_sector;
    uint32_t sector_count;
    uint32_t file_size_bytes;
    uint32_t created_timestamp;
    uint32_t modified_timestamp;
    uint8_t reserved[32];
} __attribute__((packed)) FileEntry;

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
} FileTable;

// Globals

extern FileTable* file_table;
extern SuperBlock superblock;

// Low-level I/O

int disk_read(uint32_t sector, uint32_t count, void* buffer);
int disk_write(uint32_t sector, uint32_t count, const void* buffer);

// Superblock / tables

int read_superblock(SuperBlock* sb);
int read_file_table(const SuperBlock* sb);
int init_filesystem(void);

// Lookup

int find_entry_in_dir(const FileTable* table, uint32_t parent_id, const char* filename);
int find_entry_by_path(const FileTable* table, const char* path);

// File I/O

int read_file(const FileTable* table, const char* path, void* buffer); // returns bytes read or negative error

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

