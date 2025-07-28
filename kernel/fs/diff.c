#include "diff.h"
#include "string.h"
#include "stddef.h"
#include "heap.h"

#define SECTOR_SIZE     512

//static SuperBlock superblock;
static FileEntry *file_table;
static uint8_t *file_bitmap;
static uint8_t *sector_bitmap;      // Point to bitmap in RAM

int disk_read(uint32_t sector, uint64_t count, void *buffer)
{
    (void)sector;
    (void)count;
    (void)buffer;
    // FIXME: Add actual functuality
    return 0;
}

// Read superblock from sector 0
int read_superblock(SuperBlock *sb)
{
    return disk_read(0, 1, sb);
}

// Read file table from filesystems filetable sector
int read_file_table(const SuperBlock *sb)
{
    // Read File Table
    size_t table_size_bytes = sb->file_table_size * SECTOR_SIZE;
    file_table = kmalloc(table_size_bytes);
    
    if(disk_read(sb->file_table_sector, sb->file_table_size, file_table) != 0)
    {
        return -1;
    }

    // Read bitmap
    size_t bitmap_size_bytes = sb->file_table_bitmap_size * SECTOR_SIZE;
    file_bitmap = kmalloc(bitmap_size_bytes);

    if(disk_read(sb->file_table_bitmap_sector, sb->file_table_bitmap_size, file_bitmap) != 0)
    {
        return -1;
    }

    return 0;
}

// Find file/directory in a given directory (parent_id)
int find_entry_in_dir(const FileTable *table, uint32_t parent_id, const char *filename)
{
    for(int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *fe = &table->entries[i];

        if(fe->entry_id == 0)
        {
            continue;   // Empty post
        }

        if(fe->parent_id == parent_id && strncmp(fe->filename, filename, MAX_FILENAME_LEN) == 0)
        {
            return i;
        }
    }

    return -1;
}

// Find entry in filetable from absolute path
int find_entry_by_path(const FileTable *table, const char *path)
{
    if(path == NULL || path[0] != '/')
    {
        return -1;
    }

    uint32_t current_parent = 0;    // Root level, parent_id = 0

    // Copy filepath
    char path_copy[MAX_FILENAME_LEN];
    strncpy(path_copy, path, sizeof(path_copy));
    path_copy[sizeof(path_copy) - 1] = '\0';

    char *token = strtok(path_copy, "/");
    int index = -1;

    while(token != NULL)
    {
        index = find_entry_in_dir(table, current_parent, token);

        if(index == -1)
        {
            return -1;      // No such entry
        }

        const FileEntry *fe = &table->entries[index];

        // If next token exists, we are in a folder
        token = strtok(NULL, "/");

        if(token != NULL)
        {
            if(fe->type != ENTRY_TYPE_DIR)
            {
                return -1;      // Trying to enter a file as a directory
            }

            current_parent = fe->entry_id;
        }
    }

    // Return found entry
    return index;
}

// Read files content to buffer, assuming the buffer size is large enough)
int read_file(const SuperBlock *sb, const FileTable *table, const char *path, void *buffer)
{
    (void)sb;
    int index = find_entry_by_path(table, path);

    if(index == -1)
    {
        return -1;
    }

    const FileEntry *fe = &table->entries[index];

    if(fe->type != ENTRY_TYPE_FILE)
    {
        return -1;
    }

    return disk_read(fe->start_sector, fe->sector_count, buffer);
}

// Set a bit in a bitmap
void set_bitmap_bit(uint8_t *bitmap, int index)
{
    bitmap[index / 8] |= (1 << (index % 8));
}

// Clear a bit
void clear_bitmap_bit(uint8_t *bitmap, int index)
{
    bitmap[index / 8] &= ~(1 << (index % 8));
}

// Check if set
int is_bitmap_bit_set(const uint8_t *bitmap, int index)
{
    return bitmap[index / 8] & (1 << (index % 8));
}

//Find first free entry in File Table
int find_free_entry(const uint8_t *bitmap, int max_files)
{
    for(int i = 0; i < max_files; i++)
    {
        if(!is_bitmap_bit_set(bitmap, i))
        {
            return i;
        }
    }

    return -1;
}

int allocate_file_entry(const char *name, EntryType type, int max_files)
{
    int index = find_free_entry(file_bitmap, max_files);

    if(index == -1)
    {
        return -1;  // No more available space
    }

    set_bitmap_bit(file_bitmap, index);

    FileEntry *entry = &file_table[index];
    memset(entry, 0, sizeof(FileEntry));
    entry->entry_id = index + 1;        // Make sure ID != 0
    entry->type = type;
    strncpy(entry->filename, name, MAX_FILENAME_LEN - 1);

    return index;
}

// Read sector bitmap from disk to RAM
int read_sector_bitmap(const SuperBlock *sb)
{
    size_t bitmap_bytes = sb->sector_bitmap_size * SECTOR_SIZE;     // Size in bytes
                                                                    
    sector_bitmap = kmalloc(bitmap_bytes);

    return disk_read(sb->sector_bitmap_sector, sb->sector_bitmap_size, sector_bitmap);    
}

// Attempt to allocate "count" sectors, return the start sector
int allocate_sectors(uint32_t count, uint32_t *first_sector, const SuperBlock *sb)
{
    uint32_t allocated = 0;

    for(uint32_t i = 0; i < sb->total_sectors && allocated < count; i++)
    {
        if(!is_bitmap_bit_set(sector_bitmap, i))
        {
            // Pick the first sector found
            if(allocated == 0)
            {
                *first_sector = i;
            }

            set_bitmap_bit(sector_bitmap, i);

            allocated++;
        }
    }

    // Return 0 if we succeeded, else -1
    return (allocated == count) ? 0 : -1;
}

void free_sectors(uint32_t start, uint32_t count)
{
    for(uint32_t i = 0; i < count; i++)
    {
        clear_bitmap_bit(sector_bitmap, start + i);
    }
}


