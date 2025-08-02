#include "diff.h"
#include "string.h"
#include "stddef.h"
#include "heap.h"
#include "drivers/ata.h"

#define SECTOR_SIZE     512

FileTable *file_table;
static uint8_t *file_bitmap;
static uint8_t *sector_bitmap;      // Points to bitmap in RAM

int disk_read(uint32_t sector, uint32_t count, void *buffer)
{
    return ata_read(sector, count, buffer);
}

// Read superblock from fixed sector (FS_START_LBA)
int read_superblock(SuperBlock *sb)
{
    return disk_read(2048, 1, sb);
}

// Read file table and its bitmap from disk
int read_file_table(const SuperBlock *sb)
{
    size_t table_size_bytes = sb->file_table_size * SECTOR_SIZE;
    file_table = kmalloc(table_size_bytes);

    if (disk_read(sb->file_table_sector, sb->file_table_size, file_table) != 0)
    {
        return -1;
    }

    size_t bitmap_size_bytes = sb->file_table_bitmap_size * SECTOR_SIZE;
    file_bitmap = kmalloc(bitmap_size_bytes);

    if (disk_read(sb->file_table_bitmap_sector, sb->file_table_bitmap_size, file_bitmap) != 0)
    {
        return -1;
    }

    return 0;
}

// Find file/directory entry with given filename under given parent_id
int find_entry_in_dir(const FileTable *table, uint32_t parent_id, const char *filename)
{
    for (int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *fe = &table->entries[i];

        if (fe->entry_id == 0)
        {
            continue;
        }

        if (fe->parent_id == parent_id &&
            strncmp(fe->filename, filename, MAX_FILENAME_LEN) == 0)
        {
            return i;
        }
    }

    return -1;
}

// Find entry in filetable from absolute path (e.g. "/system/drivers/keyboard.ddf")
int find_entry_by_path(const FileTable *table, const char *path)
{
    if (path == NULL)
    {
        return -1;
    }

    // Support absolute path (skip leading '/')
    if (path[0] == '/')
    {
        path++;
    }

    uint32_t current_parent = 1;   // Root directory (id=1)

    // Copy filepath (so we can tokenize)
    char path_copy[MAX_FILENAME_LEN * 4]; // Allow long path
    strncpy(path_copy, path, sizeof(path_copy));
    path_copy[sizeof(path_copy) - 1] = '\0';

    char *token = strtok(path_copy, "/");
    int index = -1;

    while (token != NULL)
    {
        index = find_entry_in_dir(table, current_parent, token);

        if (index == -1)
        {
            return -1; // No such entry
        }

        const FileEntry *fe = &table->entries[index];

        // Next token = must be a directory
        token = strtok(NULL, "/");

        if (token != NULL)
        {
            if (fe->type != ENTRY_TYPE_DIR)
            {
                return -1; // Can't go inside file
            }
            current_parent = fe->entry_id;
        }
    }

    return index;
}

// Read file contents into buffer (buffer must be large enough)
int read_file(const SuperBlock *sb, const FileTable *table, const char *path, void *buffer)
{
    (void)sb; // Not needed, could be used for sector size
    int index = find_entry_by_path(table, path);

    if (index == -1)
    {
        return -1;
    }

    const FileEntry *fe = &table->entries[index];

    if (fe->type != ENTRY_TYPE_FILE)
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

// Check if bit is set
int is_bitmap_bit_set(const uint8_t *bitmap, int index)
{
    return bitmap[index / 8] & (1 << (index % 8));
}

// Find first free entry in File Table
int find_free_entry(const uint8_t *bitmap, int max_files)
{
    for (int i = 0; i < max_files; i++)
    {
        if (!is_bitmap_bit_set(bitmap, i))
        {
            return i;
        }
    }

    return -1;
}

// Allocate file entry (returns new index or -1)
int allocate_file_entry(const char *name, EntryType type, int max_files)
{
    int index = find_free_entry(file_bitmap, max_files);

    if (index == -1)
    {
        return -1;  // No more available space
    }

    set_bitmap_bit(file_bitmap, index);

    FileEntry *entry = &file_table->entries[index];
    memset(entry, 0, sizeof(FileEntry));
    entry->entry_id = (uint32_t)(index + 1);    // Never 0
    entry->type = type;
    strncpy(entry->filename, name, MAX_FILENAME_LEN - 1);
    entry->filename[MAX_FILENAME_LEN - 1] = 0;

    return index;
}

// Read sector bitmap from disk to RAM
int read_sector_bitmap(const SuperBlock *sb)
{
    size_t bitmap_bytes = sb->sector_bitmap_size * SECTOR_SIZE;
    sector_bitmap = kmalloc(bitmap_bytes);

    return disk_read(sb->sector_bitmap_sector, sb->sector_bitmap_size, sector_bitmap);
}

// Attempt to allocate "count" sectors, return the start sector
int allocate_sectors(uint32_t count, uint32_t *first_sector, const SuperBlock *sb)
{
    uint32_t allocated = 0;

    for (uint32_t i = 0; i < sb->total_sectors && allocated < count; i++)
    {
        if (!is_bitmap_bit_set(sector_bitmap, i))
        {
            if (allocated == 0)
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
    for (uint32_t i = 0; i < count; i++)
    {
        clear_bitmap_bit(sector_bitmap, start + i);
    }
}

