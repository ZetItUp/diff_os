#include "diff.h"
#include "string.h"
#include "stddef.h"

int disk_read(uint64_t sector, uint64_t count, void *buffer)
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
int read_file_table(const SuperBlock *sb, FileTable *table)
{
    return disk_read(sb->file_table_sector, sb->file_table_size, table);
}

// Find file/directory in a given directory (parent_id)
int find_entry_in_dir(const FileTable *table, uint64_t parent_id, const char *filename)
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

    uint64_t current_parent = 0;    // Root level, parent_id = 0

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
