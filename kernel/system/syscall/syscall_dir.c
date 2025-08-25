#include "stdint.h"
#include "stddef.h"
#include "string.h"
#include "stdio.h"
#include "heap.h"
#include "paging.h"
#include "console.h"
#include "dirent.h"
#include "system/usercopy.h"
#include "interfaces.h"
#include "diff.h"

#define MAX_DIR_HANDLES 32

typedef struct
{
    int used;
    uint32_t parent_id;
    uint32_t cursor;
} dir_handle_t;

extern FileTable *file_table;

static dir_handle_t g_dir[MAX_DIR_HANDLES];

// Try to find root dir id
static uint32_t find_root_id(void)
{
    // First check for dir with parent id 0
    for(int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *fe = &file_table->entries[i];

        if(fe->entry_id && fe->type == ENTRY_TYPE_DIR && fe->parent_id == 0)
        {
            return fe->entry_id;
        }
    }

    // If not found, pick the lowest dir id
    uint32_t root_id = 0;

    for(int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *fe = &file_table->entries[i];

        if(fe->entry_id && fe->type == ENTRY_TYPE_DIR)
        {
            if(!root_id || fe->entry_id < root_id)
            {
                root_id = fe->entry_id;
            }
        }
    }

    return root_id;
}

// Compare two names char by char
static int name_equals(const char *a, const char *b)
{
    for(int i = 0; i < MAX_FILENAME_LEN; i++)
    {
        char ca = a[i];
        char cb = b[i];

        if(ca != cb)
        {
            return 0;
        }

        if(ca == '\0')
        {
            return 1;
        }
    }

    return 1;
}

// Look for child dir under given parent
static int find_child_dir(uint32_t parent_id, const char *name, uint32_t *out_id)
{
    if(!name || !name[0])
    {
        return -1;
    }

    for(int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *fe = &file_table->entries[i];

        if(!fe->entry_id)
        {
            continue;
        }

        if(fe->parent_id != parent_id)
        {
            continue;
        }

        if(fe->type != ENTRY_TYPE_DIR)
        {
            continue;
        }

        if(name_equals(fe->filename, name))
        {
            *out_id = fe->entry_id;

            return 0;
        }
    }

    return -1;
}

// Go through path string and resolve to dir id
static int path_to_dir_id(const char *path, uint32_t *out_id)
{
    uint32_t cur = 0;
    int absolute = 0;

    // Handle empty or "."
    if(!path || !path[0] || (path[0] == '.' && path[1] == '\0'))
    {
        cur = find_root_id();

        if(!cur)
        {
            return -1;
        }
    }
    else if(path[0] == '/')
    {
        // Absolute path, start from root
        absolute = 1;
        cur = find_root_id();

        if(!cur)
        {
            return -1;
        }

        // If it's only a "/", return root
        if(path[1] == '\0')
        {
            *out_id = cur;

            return 0;
        }
    }
    else
    {
        // Relative path, for now also from root
        cur = find_root_id();

        if(!cur)
        {
            return -1;
        }
    }

    // Tokenize
    const char *p = path + (absolute ? 1 : 0);
    char tok[NAME_MAX];
    int ti = 0;

    while(1)
    {
        char c = *p++;
        int end = (c == '\0');

        if(c == '/' || end)
        {
            tok[ti] = '\0';
            ti = 0;

            if(tok[0] == '\0')
            {
                // Skip empty token like "//"
            }
            else if(tok[0] == '.' && tok[1] == '\0')
            {
                // Stay in same dir
            }
            else if(tok[0] == '.' && tok[1] == '.' && tok[2] == '\0')
            {
                // Go one step up
                uint32_t parent_of_cur = 0;

                for(int i = 0; i < MAX_FILES; i++)
                {
                    const FileEntry *fe = &file_table->entries[i];

                    if(fe->entry_id == cur)
                    {
                        parent_of_cur = fe->parent_id;

                        break;
                    }
                }

                if(parent_of_cur != 0)
                {
                    cur = parent_of_cur;
                }
            }
            else
            {
                // Try to step into child dir
                uint32_t next_id = 0;

                if(find_child_dir(cur, tok, &next_id) != 0)
                {
                    return -1;
                }

                cur = next_id;
            }

            if(end)
            {
                break;
            }
        }
        else
        {
            if(ti < NAME_MAX - 1)
            {
                tok[ti++] = c;
            }
        }
    }

    *out_id = cur;

    return 0;
}

// Grab a free handle slot
static int dir_handle_alloc(void)
{
    for(int i = 0; i < MAX_DIR_HANDLES; i++)
    {
        if(!g_dir[i].used)
        {
            g_dir[i].used = 1;
            g_dir[i].parent_id = 0;
            g_dir[i].cursor = 0;

            return i;
        }
    }

    return -1;
}

// Mark handle slot free again
static void dir_handle_free(int handle)
{
    if(handle >= 0 && handle < MAX_DIR_HANDLES)
    {
        g_dir[handle].used = 0;
        g_dir[handle].parent_id = 0;
        g_dir[handle].cursor = 0;
    }
}

// Open dir given a path
int system_open_dir(const char *path)
{
    if(!file_table)
    {
        // Setup filesystem if first time
        if(init_filesystem() != 0)
        {
            return -1;
        }
    }

    char kpath[256];

    if(path)
    {
        if(copy_string_from_user(kpath, path, sizeof(kpath)) < 0)
        {
            return -1;
        }
    }
    else
    {
        kpath[0] = '\0';
    }

    uint32_t dir_id = 0;

    if(path_to_dir_id(kpath, &dir_id) != 0 || dir_id == 0)
    {
        return -1;
    }

    int handle = dir_handle_alloc();

    if(handle < 0)
    {
        return -1;
    }

    g_dir[handle].parent_id = dir_id;
    g_dir[handle].cursor = 0;

    return handle;
}

// Read entry from dir handle
int system_read_dir(int handle, struct dirent *out)
{
    if(handle < 0 || handle >= MAX_DIR_HANDLES || !out)
    {
        return -1;
    }

    if(!g_dir[handle].used)
    {
        return -1;
    }

    uint32_t parent = g_dir[handle].parent_id;

    struct dirent kdir;

    // Loop through table
    for(uint32_t i = g_dir[handle].cursor; i < (uint32_t)MAX_FILES; i++)
    {
        const FileEntry *fe = &file_table->entries[i];

        if(fe->entry_id == 0)
        {
            continue;
        }

        if(fe->parent_id != parent)
        {
            continue;
        }

        // Fill dirent data
        kdir.d_id = fe->entry_id;
        kdir.d_type = (fe->type == ENTRY_TYPE_DIR) ? DT_DIR :
                      (fe->type == ENTRY_TYPE_FILE) ? DT_REG : DT_UNKNOWN;
        kdir.d_size = fe->file_size_bytes;

        // Copy filename
        size_t src_len = 0;

        while(src_len < MAX_FILENAME_LEN && fe->filename[src_len] != '\0')
        {
            src_len++;
        }

        size_t n = src_len;

        if(n > NAME_MAX - 1)
        {
            n = NAME_MAX - 1;
        }

        if(n)
        {
            memcpy(kdir.d_name, fe->filename, n);
        }

        kdir.d_name[n] = '\0';

        // Save cursor for next call
        g_dir[handle].cursor = i + 1;

        if(copy_to_user(out, &kdir, sizeof(kdir)) != 0)
        {
            return -1;
        }

        return 0;
    }

    // No more files in dir
    return 1;
}

// Close dir handle
int system_close_dir(int handle)
{
    if(handle < 0 || handle >= MAX_DIR_HANDLES)
    {
        return -1;
    }

    if(!g_dir[handle].used)
    {
        return -1;
    }

    dir_handle_free(handle);

    return 0;
}

