// syscall_dir.c

#include "stdint.h"
#include "stddef.h"
#include "string.h"
#include "stdio.h"
#include "heap.h"
#include "paging.h"
#include "console.h"
#include "dirent.h"
#include "system/usercopy.h"
#include "system/process.h"
#include "system/path.h"
#include "interfaces.h"
#include "diff.h"

#define MAX_DIR_HANDLES 32

typedef struct
{
    int      used;
    uint32_t parent_id;
    uint32_t cursor;
} dir_handle_t;

extern FileTable *file_table;

static dir_handle_t g_dir[MAX_DIR_HANDLES];
static int          g_dir_inited = 0;

static void dir_table_init_once(void)
{
    if (g_dir_inited) return;
    for (int i = 0; i < MAX_DIR_HANDLES; ++i)
    {
        g_dir[i].used      = 0;
        g_dir[i].parent_id = 0;
        g_dir[i].cursor    = 0;
    }
    g_dir_inited = 1;
}

// Grab a free handle slot
static int dir_handle_alloc(void)
{
    for(int i = 0; i < MAX_DIR_HANDLES; i++)
    {
        if(!g_dir[i].used)
        {
            g_dir[i].used      = 1;
            g_dir[i].parent_id = 0;
            g_dir[i].cursor    = 0;
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
        g_dir[handle].used      = 0;
        g_dir[handle].parent_id = 0;
        g_dir[handle].cursor    = 0;
    }
}

// Open dir given a path
int system_open_dir(const char *path)
{
    dir_table_init_once();

    if(!file_table)
    {
        // Setup filesystem if first time
        if(init_filesystem() != 0)
            return -1;
    }

    char kpath[256];
    if(path)
    {
        if(copy_string_from_user(kpath, path, sizeof(kpath)) < 0)
            return -1;
    }
    else
    {
        kpath[0] = '\0';
    }

    process_t *proc = process_current();
    const char *base = process_cwd_path(proc);
    char abs_path[256];
    if (path_normalize(base, kpath, abs_path, sizeof(abs_path)) != 0)
        return -1;

    uint32_t dir_id = 0;
    if(vfs_resolve_dir(abs_path, &dir_id) != 0 || dir_id == 0)
        return -1;

    int handle = dir_handle_alloc();
    if(handle < 0)
        return -1;

    g_dir[handle].parent_id = dir_id;
    g_dir[handle].cursor    = 0;
    return handle;
}

int system_chdir(const char *path)
{
    if (!file_table)
    {
        if (init_filesystem() != 0)
            return -1;
    }

    char kpath[256];
    if (path)
    {
        if (copy_string_from_user(kpath, path, sizeof(kpath)) < 0)
            return -1;
    }
    else
    {
        kpath[0] = '\0';
    }

    process_t *proc = process_current();
    const char *base = process_cwd_path(proc);
    char abs_path[256];
    if (path_normalize(base, kpath, abs_path, sizeof(abs_path)) != 0)
        return -1;

#ifdef DIFF_DEBUG
    printf("[CHDIR] pid=%d from=\"%s\" req=\"%s\" norm=\"%s\"\n",
           proc ? proc->pid : -1, base ? base : "(null)", kpath, abs_path);
#endif
    uint32_t dir_id;
    if (vfs_resolve_dir(abs_path, &dir_id) != 0)
    {
        printf("[CHDIR] resolve failed for \"%s\"\n", abs_path);
        return -1;
    }

    if (!proc)
        return -1;

    process_set_cwd(proc, dir_id, abs_path);
#ifdef DIFF_DEBUG
    printf("[CHDIR] pid=%d cwd_id=%u ok\n", proc->pid, dir_id);
#endif
    return 0;
}

int system_getcwd(char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
    {
        return -1;
    }

    process_t *proc = process_current();
    const char *cwd = process_cwd_path(proc);
    char buf[256];

    (void)strlcpy(buf, cwd, sizeof(buf));

    size_t need = strlen(buf) + 1;
    if (need > out_sz)
    {
        return -1;
    }

    if (copy_to_user(out, buf, need) != 0)
    {
        return -1;
    }

    return (int)need;
}

// Read entry from dir handle
int system_read_dir(int handle, struct dirent *out)
{
    if(handle < 0 || handle >= MAX_DIR_HANDLES || !out)
        return -1;
    if(!g_dir[handle].used)
        return -1;

    uint32_t parent = g_dir[handle].parent_id;
    struct dirent kdir;

    // Loop through table
    for(uint32_t i = g_dir[handle].cursor; i < (uint32_t)MAX_FILES; i++)
    {
        const FileEntry *fe = &file_table->entries[i];
        if(fe->entry_id == 0)              continue;
        if(fe->parent_id != parent)        continue;

        // Fill dirent data
        kdir.d_id   = fe->entry_id;
        kdir.d_type = (fe->type == ENTRY_TYPE_DIR)  ? DT_DIR :
                      (fe->type == ENTRY_TYPE_FILE) ? DT_REG : DT_UNKNOWN;
        kdir.d_size = fe->file_size_bytes;

        // Copy filename
        size_t src_len = 0;
        while(src_len < MAX_FILENAME_LEN && fe->filename[src_len] != '\0') src_len++;
        size_t n = (src_len > NAME_MAX - 1) ? (NAME_MAX - 1) : src_len;
        if(n) memcpy(kdir.d_name, fe->filename, n);
        kdir.d_name[n] = '\0';

        // Save cursor for next call
        g_dir[handle].cursor = i + 1;

        if(copy_to_user(out, &kdir, sizeof(kdir)) != 0)
            return -1;

        return 0;
    }

    // No more files in dir
    return 1;
}

// Close dir handle
int system_close_dir(int handle)
{
    if(handle < 0 || handle >= MAX_DIR_HANDLES)
        return -1;
    if(!g_dir[handle].used)
        return -1;

    dir_handle_free(handle);
    return 0;
}
