#include "system/path.h"
#include "diff.h"
#include "string.h"

#define PATH_MAX_SEGMENTS 64
#define PATH_SEG_LEN      64

static void parts_push(char parts[][PATH_SEG_LEN], int *count, const char *s)
{
    if (!parts || !count || !s)
    {
        return;
    }

    if (*count >= PATH_MAX_SEGMENTS)
    {
        return;
    }

    size_t len = strlen(s);
    if (len >= PATH_SEG_LEN)
    {
        len = PATH_SEG_LEN - 1;
    }

    memcpy(parts[*count], s, len);
    parts[*count][len] = '\0';
    (*count)++;
}

static void parts_pop(int *count)
{
    if (!count)
    {
        return;
    }

    if (*count > 0)
    {
        (*count)--;
    }
}

static void split_into_parts(const char *path, char parts[][PATH_SEG_LEN], int *count)
{
    if (!path || !parts || !count)
    {
        return;
    }

    const char *p = path;

    while (*p == '/')
    {
        p++;
    }

    while (*p)
    {
        const char *start = p;

        while (*p && *p != '/')
        {
            p++;
        }

        size_t len = (size_t)(p - start);
        if (len > 0)
        {
            char tmp[PATH_SEG_LEN];

            if (len >= sizeof(tmp))
            {
                len = sizeof(tmp) - 1;
            }

            memcpy(tmp, start, len);
            tmp[len] = '\0';

            if (strcmp(tmp, ".") == 0)
            {
                /* ignore */
            }
            else if (strcmp(tmp, "..") == 0)
            {
                parts_pop(count);
            }
            else
            {
                parts_push(parts, count, tmp);
            }
        }

        while (*p == '/')
        {
            p++;
        }
    }
}

int path_normalize(const char *base, const char *input, char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
    {
        return -1;
    }

    char parts[PATH_MAX_SEGMENTS][PATH_SEG_LEN];
    int count = 0;
    const char *base_path = (base && base[0]) ? base : "/";
    const char *input_path = (input && input[0]) ? input : ".";
    int absolute = (input_path[0] == '/');

    if (!absolute)
    {
        split_into_parts(base_path, parts, &count);
    }
    else
    {
        count = 0;
    }

    split_into_parts(input_path, parts, &count);

    if (count == 0)
    {
        if (out_sz < 2)
        {
            return -1;
        }
        out[0] = '/';
        out[1] = '\0';
        return 0;
    }

    size_t off = 0;
    for (int i = 0; i < count; i++)
    {
        const char *seg = parts[i];
        size_t seglen = strlen(seg);

        if (off + 1 + seglen >= out_sz)
        {
            if (out_sz > 0)
            {
                out[0] = '\0';
            }
            return -1;
        }

        out[off++] = '/';
        memcpy(out + off, seg, seglen);
        off += seglen;
    }

    if (off >= out_sz)
    {
        return -1;
    }

    out[off] = '\0';
    return 0;
}

uint32_t vfs_root_id(void)
{
    if (superblock.root_dir_id != 0)
    {
        return superblock.root_dir_id;
    }

    if (file_table)
    {
        for (int i = 0; i < MAX_FILES; i++)
        {
            const FileEntry *fe = &file_table->entries[i];
            if (fe->entry_id != 0 && fe->type == ENTRY_TYPE_DIR && fe->parent_id == 0)
            {
                return fe->entry_id;
            }
        }
    }

    return 1;
}

static int vfs_find_entry_index_by_id(uint32_t entry_id)
{
    if (!file_table || entry_id == 0)
    {
        return -1;
    }

    for (int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *fe = &file_table->entries[i];
        if (fe->entry_id == entry_id)
        {
            return i;
        }
    }

    return -1;
}

int vfs_resolve_entry(const char *abs_path, int *out_index)
{
    if (!out_index || !abs_path || abs_path[0] != '/')
    {
        return -1;
    }

    if (!file_table)
    {
        return -1;
    }

    if (abs_path[1] == '\0')
    {
        int idx = vfs_find_entry_index_by_id(vfs_root_id());
        if (idx < 0)
        {
            return -1;
        }
        *out_index = idx;
        return 0;
    }

    int idx = find_entry_by_path(file_table, abs_path);
    if (idx < 0)
    {
        return -1;
    }

    *out_index = idx;
    return 0;
}

int vfs_resolve_dir(const char *abs_path, uint32_t *out_dir_id)
{
    if (!out_dir_id || !abs_path || abs_path[0] != '/')
    {
        return -1;
    }

    if (!file_table)
    {
        return -1;
    }

    if (abs_path[1] == '\0')
    {
        *out_dir_id = vfs_root_id();
        return 0;
    }

    int idx = -1;
    if (vfs_resolve_entry(abs_path, &idx) != 0)
    {
        return -1;
    }

    const FileEntry *fe = &file_table->entries[idx];
    if (fe->type != ENTRY_TYPE_DIR)
    {
        return -1;
    }

    *out_dir_id = fe->entry_id;
    return 0;
}
