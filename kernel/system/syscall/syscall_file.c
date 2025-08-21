#include "stdint.h"
#include "stddef.h"
#include "string.h"
#include "stdio.h"
#include "heap.h"
#include "console.h"
#include "interfaces.h"
#include "drivers/ata.h"
#include "system/usercopy.h"
#include "dirent.h"
#include "diff.h"

#ifndef O_RDONLY
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR   0x0002
#define O_CREAT  0x0100
#define O_TRUNC  0x0200
#define O_APPEND 0x0400
#endif

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#define KERNEL_FILE_DESCRIPTOR_BASE 3
#define KERNEL_FILE_DESCRIPTOR_MAX  32

// File descriptor
typedef struct
{
    uint8_t used;
    uint8_t *data;
    uint32_t size;
    uint32_t pos;
    int flags;
    int ft_index;
} file_descriptor_t;

static file_descriptor_t s_file_descriptor[KERNEL_FILE_DESCRIPTOR_MAX];
static int s_sector_bitmap_loaded = 0;

// Check if file can be written
static int file_writable(int flags)
{
    return (flags & (O_WRONLY | O_RDWR)) ? 1 : 0;
}

// Make sure filesystem is initialized
static int verify_fs_ready(void)
{
    if(!file_table)
    {
        if(init_filesystem() != 0)
        {
            return -1;
        }
    }

    return 0;
}

// Make sure sector bitmap is loaded
static int verify_sector_bitmap(void)
{
    if(!s_sector_bitmap_loaded)
    {
        if(read_sector_bitmap(&superblock) <= 0)
        {
            return -1;
        }

        s_sector_bitmap_loaded = 1;
    }

    return 0;
}

// Write file table and sector bitmap back to disk
static int flush_metadata(void)
{
    if(write_file_table(&superblock) != 0)
    {
        return -1;
    }

    if(s_sector_bitmap_loaded)
    {
        if(write_sector_bitmap(&superblock) != 0)
        {
            return -1;
        }
    }

    return 0;
}

// Find root directory id
static uint32_t find_root_id(void)
{
    for(int i = 0; i < MAX_FILES; i++)
    {
        const FileEntry *fe = &file_table->entries[i];

        if(fe->entry_id && fe->type == ENTRY_TYPE_DIR && fe->parent_id == 0)
        {
            return fe->entry_id;
        }
    }

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

// Compare two names
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

// Find child entry under a parent directory
static int find_child_entry(uint32_t parent_id, const char *name, int *out_index)
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

        if(name_equals(fe->filename, name))
        {
            *out_index = i;

            return 0;
        }
    }

    return -1;
}

// Convert path string to file entry index
static int path_to_entry_index(const char *path, int *out_index)
{
    uint32_t cur = 0;
    int absolute = 0;

    if(!path || !path[0])
    {
        return -1;
    }

    cur = find_root_id();

    if(!cur)
    {
        return -1;
    }

    if(path[0] == '/')
    {
        absolute = 1;

        if(path[1] == '\0')
        {
            for(int i = 0; i < MAX_FILES; i++)
            {
                const FileEntry *fe = &file_table->entries[i];

                if(fe->entry_id == cur)
                {
                    *out_index = i;

                    return 0;
                }
            }

            return -1;
        }
    }

    const char *p = path + (absolute ? 1 : 0);
    char tok[NAME_MAX];
    int ti = 0;
    int last_index = -1;

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
                // Skip empty name
            }
            else if(tok[0] == '.' && tok[1] == '\0')
            {
                // Stay in same dir
            }
            else if(tok[0] == '.' && tok[1] == '.' && tok[2] == '\0')
            {
                // Go up one dir
                uint32_t parent_of_cur = 0;
                int parent_index = -1;

                for(int i = 0; i < MAX_FILES; i++)
                {
                    const FileEntry *fe = &file_table->entries[i];

                    if(fe->entry_id == cur)
                    {
                        parent_of_cur = fe->parent_id;
                        parent_index = i;

                        break;
                    }
                }

                if(parent_of_cur != 0)
                {
                    cur = parent_of_cur;
                    last_index = parent_index;
                }
            }
            else
            {
                int child_index = -1;

                if(find_child_entry(cur, tok, &child_index) != 0)
                {
                    return -1;
                }

                const FileEntry *fe = &file_table->entries[child_index];

                cur = fe->entry_id;
                last_index = child_index;
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

    if(last_index < 0)
    {
        return -1;
    }

    *out_index = last_index;

    return 0;
}

// Open a file and return file descriptor
int system_file_open(const char *abs_path, int oflags, int mode)
{
    (void)mode;

    if(verify_fs_ready() != 0)
    {
        return -1;
    }

    char kpath[MAX_FILENAME_LEN];

    if(copy_string_from_user(kpath, abs_path, sizeof(kpath)) != 0)
    {
        return -1;
    }

    int idx = -1;

    if(path_to_entry_index(kpath, &idx) != 0)
    {
        printf("[FILE OPEN] File not found '%s'\n", kpath);

        return -1;
    }

    FileEntry *fe = &file_table->entries[idx];

    if(fe->type != ENTRY_TYPE_FILE)
    {
        return -1;
    }

    uint32_t size = fe->file_size_bytes;
    uint8_t *buf = kmalloc(size ? size : 1);

    if(!buf)
    {
        return -1;
    }

    int read = read_file(file_table, kpath, buf);

    if(read < 0)
    {
        kfree(buf);

        return -1;
    }

    for(int i = 0; i < KERNEL_FILE_DESCRIPTOR_MAX; i++)
    {
        if(!s_file_descriptor[i].used)
        {
            s_file_descriptor[i].used = 1;
            s_file_descriptor[i].data = buf;
            s_file_descriptor[i].size = (uint32_t)read;
            s_file_descriptor[i].pos = 0;
            s_file_descriptor[i].flags = oflags;
            s_file_descriptor[i].ft_index = idx;

            if(oflags & O_TRUNC)
            {
                if(verify_sector_bitmap() != 0)
                {
                }

                if(fe->sector_count)
                {
                    free_sectors(fe->start_sector, fe->sector_count);
                    fe->start_sector = 0;
                    fe->sector_count = 0;
                }

                fe->file_size_bytes = 0;
                s_file_descriptor[i].size = 0;
                s_file_descriptor[i].pos = 0;

                flush_metadata();
            }

            return KERNEL_FILE_DESCRIPTOR_BASE + i;
        }
    }

    kfree(buf);

    return -1;
}

// Close an open file
int system_file_close(int file_descriptor)
{
    if(file_descriptor < KERNEL_FILE_DESCRIPTOR_BASE)
    {
        return 0;
    }

    int i = file_descriptor - KERNEL_FILE_DESCRIPTOR_BASE;

    if(i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || !s_file_descriptor[i].used)
    {
        return -1;
    }

    kfree(s_file_descriptor[i].data);
    memset(&s_file_descriptor[i], 0, sizeof(s_file_descriptor[i]));

    return 0;
}

// Read from a file or stdin
long system_file_read(int file, void *buf, unsigned long count)
{
    if(file == 0)
    {
        // stdin
        uint8_t first = keyboard_getch();

        if(copy_to_user(buf, &first, 1) != 0)
        {
            return -1;
        }

        unsigned long n = 1;

        while(n < count)
        {
            uint8_t c;

            if(!keyboard_trygetch(&c))
            {
                break;
            }

            if(copy_to_user((uint8_t*)buf + n, &c, 1) != 0)
            {
                break;
            }

            n++;
        }

        return (long)n;
    }

    if(file == 1 || file == 2)
    {
        // stdout/stderr not readable
        return -1;
    }

    int i = file - KERNEL_FILE_DESCRIPTOR_BASE;

    if(i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || !s_file_descriptor[i].used)
    {
        return -1;
    }

    file_descriptor_t *kf = &s_file_descriptor[i];
    uint32_t left = (kf->pos < kf->size) ? (kf->size - kf->pos) : 0;
    uint32_t take = (count < left) ? (uint32_t)count : left;

    if(take)
    {
        if(copy_to_user(buf, kf->data + kf->pos, take) != 0)
        {
            return -1;
        }

        kf->pos += take;
    }

    return (long)take;
}

// Change file position
long system_file_seek(int file, long offset, int whence)
{
    if(file < KERNEL_FILE_DESCRIPTOR_BASE)
    {
        if(whence == SEEK_CUR && offset == 0)
        {
            return 0;
        }

        return -1;
    }

    int i = file - KERNEL_FILE_DESCRIPTOR_BASE;

    if(i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || !s_file_descriptor[i].used)
    {
        return -1;
    }

    file_descriptor_t *kf = &s_file_descriptor[i];
    uint32_t base = 0;

    switch(whence)
    {
        case SEEK_SET:
        {
            base = 0;

            break;
        }

        case SEEK_CUR:
        {
            base = kf->pos;

            break;
        }

        case SEEK_END:
        {
            base = kf->size;

            break;
        }

        default:
        {
            return -1;
        }
    }

    long np = (long)base + offset;

    if(np < 0)
    {
        np = 0;
    }

    if((uint32_t)np > kf->size)
    {
        np = (long)kf->size;
    }

    kf->pos = (uint32_t)np;

    return (long)kf->pos;
}

// Write buffer to disk for a file
static int system_write_file_to_disk(FileEntry *fe, const uint8_t *data, uint32_t new_size)
{
    uint32_t new_sectors = (new_size + 511) / 512;

    if(new_sectors == 0)
    {
        if(verify_sector_bitmap() != 0)
        {
            return -1;
        }

        if(fe->sector_count)
        {
            free_sectors(fe->start_sector, fe->sector_count);
            fe->start_sector = 0;
            fe->sector_count = 0;
        }

        fe->file_size_bytes = 0;

        return flush_metadata();
    }

    if(verify_sector_bitmap() != 0)
    {
        return -1;
    }

    uint32_t new_first = 0;

    if(allocate_sectors(new_sectors, &new_first, &superblock) != 0)
    {
        if(fe->sector_count)
        {
            free_sectors(fe->start_sector, fe->sector_count);
        }

        if(allocate_sectors(new_sectors, &new_first, &superblock) != 0)
        {
            return -1;
        }
    }

    uint8_t sector_buf[SECTOR_SIZE];
    uint32_t written = 0;

    for(uint32_t s = 0; s < new_sectors; s++)
    {
        uint32_t to_copy = (new_size - written > SECTOR_SIZE) ? SECTOR_SIZE : (new_size - written);

        if(to_copy)
        {
            memcpy(sector_buf, data + written, to_copy);
        }

        if(to_copy < SECTOR_SIZE)
        {
            memset(sector_buf + to_copy, 0, SECTOR_SIZE - to_copy);
        }

        int w = disk_write(new_first + s, 1, sector_buf);

        if(w <= 0)
        {
            return -1;
        }

        written += to_copy;
    }

    fe->start_sector = new_first;
    fe->sector_count = new_sectors;
    fe->file_size_bytes = new_size;

    return flush_metadata();
}

// Write to file or stdout/stderr
long system_file_write(int file, const void *buf, unsigned long count)
{
    if(file == 1 || file == 2)
    {
        // stdout/stderr
        for(unsigned long i = 0; i < count; i++)
        {
            char c;

            if(copy_from_user(&c, (const uint8_t*)buf + i, 1) != 0)
            {
                return (long)i;
            }

            putch(c);
        }

        return (long)count;
    }

    if(file == 0)
    {
        // stdin not writable
        return -1;
    }

    int i = file - KERNEL_FILE_DESCRIPTOR_BASE;

    if(i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || !s_file_descriptor[i].used)
    {
        return -1;
    }

    if(!file_writable(s_file_descriptor[i].flags))
    {
        return -1;
    }

    file_descriptor_t *kf = &s_file_descriptor[i];
    FileEntry *fe = &file_table->entries[kf->ft_index];

    if(kf->flags & O_APPEND)
    {
        kf->pos = kf->size;
    }

    uint32_t end_pos = kf->pos + (uint32_t)count;
    uint32_t new_size = (end_pos > kf->size) ? end_pos : kf->size;

    if(new_size > kf->size)
    {
        uint8_t *nbuf = kmalloc(new_size);

        if(!nbuf)
        {
            return -1;
        }

        if(kf->size)
        {
            memcpy(nbuf, kf->data, kf->size);
        }

        kfree(kf->data);
        kf->data = nbuf;
        kf->size = new_size;
    }

    if(copy_from_user(kf->data + kf->pos, buf, count) != 0)
    {
        return -1;
    }

    kf->pos += (uint32_t)count;

    if(system_write_file_to_disk(fe, kf->data, kf->size) != 0)
    {
        return -1;
    }

    return (long)count;
}

