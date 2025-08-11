#include "drivers/ata.h"
#include "stdint.h"
#include "console.h"
#include "idt.h"
#include "system/syscall.h"
#include "stdio.h"
#include "interfaces.h"
#include "diff.h"
#include "string.h"
#include "heap.h"

#define KERNEL_FILE_DESCRIPTOR_BASE         3       // 0 = stdin, 1 = stdout, 2 = stderr
#define KERNEL_FILE_DESCRIPTOR_MAX          32

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

typedef struct
{
    uint8_t used;
    uint8_t *data;          // File in RAM
    uint32_t size;          // Size in data
    uint32_t pos;           // Offset
    int flags;
    int ft_index;           // File table index
} file_descriptor_t;

extern void system_call_stub(void);

static uint8_t s_exit_kstack[4096];

static file_descriptor_t s_file_descriptor[KERNEL_FILE_DESCRIPTOR_MAX];
static int s_sector_bitmap_loaded = 0;

static void user_exit_trampoline(void) __attribute__((noreturn));
static void user_exit_trampoline(void)
{
    puts("[SYSTEM] Program exited successfully!\n");
    // TODO: här kan du städa upp: unmapa user image, fria RAM, visa prompt, starta nästa program, etc.
    for (;;)
        asm volatile("hlt");
}

static int system_putchar(int ch)
{
    putch((char)ch & 0xFF);

    return 0;
}

static int system_print(const char *s)
{
    if(s)
    {
        puts(s);
    }

    return 0;
}

/*static int file_readable(int flags)
{
    return (flags & O_WRONLY) ? 0 : 1;
}*/

static int file_writable(int flags)
{
    return (flags & (O_WRONLY | O_RDWR)) ? 1 : 0;
}

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

static int system_open_file(const char *abs_path, int oflags, int mode)
{
    (void)mode;

    if(verify_fs_ready() != 0)
    {
        return -1;
    }

    int idx = find_entry_by_path(file_table, abs_path);
    if(idx < 0)
    {
        // TODO: Impl O_CREAT
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

    int read = read_file(file_table, abs_path, buf);

    if(read < 0)
    {
        kfree(buf);

        return -1;
    }

    for(int i = 0; i < KERNEL_FILE_DESCRIPTOR_MAX; ++i)
    {
        if(s_file_descriptor[i].used)
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
                    // TODO: Reset ram and meta data, flush failed
                }

                // Free old sectors
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

static int system_close_file(int file_descriptor)
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

static long system_read_file(int file, void *buf, unsigned long count)
{
    if(file == 0)
    {
        // Read atleast 1 character
        uint8_t *p = (uint8_t*)buf;
        unsigned long n = 0;

        p[n++] = keyboard_getch();

        while(n < count)
        {
            uint8_t c;

            if(!keyboard_trygetch(&c))
            {
                break;
            }

            p[n++] = c;
        }

        return (long)n;
    }

    if(file == 1 || file == 2)
    {
        // stdout/stderr: read inte definierat
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
        memcpy(buf, kf->data + kf->pos, take);
        kf->pos += take;
    }

    return (long)take;
}

static long system_lseek_file(int file, long offset, int whence)
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

    if(i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || s_file_descriptor[i].used)
    {
        return -1;
    }

    file_descriptor_t *kf = &s_file_descriptor[i];
    uint32_t base = 0;

    switch(whence)
    {
        // SEEK_SET
        case 0:
            base = 0;
            break;
        // SEEK_CUR
        case 1:
            base = kf->pos;
            break;
        // SEEK_END
        case 2:
            base = kf->size;
            break;
        default:
            return -1;
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

static int system_write_file_to_disk(FileEntry *fe, const uint8_t *data, uint32_t new_size)
{
    uint32_t new_sectors = (new_size + 511) / 512;

    if(new_sectors == 0)
    {
        // Empty file, free up stuff and flush metadata
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
        // If fail, try clear some old sectors and try again
        if(fe->sector_count)
        {
            free_sectors(fe->start_sector, fe->sector_count);
        }

        if(allocate_sectors(new_sectors, &new_first, &superblock) != 0)
        {
            // Failed again, metadata should have been free'd, flee.
            return -1;
        }
    }

    uint8_t sector_buf[SECTOR_SIZE];
    uint32_t written = 0;

    for(uint32_t s = 0; s < new_sectors; ++s)
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

    // Update metadata
    fe->start_sector = new_first;
    fe->sector_count = new_sectors;
    fe->file_size_bytes = new_size;

    return flush_metadata();
}

static long system_write_file(int file, const void *buf, unsigned long count)
{
    if(file == 1 || file == 2)
    {
        // stdout/stderr
        const uint8_t *p = (const uint8_t*)buf;

        for(unsigned long i = 0; i < count; ++i)
        {
            system_putchar((char)p[i]);
        }

        return (long)count;
    }

    if(file == 0)
    {
        // stdin, can't write here!
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

    // Append at the end of the file
    if(kf->flags & O_APPEND)
    {
        kf->pos = kf->size;
    }

    // New file size
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

    memcpy(kf->data + kf->pos, buf, count);
    kf->pos += (uint32_t)count;

    // Write to disk
    if(system_write_file_to_disk(fe, kf->data, kf->size) != 0)
    {
        return -1;
    }

    return (long)count;
}   

static int system_exit(struct syscall_frame *f, int code)
{
    (void)code;
    
    f->eip = (uint32_t)user_exit_trampoline;
    f->cs = KERNEL_CS;
    f->eflags |= 0x200;
    f->useresp = (uint32_t)(s_exit_kstack + sizeof(s_exit_kstack) - 16);
    f->ss = KERNEL_DS;
    f->ds = f->es = f->fs = f->gs = KERNEL_DS;

    return 0;

}


int system_call_dispatch(struct syscall_frame *f)
{
    int num = (int)f->eax;
    int arg0 = (int)f->ebx;
    int arg1 = (int)f->ecx;
    int arg2 = (int)f->edx;
    int arg3 = (int)f->esi;

    int ret = -1;

    // Unused for now
    (void)arg1;
    (void)arg2;
    (void)arg3;

    switch(num)
    {
        case SYSTEM_EXIT:
            ret = system_exit(f, arg0);
            
            break;
        case SYSTEM_PUTCHAR:
            ret = system_putchar(arg0);
            
            break;
        case SYSTEM_PRINT:
            ret = system_print((const char *)arg0);

            break;
        case SYSTEM_GETCH:
            {
                uint8_t ch = keyboard_getch();
                ret = (int)ch;
            }
            break;
        case SYSTEM_TRYGETCH:
            {
                uint8_t ch;
                ret = keyboard_trygetch(&ch) ? (int)ch : -1;
            }   
            break;
        case SYSTEM_CONSOLE_GETXY:
            {
                int x, y;
                get_cursor(&x, &y);

                ret = ((uint32_t)(x & 0xFFFF) << 16) | (uint32_t)(y & 0xFFFF);
                
                break;
            }
        case SYSTEM_CONSOLE_FLOOR_SET:
            {
                int x = (f->ebx >> 16) & 0xFFFF;
                int y = f->ebx & 0xFFFF;

                set_input_floor(x, y);
                ret = 0;
                
                break;
            }
        case SYSTEM_CONSOLE_FLOOR_CLEAR:
            {
                clear_input_floor();
                ret = 0;

                break;
            }
        case SYSTEM_FILE_OPEN:
            {
                ret = system_open_file((const char*)arg0, arg1, arg2);
                break;
            }
        case SYSTEM_FILE_CLOSE:
            {
                ret = system_close_file(arg0);
                break;
            }
        case SYSTEM_FILE_SEEK:
            {
                ret = (int)system_lseek_file(arg0, (long)arg1, arg2);
                break;
            }
        case SYSTEM_FILE_READ:
            {
                ret = (int)system_read_file(arg0, (void*)arg1, (unsigned long)(uint32_t)arg2);
                break;
            }
        case SYSTEM_FILE_WRITE:
            {
                ret = (int)system_write_file(arg0, (const void*)arg1, (unsigned long)(uint32_t)arg2);
                break;
            }
        default:
            puts("[System Call] Unknown number: ");
            puthex(num);
            puts("\n");
            ret = -1;

            break;
    }

    f->eax = (uint32_t)ret; // Return value to userland

    return ret;
}

void system_call_init(void)
{
    idt_set_entry(0x66, (uint32_t)system_call_stub, 0x08, 0xEE);
}
