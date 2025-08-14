#include "interfaces.h"
#include "string.h"
#include "stdint.h"
#include "idt.h"
#include "system/syscall.h"
#include "system/usercopy.h"
#include "console.h"
#include "stdio.h"
#include "paging.h"
#include "heap.h"
#include "dex/dex.h"
#include "diff.h"

#define MAX_EXEC_NEST 8
#define MAX_ARG_LEN   128

struct dirent;

extern void system_call_stub(void);

static struct syscall_frame s_parent_stack[MAX_EXEC_NEST];
static int s_parent_sp = 0;
static uint8_t s_exit_kstack[4096];

static void user_exit_trampoline(void) __attribute__((noreturn));
static void user_exit_trampoline(void)
{
    puts("[SYSTEM] Halted!\n");

    for (;;)
    {
        asm volatile("hlt");
    }
}

static int resolve_exec_path(char *out, size_t out_sz, const char *name)
{
    if(!name || !name[0])
    {
        return -1;
    }

    if(name[0] == '/')
    {
        if(find_entry_by_path(file_table, name) >= 0)
        {
            snprintf(out, out_sz, "%s", name);

            return 0;
        }

        return -1;
    }

    const char *patterns[] =
    {
        "/programs/%s/%s.dex",
        "/programs/%s.dex",
        "/system/%s.dex",
        "/%s.dex"
    };

    char candidate[256];

    for(int i = 0; i < (int)(sizeof(patterns) / sizeof(patterns[0])); i++)
    {
        snprintf(candidate, sizeof(candidate), patterns[i], name, name);

        if(find_entry_by_path(file_table, candidate) >= 0)
        {
            snprintf(out, out_sz, "%s", candidate);

            return 0;
        }
    }

    return -1;
}

static int system_putchar(int ch)
{
    putch((char)ch & 0xFF);

    return 0;
}

static int system_print(const char *s)
{
    if(!s)
    {
        return 0;
    }

    for(int i = 0; i < 4096; ++i)
    {
        if(paging_check_user_range((uint32_t)(s + i), 1) != 0)
        {
            printf("[SYSTEM] bad user ptr at %p\n", s + i);

            return -1;
        }

        char c = s[i];

        if(!c)
        {
            break;
        }

        putch(c);
    }

    return 0;
}

static int system_exec_dex(struct syscall_frame *f, const char *path, int argc, char **argv)
{
    if(!path)
    {
        return -1;
    }

    if(s_parent_sp >= MAX_EXEC_NEST)
    {
        return -1;
    }

    if(argc < 0)
    {
        argc = 0;
    }

    if(argc > 64)
    {
        argc = 64;
    }

    s_parent_stack[s_parent_sp++] = *f;

    dex_run(file_table, path, argc, argv);

    return 0;
}

static int system_exit(struct syscall_frame *f, int code)
{
    (void)code;

    if(s_parent_sp > 0)
    {
        *f = s_parent_stack[--s_parent_sp];

        return 0;
    }

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

    (void)arg3;

    int ret = -1;

    switch(num)
    {
        case SYSTEM_EXIT:
        {
            ret = system_exit(f, arg0);

            break;
        }
        case SYSTEM_PUTCHAR:
        {
            ret = system_putchar(arg0);

            break;
        }
        case SYSTEM_PRINT:
        {
            ret = system_print((const char*)arg0);

            break;
        }
        case SYSTEM_GETCH:
        {
            uint8_t ch = keyboard_getch();
            ret = (int)ch;

            break;
        }
        case SYSTEM_TRYGETCH:
        {
            uint8_t ch;
            ret = keyboard_trygetch(&ch) ? (int)ch : -1;

            break;
        }
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
            ret = system_file_open((const char*)arg0, arg1, arg2);

            break;
        }
        case SYSTEM_FILE_CLOSE:
        {
            ret = system_file_close(arg0);

            break;
        }
        case SYSTEM_FILE_SEEK:
        {
            ret = (int)system_file_seek(arg0, (long)arg1, arg2);

            break;
        }
        case SYSTEM_FILE_READ:
        {
            ret = (int)system_file_read(arg0, (void*)arg1, (unsigned long)(uint32_t)arg2);

            break;
        }
        case SYSTEM_FILE_WRITE:
        {
            ret = (int)system_file_write(arg0, (const void*)arg1, (unsigned long)(uint32_t)arg2);

            break;
        }
        case SYSTEM_EXEC_DEX:
        {
            const char *upath = (const char*)arg0;
            int argc = arg1;
            char **uargv = (char**)arg2;
            ret = 0;
            char kname[256];

            if(copy_string_from_user(kname, upath, sizeof(kname)) != 0)
            {
                ret = -1;

                break;
            }

            if(argc < 0)
            {
                argc = 0;
            }

            if(argc > 64)
            {
                argc = 64;
            }

            char **kargv = NULL;
            char *argbuf = NULL;
            size_t buf_size = (size_t)argc * (size_t)MAX_ARG_LEN;

            if(argc > 0)
            {
                kargv = (char**)kmalloc(sizeof(char*) * (size_t)argc);
                argbuf = (char*)kmalloc(buf_size);

                if(!kargv || !argbuf)
                {
                    if(kargv)
                    {
                        kfree(kargv);
                    }

                    if(argbuf)
                    {
                        kfree(argbuf);
                    }

                    ret = -1;

                    break;
                }
            }

            for(int i = 0; i < argc; i++)
            {
                const char *uargp;
                const void *user_ptr_slot = (const void*)((uintptr_t)uargv + (size_t)i * sizeof(char*));

                if(copy_from_user(&uargp, user_ptr_slot, sizeof(uargp)) != 0)
                {
                    ret = -1;

                    break;
                }

                char *dst = argbuf + (size_t)i * (size_t)MAX_ARG_LEN;

                if(copy_string_from_user(dst, uargp, (size_t)MAX_ARG_LEN) != 0)
                {
                    ret = -1;

                    break;
                }

                kargv[i] = dst;
            }

            if(ret == -1)
            {
                if(kargv)
                {
                    kfree(kargv);
                }

                if(argbuf)
                {
                    kfree(argbuf);
                }

                break;
            }

            char kpath[256];

            if(resolve_exec_path(kpath, sizeof(kpath), kname) != 0)
            {
                ret = -1;

                break;
            }

            ret = system_exec_dex(f, kpath, argc, kargv);

            if(kargv)
            {
                kfree(kargv);
            }

            if(argbuf)
            {
                kfree(argbuf);
            }

            break;
        }
        case SYSTEM_DIR_OPEN:
        {
            ret = system_open_dir((const char*)arg0);

            break;
        }
        case SYSTEM_DIR_READ:
        {
            ret = system_read_dir(arg0, (struct dirent*)arg1);

            break;
        }
        case SYSTEM_DIR_CLOSE:
        {
            ret = system_close_dir(arg0);

            break;
        }
        default:
        {
            puts("[System Call] Unknown number: ");
            puthex(num);
            puts("\n");
            ret = -1;

            break;
        }
    }

    f->eax = (uint32_t)ret;

    return ret;
}

void system_call_init(void)
{
    idt_set_entry(0x66, (uint32_t)system_call_stub, 0x08, 0xEE);
}

