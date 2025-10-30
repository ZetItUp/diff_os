#include "interfaces.h"
#include "string.h"
#include "stdint.h"
#include "idt.h"
#include "system/syscall.h"
#include "system/usercopy.h"
#include "system/scheduler.h"
#include "system/threads.h"
#include "system/process.h"
#include "console.h"
#include "stdio.h"
#include "paging.h"
#include "heap.h"
#include "dex/dex.h"
#include "diff.h"
#include "timer.h"

struct dirent;

extern void system_call_stub(void);

static struct syscall_frame s_parent_stack[MAX_EXEC_NEST];
static int s_parent_sp = 0;
static uint8_t s_exit_kstack[4096];

// Jumps to a simple halt loop when no parent exists
static void user_exit_trampoline(void) __attribute__((noreturn));
static void user_exit_trampoline(void)
{
    puts("[SYSTEM] Halted!\n");

    for (;;)
    {
        asm volatile("hlt");
    }
}

// Try common locations and build an absolute path
int resolve_exec_path(char *out, size_t out_sz, const char *name)
{
    if (!name || !name[0])
    {
        return -1;
    }

    if (name[0] == '/')
    {
        if (find_entry_by_path(file_table, name) >= 0)
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

    for (int i = 0; i < (int)(sizeof(patterns) / sizeof(patterns[0])); i++)
    {
        snprintf(candidate, sizeof(candidate), patterns[i], name, name);

        if (find_entry_by_path(file_table, candidate) >= 0)
        {
            snprintf(out, out_sz, "%s", candidate);

            return 0;
        }
    }

    return -1;
}

// Try to interpret a user value as a pointer to a NUL-terminated string.
static int try_user_cstr_len(uint32_t uptr)
{
    if (uptr < 0x10000u)
    {

        return -1;
    }

    const char *p = (const char*)(uintptr_t)uptr;

    size_t n = strnlen_user(p, 4096);

    if (n == 0 || n > 4096)
    {

        return -1;
    }

    return (int)n;
}

// Set console colors from user values
static int system_console_set_color(uint32_t fg, uint32_t bg)
{
    return console_set_colors_kernel((uint8_t)fg, (uint8_t)bg);
}

// Read current console colors
static int system_console_get_color(uint32_t *out)
{
    uint8_t fg = 7;
    uint8_t bg = 0;

    if (!out)
    {
        return -1;
    }

    console_get_colors_kernel(&fg, &bg);
    uint32_t val = (uint32_t)fg | ((uint32_t)bg << 8);

    if(copy_to_user(out, &val, sizeof(val)) != 0)
    {
        return -1;
    }

    return 0;
}

// Print one character to the console
static int system_putchar(int ch)
{
    putch((char)ch & 0xFF);

    return 0;
}

// Print a user string safely by copying it to kernel first
static int system_print(const char *u_str)
{
    if (!u_str)
    {
        return 0;
    }

    const size_t MAX = 4096;

    // Bounded length from user, page-safe
    size_t n = strnlen_user(u_str, MAX);
    if (n == 0)
    {
        return 0;
    }
    if (n > MAX)
    {
        n = MAX;
    }

    char *kbuf = (char*)kmalloc(n + 1);
    if (!kbuf)
    {
        return -1;
    }

    // Copy from user; abort on any fault
    if (copy_from_user(kbuf, u_str, n) != 0)
    {
        kfree(kbuf);
        return -1;
    }

    kbuf[n] = '\0';

    // Print exactly what we copied
    printf("%s", kbuf);

    kfree(kbuf);

    return (int)n;
}

// Save parent frame and run a DEX image
static int system_exec_dex(
    struct syscall_frame *f,
    const char *path,
    int argc,
    char **argv
)
{
    if (!path)
    {
        return -1;
    }

    if (s_parent_sp >= MAX_EXEC_NEST)
    {
        return -1;
    }

    if (argc < 0)
    {
        argc = 0;
    }

    if (argc > 64)
    {
        argc = 64;
    }

    s_parent_stack[s_parent_sp++] = *f;

    dex_run(file_table, path, argc, argv);

    return 0;
}

// System exit call
static int system_exit(struct syscall_frame *f, int code)
{
    process_t *p = process_current();

    if (p && p->pid != 0)
    {
#ifdef DIFF_DEBUG
        printf("[SYSCALL] EXIT pid=%d code=%d\n", p->pid, code);
#endif
        process_exit_current(code);

        thread_yield();

        for (;;)
        {
            asm volatile("hlt");
        }
    }

    if (s_parent_sp > 0)
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

/* -----------------------------------------------------------
 * System call dispatcher
 *  ABI: syscall_frame (pushad: EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI)
 *       register-ABI primärt (EAX=nr, EBX/ECX/EDX/ESI=args)
 *       fallback till stack-ABI [num,a0,a1,a2,a3] på USERESP
 * ----------------------------------------------------------- */
int system_call_dispatch(struct syscall_frame *f)
{
    asm volatile("cld");

    /* register-ABI (primärt) */
    uint32_t num  = (uint32_t)f->eax;
    uint32_t arg0 = (uint32_t)f->ebx;
    uint32_t arg1 = (uint32_t)f->ecx;
    uint32_t arg2 = (uint32_t)f->edx;
    uint32_t arg3 = (uint32_t)f->esi;
    (void)arg3;

    /* Om EAX inte är i enum-spannet, prova stack-ABI: [num, a0, a1, a2, a3] på useresp */
    enum { SYS_MIN = SYSTEM_EXIT, SYS_MAX = SYSTEM_VIDEO_GET_GRAPHICS_MODE };
    if (num < SYS_MIN || num > SYS_MAX)
    {
        uint32_t n2 = 0;
        if (copy_from_user(&n2, (const void*)f->useresp, 4) == 0 &&
            (n2 >= SYS_MIN && n2 <= SYS_MAX))
        {
            uint32_t s0=0,s1=0,s2=0,s3=0;
            (void)copy_from_user(&s0, (const void*)(f->useresp +  4), 4);
            (void)copy_from_user(&s1, (const void*)(f->useresp +  8), 4);
            (void)copy_from_user(&s2, (const void*)(f->useresp + 12), 4);
            (void)copy_from_user(&s3, (const void*)(f->useresp + 16), 4);
            num  = n2; arg0 = s0; arg1 = s1; arg2 = s2; arg3 = s3;
#ifdef DIFF_DEBUG
            puts("[SYSCALL][compat] using stack ABI\n");
#endif
        }
    }

    int ret = -1;
    int regs_set = 0;

    switch ((int)num)
    {
        case SYSTEM_EXIT:
        {
            ret = system_exit(f, (int)arg0);

            break;
        }
        case SYSTEM_PUTCHAR:
        {
            int n = try_user_cstr_len((uint32_t)arg0);

            if (n >= 0)
            {
#ifdef DIFF_DEBUG
        puts("[SYSCALL][compat] PUTCHAR->PRINT\n");
#endif
                ret = system_print((const char*)(uintptr_t)arg0);
            }
            else
            {
                ret = system_putchar((int)arg0);
            }

            break;
        }
        case SYSTEM_PRINT:
        {
            const char *u = (const char*)(uintptr_t)arg0;

            int n = try_user_cstr_len((uint32_t)arg0);

            if (n < 0)
            {
                // Compatibility: some callers may pass the pointer in ECX
                int n2 = try_user_cstr_len((uint32_t)arg1);

                if (n2 >= 0)
                {
#ifdef DIFF_DEBUG
    puts("[SYSCALL][compat] PRINT from ECX\n");
#endif
                    u = (const char*)(uintptr_t)arg1;
                }
                else
                {
                    ret = 0;

                    break;
                }
            }

            ret = system_print(u);


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
            /* använd arg0 enligt ABI, inte f->ebx direkt */
            int x = (arg0 >> 16) & 0xFFFF;
            int y =  arg0        & 0xFFFF;

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
            ret = system_file_open((const char*)(uintptr_t)arg0, (int)arg1, (int)arg2);

            break;
        }
        case SYSTEM_FILE_CLOSE:
        {
            ret = system_file_close((int)arg0);

            break;
        }
        case SYSTEM_FILE_SEEK:
        {
            ret = (int)system_file_seek((int)arg0, (long)arg1, (int)arg2);

            break;
        }
        case SYSTEM_FILE_READ:
        {
            ret = (int)system_file_read((int)arg0, (void*)(uintptr_t)arg1, (unsigned long)(uint32_t)arg2);

            break;
        }
        case SYSTEM_FILE_WRITE:
        {
            ret = (int)system_file_write((int)arg0, (const void*)(uintptr_t)arg1, (unsigned long)(uint32_t)arg2);

            break;
        }
        case SYSTEM_EXEC_DEX:
        {
            const char *upath = (const char*)(uintptr_t)arg0;
            int argc = (int)arg1;
            char **uargv = (char**)(uintptr_t)arg2;
            ret = 0;

            char kname[256];

            if (copy_string_from_user(kname, upath, sizeof(kname)) < 0)
            {
                ret = -1;

                break;
            }

            if (argc < 0)
            {
                argc = 0;
            }

            if (argc > 64)
            {
                argc = 64;
            }

            char **kargv = NULL;
            char *argbuf = NULL;
            size_t buf_size = (size_t)argc * (size_t)MAX_ARG_LEN;

            if (argc > 0)
            {
                kargv = (char**)kmalloc(sizeof(char*) * (size_t)argc);
                argbuf = (char*)kmalloc(buf_size);

                if (!kargv || !argbuf)
                {
                    if (kargv)
                    {
                        kfree(kargv);
                    }

                    if (argbuf)
                    {
                        kfree(argbuf);
                    }

                    ret = -1;

                    break;
                }
            }

            // Pull argv pointers from user then copy strings
            for (int i = 0; i < argc; i++)
            {
                const char *uargp;
                const void *user_ptr_slot = (const void*)((uintptr_t)uargv + (size_t)i * sizeof(char*));

                if (copy_from_user(&uargp, user_ptr_slot, sizeof(uargp)) != 0)
                {
                    ret = -1;

                    break;
                }

                char *dst = argbuf + (size_t)i * (size_t)MAX_ARG_LEN;

                if (copy_string_from_user(dst, uargp, (size_t)MAX_ARG_LEN) < 0)
                {
                    ret = -1;

                    break;
                }

                kargv[i] = dst;
            }

            if (ret == -1)
            {
                if (kargv)
                {
                    kfree(kargv);
                }

                if (argbuf)
                {
                    kfree(argbuf);
                }

                break;
            }

            char kpath[256];

            if (resolve_exec_path(kpath, sizeof(kpath), kname) != 0)
            {
                ret = -1;

                break;
            }

            ret = system_exec_dex(f, kpath, argc, kargv);

            if (kargv)
            {
                kfree(kargv);
            }

            if (argbuf)
            {
                kfree(argbuf);
            }

            break;
        }
        case SYSTEM_DIR_OPEN:
        {
            ret = system_open_dir((const char*)(uintptr_t)arg0);

            break;
        }
        case SYSTEM_DIR_READ:
        {
            ret = system_read_dir((int)arg0, (struct dirent*)(uintptr_t)arg1);

            break;
        }
        case SYSTEM_DIR_CLOSE:
        {
            ret = system_close_dir((int)arg0);

            break;
        }
        case SYSTEM_CONSOLE_SET_COLOR:
        {
            ret = system_console_set_color(arg0, arg1);

            break;
        }
        case SYSTEM_CONSOLE_GET_COLOR:
        {
            ret = system_console_get_color((uint32_t*)(uintptr_t)arg0);

            break;
        }
        case SYSTEM_THREAD_YIELD:
        {
            thread_yield();

            ret = 0;

            break;
        }
        case SYSTEM_THREAD_SLEEP_MS:
        {
            uint32_t ms = (uint32_t)arg0;

            sleep_ms(ms);

            ret = 0;

            break;
        }
        case SYSTEM_TIME_MS:
        {
            uint64_t now = timer_now_ms();

            f->eax = (uint32_t)(now & 0xFFFFFFFF);
            f->edx = (uint32_t)(now >> 32);

            regs_set = 1;
            ret = 0;

            break;
        }
        case SYSTEM_THREAD_GET_ID:
        {
            thread_t *t = current_thread();

            ret = t ? t->thread_id : -1;

            break;
        }
        case SYSTEM_PROCESS_SPAWN:
        {
            ret = system_process_spawn((const char*)(uintptr_t)arg0, (int)arg1, (char**)(uintptr_t)arg2);

            break;
        }
        case SYSTEM_WAIT_PID:
        {
            int pid = (int)arg0;
            int *u_status = (int*)(uintptr_t)arg1;

            ret = system_wait_pid(pid, u_status);

            break;
        } 
        case SYSTEM_FILE_STAT:
        {
            ret = system_file_stat((const char*)(uintptr_t)arg0, (filesystem_stat_t*)(uintptr_t)arg1);

            break;
        }
        case SYSTEM_FILE_FSTAT:
        {
            ret = system_file_fstat((int)arg0, (filesystem_stat_t*)(uintptr_t)arg1);

            break;
        }
        case SYSTEM_VIDEO_PRESENT:
        {
            // arg0 = user ptr, arg1 = pitch bytes, arg2 = (w << 16) | h
            ret = system_video_present_user((const void*)(uintptr_t)arg0, (int)arg1, (int)arg2);

            break;
        }
        case SYSTEM_VIDEO_MODE_SET:
        {
            ret = system_video_mode_set((uint32_t)arg0, (uint32_t)arg1, (uint32_t)arg2);

            break;
        }
        case SYSTEM_BREAK:
        {
            ret = system_brk_set((void*)(uintptr_t)arg0);

            break;
        }
        case SYSTEM_VIDEO_TOGGLE_GRAPHICS_MODE:
        {
            ret = console_toggle_graphics_mode();
            
            break;
        }
        case SYSTEM_VIDEO_GET_GRAPHICS_MODE:
        {
            ret = console_get_graphics_mode();

            break;
        }
        default:
        {
            puts("[System Call] Unknown number: ");
            puthex(num);
            puts("  eax="); puthex(f->eax);
            puts(" ebx="); puthex(f->ebx);
            puts(" ecx="); puthex(f->ecx);
            puts(" edx="); puthex(f->edx);
            puts(" useresp="); puthex(f->useresp);
            puts("\n");

            ret = -1;

            break;
        }
    }

    // Write return values unless already set in the frame
    if (!regs_set)
    {
        f->eax = (uint32_t)ret;
        f->edx = 0;
    }

    return ret;
}

// Install the syscall gate in the IDT
void system_call_init(void)
{
    idt_set_entry(0x66, (uint32_t)system_call_stub, 0x08, 0xEE);
}

