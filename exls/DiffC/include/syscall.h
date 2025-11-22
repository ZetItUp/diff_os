#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <dirent.h>
#include <system/stat.h>
#include <video.h>

#define SYSCALL_VECTOR      0x66        // Different OS Specific
                                        
enum
{
    SYSTEM_EXIT = 0,
    SYSTEM_PUTCHAR = 1,
    SYSTEM_PRINT = 2,
    SYSTEM_GETCH = 3,
    SYSTEM_TRYGETCH = 4,
    SYSTEM_CONSOLE_GETXY = 5,
    SYSTEM_CONSOLE_FLOOR_SET = 6,
    SYSTEM_CONSOLE_FLOOR_CLEAR = 7,
    SYSTEM_FILE_OPEN = 8,
    SYSTEM_FILE_CLOSE = 9,
    SYSTEM_FILE_SEEK = 10,
    SYSTEM_FILE_READ = 11,
    SYSTEM_FILE_WRITE = 12,
    SYSTEM_EXEC_DEX = 13,
    SYSTEM_DIR_OPEN = 14,
    SYSTEM_DIR_READ = 15,
    SYSTEM_DIR_CLOSE = 16,
    SYSTEM_CONSOLE_SET_COLOR = 17,
    SYSTEM_CONSOLE_GET_COLOR = 18,
    SYSTEM_THREAD_YIELD = 19,
    SYSTEM_THREAD_SLEEP_MS = 20,
    SYSTEM_TIME_MS = 21,
    SYSTEM_THREAD_GET_ID = 22,
    SYSTEM_PROCESS_SPAWN = 23,
    SYSTEM_WAIT_PID = 24,
    SYSTEM_FILE_STAT = 25,
    SYSTEM_FILE_FSTAT = 26,
    SYSTEM_VIDEO_PRESENT = 27,
    SYSTEM_VIDEO_MODE_SET = 28,
    SYSTEM_BREAK = 29,
    SYSTEM_VIDEO_TOGGLE_GRAPHICS_MODE = 30,
    SYSTEM_VIDEO_GET_GRAPHICS_MODE = 31,
    SYSTEM_CHDIR = 32,
    SYSTEM_GETCWD = 33,
    SYSTEM_GETEXECROOT = 34,
    SYSTEM_KEYBOARD_EVENT_GET = 35,
    SYSTEM_KEYBOARD_EVENT_TRY = 36,
    SYSTEM_FILE_DELETE = 37,
    SYSTEM_FILE_RENAME = 38,
    SYSTEM_DIR_CREATE = 39,
    SYSTEM_DIR_REMOVE = 40,
    SYSTEM_VIDEO_MODE_GET = 41,
};

static inline __attribute__((always_inline)) uint64_t do_sys64_0(int n)
{
    uint32_t lo, hi;
    asm volatile(
        "push %%ebx\n\t"
        "push %%esi\n\t"
        "push %%edi\n\t"
        "mov  %2, %%eax\n\t"   // eax = syscall#
        "int  $0x66\n\t"       // returns with edx:eax
        "pop  %%edi\n\t"
        "pop  %%esi\n\t"
        "pop  %%ebx\n\t"
        : "=a"(lo), "=d"(hi)
        : "r"(n)
        : "ecx", "memory", "cc");
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

static inline __attribute__((always_inline)) int do_sys(int n, int a0, int a1, int a2, int a3)
{
    register int r_eax asm("eax") = n;
    register int r_ebx asm("ebx") = a0;
    register int r_ecx asm("ecx") = a1;
    register int r_edx asm("edx") = a2;
    register int r_esi asm("esi") = a3;
    register int r_edi asm("edi");

    asm volatile(
        "push %%ebx\n\t"
        "push %%esi\n\t"
        "push %%edi\n\t"
        "int $0x66\n\t"
        "pop %%edi\n\t"
        "pop %%esi\n\t"
        "pop %%ebx\n\t"
        : "+a"(r_eax), "+b"(r_ebx), "+c"(r_ecx), "+d"(r_edx), "+S"(r_esi), "+D"(r_edi)
        :
        : "memory", "cc"
    );

    return r_eax;
}


static inline __attribute__((always_inline)) void system_exit(int code) 
{
    (void)do_sys(SYSTEM_EXIT, code, 0, 0, 0);
}

static inline __attribute__((always_inline)) void system_putchar(char c) 
{
    (void)do_sys(SYSTEM_PUTCHAR, (unsigned char)c, 0, 0, 0);
}

static inline __attribute__((always_inline)) int system_print(const char *str) 
{
    return do_sys(SYSTEM_PRINT, (int)(uintptr_t)str, 0, 0, 0);
}

static inline __attribute__((always_inline)) uint8_t system_getch(void)
{
    return (uint8_t)(do_sys(SYSTEM_GETCH, 0, 0, 0, 0) & 0xFF);    
}

static inline __attribute__((always_inline)) int system_trygetch(uint8_t *out)
{
    int r = do_sys(SYSTEM_TRYGETCH, 0, 0, 0, 0);

    if(r < 0)
    {
        return 0;
    }

    if(out)
    {
        *out = (uint8_t)(r & 0xFF);
    }

    return 1;
}

typedef struct system_key_event
{
    uint8_t pressed;
    uint8_t key;
} system_key_event_t;

static inline __attribute__((always_inline)) system_key_event_t system_keyboard_event_get(void)
{
    int r = do_sys(SYSTEM_KEYBOARD_EVENT_GET, 0, 0, 0, 0);

    system_key_event_t ev;
    ev.pressed = (uint8_t)((r >> 8) & 0xFF);
    ev.key = (uint8_t)(r & 0xFF);

    return ev;
}

static inline __attribute__((always_inline)) int system_keyboard_event_try(system_key_event_t *out)
{
    int r = do_sys(SYSTEM_KEYBOARD_EVENT_TRY, 0, 0, 0, 0);

    if (r < 0)
    {
        return 0;
    }

    if (out)
    {
        out->pressed = (uint8_t)((r >> 8) & 0xFF);
        out->key = (uint8_t)(r & 0xFF);
    }

    return 1;
}

static inline __attribute__((always_inline)) int console_getxy(int *x,int *y)
{
    int r = do_sys(SYSTEM_CONSOLE_GETXY, 0, 0, 0, 0); 
    
    if(x)
    {
        *x = (r >> 16) & 0xFFFF;
    } 
    
    if(y)
    {
        *y = r & 0xFFFF; 
    }

    return 0;
}

static inline __attribute__((always_inline)) int console_floor_set(int x,int y)
{
    int packed = ((x & 0xFFFF) << 16) | (y & 0xFFFF);
    
    return do_sys(SYSTEM_CONSOLE_FLOOR_SET, packed, 0, 0, 0); 
}

static inline __attribute__((always_inline)) int console_floor_clear(void)
{
    return do_sys(SYSTEM_CONSOLE_FLOOR_CLEAR, 0, 0, 0, 0); 
}

static inline int system_open (const char *path, int oflags, int mode)
{
    return do_sys(SYSTEM_FILE_OPEN, (int)(uintptr_t)path, oflags, mode, 0);
}

static inline int system_close(int file_descriptor)
{
    return do_sys(SYSTEM_FILE_CLOSE, file_descriptor, 0, 0, 0);
}

static inline long system_lseek(int file_descriptor, long off, int whence)
{
    return (long)do_sys(SYSTEM_FILE_SEEK, file_descriptor, (int)off, whence, 0);
}

static inline long system_read (int file_descriptor, void *buf, unsigned long count)
{

    return (long)do_sys(SYSTEM_FILE_READ, file_descriptor, (int)(uintptr_t)buf, (int)count, 0);
}

static inline long system_write(int file_descriptor, const void *buf, unsigned long count)
{
    return (long)do_sys(SYSTEM_FILE_WRITE, file_descriptor, (int)(uintptr_t)buf, (int)count, 0);
}

static inline int system_exec_dex(const char *path, int argc, char **argv)
{
    return do_sys(SYSTEM_EXEC_DEX, (int)(uintptr_t)path, argc, (int)(uintptr_t)argv, 0);
}

static inline int system_open_dir(const char *path)
{
    return do_sys(SYSTEM_DIR_OPEN, (int)(uintptr_t)path, 0, 0, 0);
}

static inline int system_read_dir(int handle, struct dirent *entry)
{
    return do_sys(SYSTEM_DIR_READ, handle, (int)(uintptr_t)entry, 0, 0);
}

static inline int system_close_dir(int handle)
{
    return do_sys(SYSTEM_DIR_CLOSE, handle, 0, 0, 0);
}

static inline int system_mkdir(const char *path)
{
    return do_sys(SYSTEM_DIR_CREATE, (int)(uintptr_t)path, 0, 0, 0);
}

static inline int system_rmdir(const char *path)
{
    return do_sys(SYSTEM_DIR_REMOVE, (int)(uintptr_t)path, 0, 0, 0);
}

static inline int system_console_set_color(uint32_t fg, uint32_t bg)
{
    return do_sys(SYSTEM_CONSOLE_SET_COLOR, fg, bg, 0, 0);
}

static inline int system_console_get_color(uint32_t *out)
{
    return do_sys(SYSTEM_CONSOLE_GET_COLOR, (int)(uintptr_t)out, 0, 0, 0);
}

static inline __attribute__((always_inline)) void system_thread_yield(void)
{
    (void)do_sys(SYSTEM_THREAD_YIELD, 0, 0, 0, 0);
}

static inline __attribute__((always_inline)) void system_thread_sleep_ms(uint32_t ms)
{
    (void)do_sys(SYSTEM_THREAD_SLEEP_MS, (int)ms, 0, 0, 0);
}

static inline __attribute__((always_inline)) uint64_t system_time_ms(void)
{
    return do_sys64_0(SYSTEM_TIME_MS);
}

static inline __attribute__((always_inline)) int system_thread_get_id(void)
{
    return do_sys(SYSTEM_THREAD_GET_ID, 0, 0, 0, 0);
}

static inline int system_process_spawn(const char *path, int argc, char **argv)
{
    return do_sys(SYSTEM_PROCESS_SPAWN, (int)(uintptr_t)path, argc, (int)(uintptr_t)argv, 0);
}

static inline int system_wait_pid(int pid, int *status)
{
    return do_sys(SYSTEM_WAIT_PID, pid, (int)status, 0, 0);
}

static inline int system_file_stat(const char *path, fs_stat_t *fs_stat)
{
    return do_sys(SYSTEM_FILE_STAT, (int)path, (int)fs_stat, 0, 0);
} 

static inline int system_file_fstat(int fd, fs_stat_t *fs_stat)
{
    return do_sys(SYSTEM_FILE_FSTAT, fd, (int)fs_stat, 0, 0);
}

static inline int system_video_present(const void *argb32, int pitch_bytes, int w, int h)
{
    int packed = ((w & 0xFFFF) << 16) | (h & 0xFFFF);

    return do_sys(SYSTEM_VIDEO_PRESENT, (int)(uintptr_t)argb32, pitch_bytes, packed, 0);
}

static inline int system_video_mode_set(int w, int h, int bpp)
{
    return do_sys(SYSTEM_VIDEO_MODE_SET, (w << 16) | (h & 0xFFFF), bpp, 0, 0);
}

static inline void* system_brk(void *new_end)
{
    return (void*)(uintptr_t)do_sys(SYSTEM_BREAK, (int)(uintptr_t)new_end, 0, 0, 0);
}

static inline int system_chdir(const char *path)
{
    return do_sys(SYSTEM_CHDIR, (int)(uintptr_t)path, 0, 0, 0);
}

static inline int system_getcwd(char *buf, size_t len)
{
    return do_sys(SYSTEM_GETCWD, (int)(uintptr_t)buf, (int)len, 0, 0);
}

static inline int system_getexecroot(char *buf, size_t len)
{
    return do_sys(SYSTEM_GETEXECROOT, (int)(uintptr_t)buf, (int)len, 0, 0);
}

static inline int system_video_toggle_graphics_mode(void)
{
    return do_sys(SYSTEM_VIDEO_TOGGLE_GRAPHICS_MODE, 0, 0, 0, 0);
}

static inline int system_video_get_graphics_mode(void)
{
    return do_sys(SYSTEM_VIDEO_GET_GRAPHICS_MODE, 0, 0, 0, 0);
}

static inline int system_video_mode_get(video_mode_info_t *video_out)
{
    return do_sys(SYSTEM_VIDEO_MODE_GET, (int)video_out, 0, 0, 0);
}
