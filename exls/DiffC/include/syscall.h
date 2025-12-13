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
    SYSTEM_MESSAGE_CREATE_CHANNEL = 42,
    SYSTEM_MESSAGE_CONNECT_CHANNEL = 43,
    SYSTEM_MESSAGE_SEND = 44,
    SYSTEM_MESSAGE_RECEIVE = 45,
    SYSTEM_MESSAGE_TRY_RECEIVE = 53,
    SYSTEM_SHARED_MEMORY_CREATE = 46,
    SYSTEM_SHARED_MEMORY_GRANT = 47,
    SYSTEM_SHARED_MEMORY_MAP = 48,
    SYSTEM_SHARED_MEMORY_UNMAP = 49,
    SYSTEM_SHARED_MEMORY_RELEASE = 50,
    SYSTEM_TTY_READ = 51,
    SYSTEM_TTY_WRITE = 52,
    SYSTEM_CONSOLE_DISABLE = 54,
    SYSTEM_WAIT_PID_NOHANG = 55,
    SYSTEM_THREAD_CREATE = 56,
    SYSTEM_THREAD_EXIT   = 57,
    SYSTEM_VIDEO_PRESENT_REGION = 58,
    SYSTEM_MOUSE_EVENT_GET = 59,
    SYSTEM_MOUSE_EVENT_TRY = 60,
    SYSTEM_MESSAGE_RECEIVE_TIMEOUT = 61,
    SYSTEM_MOUSE_GET_POS = 62,
    SYSTEM_MOUSE_SET_POS = 63,
    SYSTEM_MOUSE_SET_BOUNDS = 64,
    SYSTEM_MOUSE_GET_BUTTONS_DOWN = 65,
    SYSTEM_MOUSE_GET_BUTTONS_PRESSED = 66,
    SYSTEM_MOUSE_GET_BUTTONS_CLICKED = 67,
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

// Modifier key flags (matches kernel KB_MOD_*)
#define KB_MOD_SHIFT  0x01
#define KB_MOD_CTRL   0x02
#define KB_MOD_ALT    0x04
#define KB_MOD_CAPS   0x08

typedef struct system_key_event
{
    uint8_t pressed;
    uint8_t key;
    uint8_t modifiers;  // KB_MOD_* flags
} system_key_event_t;

static inline __attribute__((always_inline)) system_key_event_t system_keyboard_event_get(void)
{
    int r = do_sys(SYSTEM_KEYBOARD_EVENT_GET, 0, 0, 0, 0);

    system_key_event_t ev;
    ev.modifiers = (uint8_t)((r >> 16) & 0xFF);
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
        out->modifiers = (uint8_t)((r >> 16) & 0xFF);
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
    // Kernel returns time in EDX:EAX (uint64). In 32-bit userland we only consume
    // the low 32 bits, but still perform the 64-bit syscall and mask the result
    // to avoid stale values if the high dword changes.
    return (uint32_t)do_sys64_0(SYSTEM_TIME_MS);
}

static inline __attribute__((always_inline)) int system_thread_get_id(void)
{
    return do_sys(SYSTEM_THREAD_GET_ID, 0, 0, 0, 0);
}

static inline __attribute__((always_inline)) int system_thread_create(void *entry, void *user_stack_top, size_t kernel_stack_bytes)
{
    return do_sys(SYSTEM_THREAD_CREATE,
                  (int)(uintptr_t)entry,
                  (int)(uintptr_t)user_stack_top,
                  (int)kernel_stack_bytes,
                  0);
}

static inline __attribute__((always_inline)) void system_thread_exit(void)
{
    (void)do_sys(SYSTEM_THREAD_EXIT, 0, 0, 0, 0);
}

static inline int system_process_spawn(const char *path, int argc, char **argv)
{
    return do_sys(SYSTEM_PROCESS_SPAWN, (int)(uintptr_t)path, argc, (int)(uintptr_t)argv, 0);
}

static inline int system_wait_pid(int pid, int *status)
{
    return do_sys(SYSTEM_WAIT_PID, pid, (int)status, 0, 0);
}

static inline int system_wait_pid_nohang(int pid, int *status)
{
    return do_sys(SYSTEM_WAIT_PID_NOHANG, pid, (int)status, 0, 0);
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

// Present a rectangular region (dirty rect optimization)
static inline int system_video_present_region(const void *argb32, int pitch_bytes,
                                               int x, int y, int w, int h)
{
    int packed_xy = ((x & 0xFFFF) << 16) | (y & 0xFFFF);
    int packed_wh = ((w & 0xFFFF) << 16) | (h & 0xFFFF);

    return do_sys(SYSTEM_VIDEO_PRESENT_REGION, (int)(uintptr_t)argb32, pitch_bytes, packed_xy, packed_wh);
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

static inline int system_console_disable(void)
{
    return do_sys(SYSTEM_CONSOLE_DISABLE, 0, 0, 0, 0);
}

static inline int system_video_mode_get(video_mode_info_t *video_out)
{
    return do_sys(SYSTEM_VIDEO_MODE_GET, (int)video_out, 0, 0, 0);
}

static inline int system_message_create_channel(int id)
{
    return do_sys(SYSTEM_MESSAGE_CREATE_CHANNEL, id, 0, 0, 0);
}

static inline int system_message_connect_channel(int id)
{
    return do_sys(SYSTEM_MESSAGE_CONNECT_CHANNEL, id, 0, 0, 0);
}

static inline int system_message_send(int channel_id, const void *buffer, uint32_t len)
{
    return do_sys(SYSTEM_MESSAGE_SEND, channel_id, (int)(uintptr_t)buffer, (int)len, 0); 
}

static inline int system_message_receive(int channel_id, void *buffer, uint32_t buf_len)
{
    return do_sys(SYSTEM_MESSAGE_RECEIVE, channel_id, (int)(uintptr_t)buffer, (int)buf_len, 0); 
}

static inline int system_message_try_receive(int channel_id, void *buffer, uint32_t buf_len)
{
    return do_sys(SYSTEM_MESSAGE_TRY_RECEIVE, channel_id, (int)(uintptr_t)buffer, (int)buf_len, 0);
}

static inline int system_message_receive_timeout(int channel_id, void *buffer, uint32_t buf_len, uint32_t timeout_ms)
{
    return do_sys(SYSTEM_MESSAGE_RECEIVE_TIMEOUT, channel_id, (int)(uintptr_t)buffer, (int)buf_len, (int)timeout_ms);
}

static inline int system_shared_memory_create(uint32_t size_bytes)
{
    return do_sys(SYSTEM_SHARED_MEMORY_CREATE, (int)size_bytes, 0, 0, 0);
}

static inline int system_shared_memory_grant(int handle, int pid)
{
    return do_sys(SYSTEM_SHARED_MEMORY_GRANT, handle, pid, 0, 0);
}

static inline int system_shared_memory_map(int handle)
{
    return do_sys(SYSTEM_SHARED_MEMORY_MAP, handle, 0, 0, 0);
}

static inline int system_shared_memory_unmap(int handle)
{
    return do_sys(SYSTEM_SHARED_MEMORY_UNMAP, handle, 0, 0, 0);
}

static inline int system_shared_memory_release(int handle)
{
    return do_sys(SYSTEM_SHARED_MEMORY_RELEASE, handle, 0, 0, 0);
}

#define TTY_READ_MODE_INPUT  0
#define TTY_READ_MODE_OUTPUT 1

static inline int system_tty_read(void *buf, uint32_t len, int mode, void *color_buf)
{
    return do_sys(SYSTEM_TTY_READ, (int)(uintptr_t)buf, (int)len, mode, (int)(uintptr_t)color_buf);
}

static inline int system_tty_write(const void *buf, uint32_t len)
{
    return do_sys(SYSTEM_TTY_WRITE, (int)(uintptr_t)buf, (int)len, 0, 0);
}

// Mouse button flags
#define MOUSE_BTN_LEFT   0x01
#define MOUSE_BTN_RIGHT  0x02
#define MOUSE_BTN_MIDDLE 0x04

typedef struct system_mouse_event
{
    int8_t dx;       // Relative X movement
    int8_t dy;       // Relative Y movement
    uint8_t buttons; // MOUSE_BTN_* flags
} system_mouse_event_t;

// Blocking: waits until a mouse packet is available
static inline __attribute__((always_inline)) system_mouse_event_t system_mouse_event_get(void)
{
    int r = do_sys(SYSTEM_MOUSE_EVENT_GET, 0, 0, 0, 0);

    system_mouse_event_t ev;
    ev.buttons = (uint8_t)((r >> 16) & 0xFF);
    ev.dy = (int8_t)((r >> 8) & 0xFF);
    ev.dx = (int8_t)(r & 0xFF);

    return ev;
}

// Non-blocking: returns 1 if event available, 0 otherwise
static inline __attribute__((always_inline)) int system_mouse_event_try(system_mouse_event_t *out)
{
    int r = do_sys(SYSTEM_MOUSE_EVENT_TRY, 0, 0, 0, 0);

    // Bit 31 set means no event available
    if (r & 0x80000000)
    {
        return 0;
    }

    if (out)
    {
        out->buttons = (uint8_t)((r >> 16) & 0xFF);
        out->dy = (int8_t)((r >> 8) & 0xFF);
        out->dx = (int8_t)(r & 0xFF);
    }

    return 1;
}

// Get mouse position (updates state from pending events)
static inline __attribute__((always_inline)) void system_mouse_get_pos(int *x, int *y)
{
    int r = do_sys(SYSTEM_MOUSE_GET_POS, 0, 0, 0, 0);
    if (x) *x = (r >> 16) & 0xFFFF;
    if (y) *y = r & 0xFFFF;
}

// Set mouse position
static inline __attribute__((always_inline)) void system_mouse_set_pos(int x, int y)
{
    int packed = ((x & 0xFFFF) << 16) | (y & 0xFFFF);
    (void)do_sys(SYSTEM_MOUSE_SET_POS, packed, 0, 0, 0);
}

// Set mouse bounds (screen resolution for clamping)
static inline __attribute__((always_inline)) void system_mouse_set_bounds(int max_x, int max_y)
{
    int packed = ((max_x & 0xFFFF) << 16) | (max_y & 0xFFFF);
    (void)do_sys(SYSTEM_MOUSE_SET_BOUNDS, packed, 0, 0, 0);
}

// Get current button state (which buttons are currently held down)
static inline __attribute__((always_inline)) uint8_t system_mouse_get_buttons_down(void)
{
    return (uint8_t)do_sys(SYSTEM_MOUSE_GET_BUTTONS_DOWN, 0, 0, 0, 0);
}

// Get buttons that were just pressed (rising edge, clears on read)
static inline __attribute__((always_inline)) uint8_t system_mouse_get_buttons_pressed(void)
{
    return (uint8_t)do_sys(SYSTEM_MOUSE_GET_BUTTONS_PRESSED, 0, 0, 0, 0);
}

// Get buttons that were just released/clicked (falling edge, clears on read)
static inline __attribute__((always_inline)) uint8_t system_mouse_get_buttons_clicked(void)
{
    return (uint8_t)do_sys(SYSTEM_MOUSE_GET_BUTTONS_CLICKED, 0, 0, 0, 0);
}
