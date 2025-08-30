#pragma once

#include "system.h"

#define KERNEL_CS   0x08
#define KERNEL_DS   0x10
#define MAX_EXEC_NEST 8
#define MAX_ARG_LEN   256

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
};

struct syscall_frame 
{
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;

    uint32_t gs;
    uint32_t fs;
    uint32_t es;
    uint32_t ds;

    uint32_t eip;
    uint32_t cs;
    uint32_t eflags;
    uint32_t useresp;
    uint32_t ss;
};

int system_call_dispatch(struct syscall_frame *f);
void system_call_init(void);

struct dirent;
extern void system_call_stub(void);
extern FileTable *file_table;

int resolve_exec_path(char *out, size_t out_sz, const char *name);

int system_open_dir(const char *path);
int system_read_dir(int handle, struct dirent *out);
int system_close_dir(int handle);

int system_file_open(const char *abs_path, int oflags, int mode);
int system_file_close(int file_descriptor);
long system_file_seek(int file, long offset, int whence);
long system_file_read(int file, void *buf, unsigned long count);
long system_file_write(int file, const void *buf, unsigned long count);

int system_file_stat(const char *abs_path, filesystem_stat_t *user_st);
int system_file_fstat(int file, filesystem_stat_t *user_st);

int system_brk_set(void *new_break);
void system_brk_init_window(uintptr_t image_base, uintptr_t image_size);

int system_process_spawn(const char *upath, int argc, char **uargv);
int system_wait_pid(int pid, int *u_status);
int system_video_present_user(const void *user_ptr, int pitch_bytes, int packed_wh);
int system_video_mode_set(int w, int h, int bpp);
