#pragma once

#include <stdint.h>
#include <stddef.h>

#define SYSCALL_VECTOR      0x66        // Different OS Specific
                                        
enum
{
    SYSTEM_EXIT = 0,
    SYSTEM_PUTCHAR = 1,
    SYSTEM_PRINT = 2,
};

static inline int syscall(int num, int arg0, int arg1, int arg2, int arg3)
{
    int ret;
    
    __asm__ volatile (
        "int %1"
        : "=a"(ret)
        : "i"(SYSCALL_VECTOR), "a"(num), "b"(arg0), "c"(arg1), "d"(arg2), "S"(arg3)
        : "memory"
    );

    return ret;
}

static inline __attribute__((always_inline)) void system_exit(int code) {
    syscall(SYSTEM_EXIT, code, 0, 0, 0);
    __builtin_unreachable();
}
static inline __attribute__((always_inline)) void system_putchar(char c) {
    (void)syscall(SYSTEM_PUTCHAR, (unsigned char)c, 0, 0, 0);
}
static inline __attribute__((always_inline)) void system_print(const char *str) {
    (void)syscall(SYSTEM_PRINT, (uintptr_t)str, 0, 0, 0);
}

