#pragma once

#include <stdint.h>
#include <stddef.h>

#define SYSCALL_VECTOR      0x66        // Different OS Specific
                                        
enum
{
    SYSTEM_EXIT = 0,
    SYSTEM_PUTCHAR = 1,
    SYSTEM_PRINT = 2,
    SYSTEM_GETCH = 3,
    SYSTEM_TRYGETCH = 4,
};

static inline int syscall(int num, int arg0, int arg1, int arg2, int arg3)
{
    int ret;
    
    __asm__ volatile (
        "int %1"
        : "=a"(ret)
        : "i"(SYSCALL_VECTOR), "a"(num), "b"(arg0), "c"(arg1), "d"(arg2), "S"(arg3)
        : "memory", "cc"
    );

    return ret;
}

static inline __attribute__((always_inline)) void system_exit(int code) 
{
    syscall(SYSTEM_EXIT, code, 0, 0, 0);
    __builtin_unreachable();
}

static inline __attribute__((always_inline)) void system_putchar(char c) 
{
    (void)syscall(SYSTEM_PUTCHAR, (unsigned char)c, 0, 0, 0);
}

static inline __attribute__((always_inline)) void system_print(const char *str) 
{
    (void)syscall(SYSTEM_PRINT, (uintptr_t)str, 0, 0, 0);
}

static inline __attribute__((always_inline)) uint8_t system_getch(void)
{
    return (uint8_t)(syscall(SYSTEM_GETCH, 0, 0, 0, 0) & 0xFF);    
}

static inline __attribute__((always_inline)) int system_trygetch(uint8_t *out)
{
    int r = syscall(SYSTEM_TRYGETCH, 0, 0, 0, 0);

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
