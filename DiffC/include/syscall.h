#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

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
    SYSTEM_CONSOLE_FLOOR_CLEAR = 7
};

static inline __attribute__((always_inline))
int do_sys(int n, int a0, int a1, int a2, int a3) {
    int r;
    asm volatile(
        "push %%ebx; push %%ecx; push %%edx; push %%esi;"
        "mov %1,%%eax; mov %2,%%ebx; mov %3,%%ecx; mov %4,%%edx; mov %5,%%esi;"
        "int $0x66;"
        "pop %%esi; pop %%edx; pop %%ecx; pop %%ebx;"
        : "=a"(r) : "r"(n),"r"(a0),"r"(a1),"r"(a2),"r"(a3) : "memory","cc"
    );
    return r;
}

static inline __attribute__((always_inline)) void system_exit(int code) 
{
    (void)do_sys(SYSTEM_EXIT, code, 0, 0, 0);
    __builtin_unreachable();
}

static inline __attribute__((always_inline)) void system_putchar(char c) 
{
    (void)do_sys(SYSTEM_PUTCHAR, (unsigned char)c, 0, 0, 0);
}

static inline __attribute__((always_inline)) void system_print(const char *str) 
{
    (void)do_sys(SYSTEM_PRINT, (uintptr_t)str, 0, 0, 0);
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

