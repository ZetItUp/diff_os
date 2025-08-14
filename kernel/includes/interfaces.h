#pragma once

#include "stdint.h"
#include "stdarg.h"

typedef struct kernel_exports
{
    unsigned char (*inb)(unsigned short port);
    void (*outb)(unsigned short port, unsigned char data);
    void (*printf)(const char *fmt, ...);
    void (*vprintf)(const char *fmt, va_list ap);
    void (*pic_clear_mask)(uint8_t);
    void (*pic_set_mask)(uint8_t);
    
    // Interfaces
    void (*keyboard_register)(int (*read_fn)(uint8_t*), uint8_t (*block_fn)(void));
} __attribute__((packed)) kernel_exports_t;

typedef struct keyboard_exports
{
    int (*keyboard_read)(uint8_t *out);
    uint8_t (*keyboard_read_blocking)(void);
} __attribute__((packed)) keyboard_exports_t;

// Kernel
extern kernel_exports_t g_exports;

// Keyboard
extern keyboard_exports_t g_keyboard;

void keyboard_register(int (*read_fn)(uint8_t*), uint8_t (*block_fn)(void));

void keyboard_init(void);
void keyboard_drain(void);
int keyboard_trygetch(uint8_t *out);
uint8_t keyboard_getch(void);
