#pragma once

#include "stdint.h"
#include "stdarg.h"

// Exposed kernel function hooks (used by drivers)
typedef struct kernel_exports
{
    unsigned char (*inb)(unsigned short port);
    void (*outb)(unsigned short port, unsigned char data);
    unsigned short (*inw)(unsigned short port);
    void (*outw)(unsigned short port, unsigned short data);
    void (*outl)(uint16_t port, uint32_t value);
    uint32_t (*inl)(uint16_t port);
    void (*io_wait)(void);

    int (*printf)(const char *fmt, ...);
    int (*vprintf)(const char *fmt, va_list ap);
    void (*pic_clear_mask)(uint8_t);
    void (*pic_set_mask)(uint8_t);

    void *(*map_physical)(uint32_t phys, uint32_t size, uint32_t flags);  // Map physical memory into VA

    void (*keyboard_register)(int (*read_fn)(uint8_t*), uint8_t (*block_fn)(void));  // Plug keyboard backend

    void (*vbe_register)(uint32_t phys_base, uint32_t width, uint32_t height, uint32_t bpp, uint32_t pitch);  // Register VBE mode
} __attribute__((packed)) kernel_exports_t;

// Keyboard-facing exports
typedef struct keyboard_exports
{
    int (*keyboard_read)(uint8_t *out);
    uint8_t (*keyboard_read_blocking)(void);
} __attribute__((packed)) keyboard_exports_t;

// Shared VBE info
typedef struct vbe_exports
{
    volatile void *frame_buffer;

    uint32_t phys_base;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t pitch;
} __attribute__((packed)) vbe_exports_t;

// Kernel exports instance
extern kernel_exports_t g_exports;

// Memory helpers
extern void* kernel_map_physical_addr(uint32_t phys, uint32_t size, uint32_t flags);

// Keyboard
extern keyboard_exports_t g_keyboard;
void keyboard_register(int (*read_fn)(uint8_t*), uint8_t (*block_fn)(void));
void keyboard_init(void);
void keyboard_drain(void);
int keyboard_trygetch(uint8_t *out);
uint8_t keyboard_getch(void);

// Console colors 
int console_set_colors_kernel(uint8_t fg, uint8_t bg);
void console_get_colors_kernel(uint8_t *out_fg, uint8_t *out_bg);

// VBE registration and state
extern vbe_exports_t g_vbe;
void vbe_register(uint32_t phys_base, uint32_t width, uint32_t height, uint32_t bpp, uint32_t pitch);
void vbe_restore_text_mode(void);

