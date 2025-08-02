#pragma once

#include "stdint.h"
#include "stdarg.h"

#define DDF_MAGIC       0x00464444      // DDF (Different Driver File) Magic Number

typedef struct
{
    uint32_t magic;                     // "DDF" Magic
    uint32_t init_offset;
    uint32_t exit_offset;
    uint32_t irq_offset;
    uint32_t symbol_table_offset;       // Offset from module start to symbol table
    uint32_t symbol_table_count;        // Number of symbols
    const char *name;
    uint32_t version_major;
    uint32_t version_minor;
} ddf_header_t;

typedef struct
{
    uint32_t name_offset;               // Offset in stringtable
    uint32_t value_offset;              // Offset from module start
    uint32_t type;                      // 0 = Function, 1 = Data
} ddf_symbol_t;

typedef struct kernel_exports
{
    unsigned char (*inb)(unsigned char port);
    void (*outb)(unsigned short port, unsigned char data);
    void (*printf)(const char *fmt, ...);
    void (*pic_clear_mask)(int);
    void (*pic_set_mask)(int);
} kernel_exports_t;

void *ddf_find_symbol(void *module, const char *name);
