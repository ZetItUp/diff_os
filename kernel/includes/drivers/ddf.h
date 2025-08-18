#pragma once

#include "stdint.h"
#include "stdarg.h"
#include "interfaces.h"

#define DDF_MAGIC       0x00464444      // DDF (Different Driver File) Magic Number

typedef struct
{
    uint32_t magic;                     // "DDF" Magic
    uint32_t init_offset;
    uint32_t exit_offset;
    uint32_t irq_offset;
    uint32_t symbol_table_offset;       // Offset from module start to symbol table
    uint32_t symbol_table_count;        // Number of symbols
    uint32_t strtab_offset;             // Offset for string table
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t reloc_table_offset;
    uint32_t reloc_table_count;
    uint32_t text_offset;
    uint32_t text_size;
    uint32_t rodata_offset;
    uint32_t rodata_size;
    uint32_t data_offset;
    uint32_t data_size;
    uint32_t bss_offset;
    uint32_t bss_size;
    uint32_t irq_number;
} __attribute__((packed)) ddf_header_t;

typedef struct
{
    uint32_t name_offset;               // Offset in stringtable
    uint32_t value_offset;              // Offset from module start
    uint32_t type;                      // 0 = Function, 1 = Data
} __attribute__((packed)) ddf_symbol_t;

typedef struct
{
    void *module_base;
    ddf_header_t *header;
    uint32_t size_bytes;

    void (*driver_init)(kernel_exports_t*);
    void (*driver_irq)(unsigned, void*);
    void (*driver_exit)(void);
    uint32_t irq_number;
} ddf_module_t;

typedef enum ddf_reloc_type
{
    DDF_RELOC_ABS32 = 1,
    DDF_RELOC_REL32 = 2,
    DDF_RELOC_RELATIVE = 3
} ddf_reloc_type_t;

typedef struct
{
    uint32_t r_offset;
    uint32_t r_type;
    uint32_t r_sym_index;
    int32_t  r_addend;
} __attribute__((packed)) ddf_reloc_t;


void ddf_driver_init(kernel_exports_t *exports);
void ddf_driver_exit(void);
void ddf_driver_irq(unsigned irq, void *context);
extern ddf_symbol_t ddf_symbol_table[];
extern const uint32_t ddf_symbol_table_count;
void *ddf_find_symbol(void *module_base, ddf_header_t *header, const char *name);
