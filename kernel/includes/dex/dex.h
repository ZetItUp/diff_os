#pragma once
#include "stdint.h"
#include "stddef.h"
#include "diff.h"

#define DEX_MAGIC           0x58454400  // "DEX\0"
#define DEX_VERSION_MAJOR   1
#define DEX_VERSION_MINOR   0

#define DEX_ABS32     0
#define DEX_PC32      2
#define DEX_RELATIVE  8

typedef struct
{
    uint32_t magic;                     // "DEX"
    uint32_t version_major;             // Version Major
    uint32_t version_minor;             // Version Minor

    uint32_t entry_offset;              // Entrypoint Offset
    uint32_t text_offset;               // Text Offset
    uint32_t text_size;                 // Text Size
    uint32_t rodata_offset;             // Read-Only Offset
    uint32_t rodata_size;               // Read-Only Size
    uint32_t data_offset;               // Data Offset
    uint32_t data_size;                 // Data Size
    uint32_t bss_size;                  // BSS Size

    uint32_t import_table_offset;       // Import Table Offset (Future proof for linking)
    uint32_t import_table_count;        // Import Table Size
    uint32_t reloc_table_offset;        // Relocation Table Offset
    uint32_t reloc_table_count;         // Relocation Size

    uint32_t symbol_table_offset;       // Symbol Table Offset
    uint32_t symbol_table_count;        // Symbol Table Size
    uint32_t strtab_offset;             // Strings Table Offset
    uint32_t strtab_size;               // Strings Table Size

    uint32_t reserved[8];               // Reserved (In case it will be needed in the future)
} __attribute__((packed)) dex_header_t;


typedef struct
{
    uint32_t exl_name_offset;           // Offset in String Table (Executable Library)
    uint32_t symbol_name_offset;        // Symbol name offset
    uint32_t import_type;               // Import type (0 = function, 1 = data, for now...)
    uint32_t reserved;                  // Reserved
} __attribute__((packed)) dex_import_t;

typedef struct
{
    uint32_t name_offset;               // Offset in String Table
    uint32_t value_offset;              // Offset from Image Base
    uint32_t type;                      // Symbol type (0 = function, 1 = data)
} __attribute__((packed)) dex_symbol_t;

typedef struct
{
    uint32_t reloc_offset;              // Relocation offset in image
    uint32_t symbol_index;              // Index in import/symbol table
    uint32_t type;                      // Relocation Type (Absolut, Relative)
    uint32_t reserved;
} __attribute__((packed)) dex_reloc_t;

typedef struct
{
    uint8_t *image_base;
    dex_header_t *header;
    void (*dex_entry)(void);
    uint32_t image_size;
} dex_executable_t;

void dex_run(const FileTable *ft, const char *path, int argc, char **argv);
int dex_load(const void *file_data, size_t file_size, dex_executable_t *out);
