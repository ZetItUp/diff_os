#pragma once
#include <stdint.h>
#include <stddef.h>

#define DEX_PARAMS_MAGIC    0x44504152  // "DPAR"
#define DEX_MAGIC           0x58454400  // "DEX\0"

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
    uint32_t magic;          // DEX_PARAMS_MAGIC
    uint16_t ver_major;      // = 1
    uint16_t ver_minor;      // = 0
    uint32_t flags;          // framtida

    // "Windows-likt": CommandLine+Environment som block, samt argv/envp färdiga
    uint32_t argc;           // antal args
    uint32_t argv;           // user-VA -> char* argv[]
    uint32_t envc;           // antal env-par (om du vill räkna)
    uint32_t envp;           // user-VA -> char* envp[] (NULL-terminerad)

    uint32_t cmdline;        // user-VA -> UTF-8/ASCII sträng (hela kommandoraden)
    uint32_t cwd;            // user-VA -> CWD-sträng (valfritt, kan vara 0)

    // Praktiskt för runtime/debug
    uint32_t image_base;     // user-VA bas
    uint32_t image_size;     // tot storlek
    uint32_t stack_top;      // högsta user-VA i stacket
    uint32_t stack_limit;    // lägsta mappade VA i stacket (över guard)

    uint32_t reserved[8];    // framtida
} __attribute__((packed)) dex_params_t;

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
    uint32_t symbol_name_offset;              // Index in import/symbol table
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

typedef struct dex_params_t dex_params_t;
extern dex_params_t __dex_process_params;

static inline const dex_params_t* dex_get_params(void) 
{
    return &__dex_process_params;
}
