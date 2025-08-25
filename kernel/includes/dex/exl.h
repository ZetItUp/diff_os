#pragma once

#include "dex/dex.h"
#include "stddef.h"
#include "stdint.h"

#define MAX_EXL_FILES       32
#define MAX_EXL_SYMBOLS     256
#define EXL_NAME_LENGTH     256

typedef struct
{
    char name[EXL_NAME_LENGTH];
    uint8_t *image_base;
    uint32_t image_size;
    const dex_header_t *header;
    const dex_symbol_t *symbol_table;
    size_t symbol_count;
    const char *strtab;
} exl_t;

const exl_t* load_exl(const FileTable *ft, const char *exl_name);
void* resolve_exl_symbol(const char* exl_name, const char* symbol);

/* Invalidate all cached EXL entries bound to a specific CR3. */
void exl_invalidate_for_cr3(uint32_t cr3);

