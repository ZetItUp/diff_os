#include "dex/exl.h"
#include "dex/dex.h"
#include "diff.h"
#include "string.h"
#include "stdint.h"
#include "stddef.h"
#include "stdio.h"
#include "console.h"
#include "paging.h"
#include "heap.h"
#include "system/usercopy.h"
#include "system/profiler.h"
#include "debug.h"

#define EXL_DBG(...) DDBG_IF(DEBUG_AREA_EXL, __VA_ARGS__)
#define EXL_IMPORT_DEBUG 0
#define EXL_REL_DEBUG 0

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

// Relaxed symbol compare ignores leading '_' and stdcall '@N' suffix
static int symname_eq(const char *left_name, const char *right_name)
{
    if (!left_name || !right_name)
    {
        return 0;
    }

    while (*left_name == '_')
    {
        ++left_name;
    }

    while (*right_name == '_')
    {
        ++right_name;
    }

    while (*left_name && *right_name)
    {
        if (*left_name == '@' || *right_name == '@')
        {
            break;
        }

        if (*left_name != *right_name)
        {
            return 0;
        }

        ++left_name;
        ++right_name;
    }

    if (*left_name == '@')
    {
        while (*left_name)
        {
            ++left_name;
        }
    }

    if (*right_name == '@')
    {
        while (*right_name)
        {
            ++right_name;
        }
    }

    return *left_name == 0 && *right_name == 0;
}

#define MAX_EXL_IMPORTS 256

static exl_t exl_files[MAX_EXL_FILES];
static uint32_t exl_cr3s[MAX_EXL_FILES];
static size_t exl_count = 0;

static char loading_names[MAX_EXL_FILES][EXL_NAME_LENGTH];
static size_t loading_depth = 0;

extern FileTable *file_table;

static void debug_print_hdr(const dex_header_t *header)
{
    if (!(g_debug_mask & DEBUG_AREA_EXL))
    {
        return;
    }

    printf("=== DEX HEADER DEBUG ===\n");
    printf("magic=0x%08x  ver=%u.%u\n", header->magic, header->version_major, header->version_minor);
    printf("entry_off=0x%08x\n", header->entry_offset);
    printf(".text  off=0x%08x sz=%u\n", header->text_offset, header->text_size);
    printf(".ro    off=0x%08x sz=%u\n", header->rodata_offset, header->rodata_size);
    printf(".data  off=0x%08x sz=%u\n", header->data_offset, header->data_size);
    printf(".bss   sz=%u\n", header->bss_size);
    printf("import off=0x%08x cnt=%u\n", header->import_table_offset, header->import_table_count);
    printf("reloc  off=0x%08x cnt=%u\n", header->reloc_table_offset, header->reloc_table_count);
    printf("symtab off=0x%08x cnt=%u\n", header->symbol_table_offset, header->symbol_table_count);
    printf("strtab off=0x%08x sz =%u\n", header->strtab_offset, header->strtab_size);
    printf("========================\n");
}

static int range_ok(uint32_t offset, uint32_t size, uint32_t maximum)
{
    if (size == 0)
    {
        return 1;
    }

    if (offset > maximum)
    {
        return 0;
    }

    if (maximum - offset < size)
    {
        return 0;
    }

    return 1;
}

static int ptr_in_range(const void *pointer, const uint8_t *base_address, uint32_t size)
{
    uint32_t pointer_value = (uint32_t)pointer;
    uint32_t base_value = (uint32_t)base_address;

    return (pointer_value >= base_value) && (pointer_value < base_value + size);
}

// Safe path and name helpers
static const char *basename_ptr_safe(const char *path)
{
    if (!path)
    {
        return "";
    }

    const char *base_name = path;

    for (const char *scan_pointer = path; *scan_pointer; ++scan_pointer)
    {
        if (*scan_pointer == '/' || *scan_pointer == '\\')
        {
            base_name = scan_pointer + 1;
        }
    }

    return base_name;
}

static void canon_exl_name(const char *input_name, char *out, size_t out_size)
{
    if (!input_name || !*input_name)
    {
        (void)strlcpy(out, "diffc.exl", out_size);
        
        return;
    }

    const char *base_name = basename_ptr_safe(input_name);
    (void)strlcpy(out, base_name, out_size);
    size_t len = strlen(out);

    if (len < 4 || strcmp(out + (len - 4), ".exl") != 0)
    {
        (void)strlcat(out, ".exl", out_size);
    }
}

static int exl_name_equals(const char *left_name, const char *right_name)
{
    char left_canonical[EXL_NAME_LENGTH];
    char right_canonical[EXL_NAME_LENGTH];

    canon_exl_name(left_name, left_canonical, sizeof(left_canonical));
    canon_exl_name(right_name, right_canonical, sizeof(right_canonical));

    return strcmp(left_canonical, right_canonical) == 0;
}

static int is_loading(const char *name)
{
    char normalized_name[EXL_NAME_LENGTH];

    canon_exl_name(name, normalized_name, sizeof(normalized_name));

    for (size_t index = 0; index < loading_depth; ++index)
    {
        if (exl_name_equals(loading_names[index], normalized_name))
        {
            return 1;
        }
    }

    return 0;
}

static void push_loading(const char *name)
{
    if (loading_depth < MAX_EXL_FILES)
    {
        canon_exl_name(name, loading_names[loading_depth], EXL_NAME_LENGTH);
        loading_depth++;
    }
}

static void pop_loading(const char *name)
{
    char normalized_name[EXL_NAME_LENGTH];

    canon_exl_name(name, normalized_name, sizeof(normalized_name));

    if (loading_depth > 0 && exl_name_equals(loading_names[loading_depth - 1], normalized_name))
    {
        loading_depth--;
        
        return;
    }

    for (size_t index = 0; index < loading_depth; ++index)
    {
        if (exl_name_equals(loading_names[index], normalized_name))
        {
            for (size_t move_index = index + 1; move_index < loading_depth; ++move_index)
            {
                (void)strlcpy(loading_names[move_index - 1], loading_names[move_index], EXL_NAME_LENGTH);
            }

            loading_depth--;
            
            return;
        }
    }
}

// EXL cache invalidation per CR3
void exl_invalidate_for_cr3(uint32_t cr3)
{
    if (!cr3)
    {
        return;
    }

    size_t index = 0;
    while (index < exl_count)
    {
        if (exl_cr3s[index] == cr3)
        {
            // Free kernel copies for this entry
            if (exl_files[index].symbol_table)
            {
                kfree((void *)exl_files[index].symbol_table);
            }

            if (exl_files[index].strtab)
            {
                kfree((void *)exl_files[index].strtab);
            }

            if (exl_files[index].header && ((uintptr_t)exl_files[index].header < USER_MIN))
            {
                kfree((void *)exl_files[index].header);
            }

            // Compress the list by moving the last entry here
            if (index != exl_count - 1)
            {
                exl_files[index] = exl_files[exl_count - 1];
                exl_cr3s[index] = exl_cr3s[exl_count - 1];
            }
            
            exl_count--;
            
            continue;
        }

        index++;
    }
}

// Symbol resolution
static void *resolve_local_symbol(const dex_header_t *header,
                                  const dex_symbol_t *symbol_table,
                                  const char *string_table,
                                  uint8_t *image,
                                  const char *symbol)
{
    if (!symbol_table || !string_table || !symbol || !*symbol)
    {
        return NULL;
    }

    for (size_t symbol_index = 0; symbol_index < header->symbol_table_count; ++symbol_index)
    {
        const dex_symbol_t *entry = &symbol_table[symbol_index];
        const char *name = string_table + entry->name_offset;

        if (strcmp(name, symbol) == 0)
        {
            return (void *)((uint32_t)image + entry->value_offset);
        }
    }

    return NULL;
}

void *resolve_exl_symbol(const char *exl_name, const char *symbol)
{
    if (!symbol || !*symbol)
    {
        return NULL;
    }

    uint32_t current_cr3 = read_cr3_local();

    // Pass 1 match requested EXL only
    for (size_t index = 0; index < exl_count; ++index)
    {
        if (exl_cr3s[index] != current_cr3)
        {
            continue;
        }

        if (!exl_name_equals(exl_files[index].name, exl_name))
        {
            continue;
        }

        const exl_t *library = &exl_files[index];
        const dex_header_t *file_header = library->header;

        for (size_t symbol_index = 0; symbol_index < library->symbol_count; ++symbol_index)
        {
            const dex_symbol_t *symbol_entry = &library->symbol_table[symbol_index];

            // First treat name_offset as relative to strtab
            const char *name_relative = library->strtab
                ? (library->strtab + symbol_entry->name_offset)
                : NULL;
            int is_relative_valid = 0;

            if (file_header && library->strtab)
            {
                uint32_t string_table_size = file_header->strtab_size;
                uintptr_t lower_bound = (uintptr_t)library->strtab;
                uintptr_t upper_bound = lower_bound + string_table_size;
                uintptr_t name_pointer = (uintptr_t)name_relative;
                is_relative_valid = (name_pointer >= lower_bound) && (name_pointer < upper_bound);
            }

            // Fallback treat name_offset as absolute file offset
            const char *name_absolute = NULL;

            if (file_header)
            {
                name_absolute = (const char *)((const uint8_t *)file_header + symbol_entry->name_offset);
                uintptr_t string_table_base = (uintptr_t)file_header + file_header->strtab_offset;
                uintptr_t string_table_end = string_table_base + file_header->strtab_size;

                if (!((uintptr_t)name_absolute >= string_table_base &&
                      (uintptr_t)name_absolute < string_table_end))
                {
                    name_absolute = NULL;
                }
            }

            const char *name = NULL;

            if (is_relative_valid)
            {
                name = name_relative;
            }
            else if (name_absolute)
            {
                name = name_absolute;
            }
            else
            {
                name = name_relative ? name_relative : name_absolute;
            }

            if (!name)
            {
                continue;
            }

            if (strcmp(name, symbol) == 0 || symname_eq(name, symbol))
            {
                return (void *)((uint32_t)library->image_base + symbol_entry->value_offset);
            }
        }
    }

    // Pass 2 search other libs in the same CR3
    for (size_t index = 0; index < exl_count; ++index)
    {
        if (exl_cr3s[index] != current_cr3)
        {
            continue;
        }

        const exl_t *library = &exl_files[index];
        const dex_header_t *file_header = library->header;

        for (size_t symbol_index = 0; symbol_index < library->symbol_count; ++symbol_index)
        {
            const dex_symbol_t *symbol_entry = &library->symbol_table[symbol_index];
            const char *name_relative = library->strtab ? (library->strtab + symbol_entry->name_offset) : NULL;
            const char *name_absolute = NULL;

            if (file_header)
            {
                const char *candidate = (const char *)((const uint8_t *)file_header + symbol_entry->name_offset);
                uintptr_t string_table_base = (uintptr_t)file_header + file_header->strtab_offset;
                uintptr_t string_table_end = string_table_base + file_header->strtab_size;

                if ((uintptr_t)candidate >= string_table_base && (uintptr_t)candidate < string_table_end)
                {
                    name_absolute = candidate;
                }
            }

            const char *name = name_relative ? name_relative : name_absolute;

            if (!name)
            {
                continue;
            }

            if (strcmp(name, symbol) == 0 || symname_eq(name, symbol))
            {
                return (void *)((uint32_t)library->image_base + symbol_entry->value_offset);
            }
        }
    }

    return NULL;
}

// Relocation
static int do_relocate_exl(
    uint8_t *image,
    uint32_t total_size,
    const dex_header_t *header,
    const dex_import_t *imports,
    const dex_reloc_t *relocations,
    const dex_symbol_t *symbol_table,
    const char *string_table,
    const char *self_name
)
{
    if (header->import_table_count > MAX_EXL_IMPORTS)
    {
        printf("[EXL] too many imports: %u\n", header->import_table_count);
        
        return -1;
    }

    void **import_pointers = NULL;

    if (header->import_table_count)
    {
        size_t bytes = (size_t)header->import_table_count * sizeof(void *);
        import_pointers = (void **)kmalloc(bytes);

        if (!import_pointers)
        {
            printf("[EXL] kmalloc(import_ptrs=%u) failed\n", (unsigned)bytes);
            
            return -2;
        }

        memset(import_pointers, 0, bytes);
    }

    #if EXL_IMPORT_DEBUG
    EXL_DBG("--- IMPORTS DEBUG ---\n");
    #endif

    for (uint32_t import_index = 0; import_index < header->import_table_count; ++import_index)
    {
        const char *exl_name = string_table + imports[import_index].exl_name_offset;
        const char *symbol_name = string_table + imports[import_index].symbol_name_offset;
        void *resolved = NULL;

        if (exl_name_equals(exl_name, self_name))
        {
            resolved = resolve_local_symbol(header, symbol_table, string_table, image, symbol_name);

            if (resolved)
            {
                #if EXL_IMPORT_DEBUG
                EXL_DBG("[EXL] resolved locally %s:%s -> %p\n", exl_name, symbol_name, resolved);
                #endif
            }
        }

        if (!resolved && is_loading(exl_name))
        {
            resolved = resolve_local_symbol(header, symbol_table, string_table, image, symbol_name);
        }

        if (!resolved)
        {
            resolved = resolve_exl_symbol(exl_name, symbol_name);
        }

        if (!resolved && !exl_name_equals(exl_name, self_name))
        {
            if (!load_exl(file_table, exl_name))
            {
                printf("[EXL] cannot load dependency: %s\n", exl_name);
                
                if (import_pointers)
                {
                    kfree(import_pointers);
                }
                
                return -3;
            }

            resolved = resolve_exl_symbol(exl_name, symbol_name);
        }

        if (!resolved)
        {
            printf("[EXL] unresolved %s:%s\n", exl_name, symbol_name);
            
            if (import_pointers)
            {
                kfree(import_pointers);
            }
            
            return -4;
        }

        if (ptr_in_range(resolved, image, total_size))
        {
            printf("[EXL] FATAL ERROR: import '%s' resolves inside EXL image (%p)\n", symbol_name, resolved);
            
            if (import_pointers)
            {
                kfree(import_pointers);
            }
            
            return -5;
        }

        import_pointers[import_index] = resolved;
        #if EXL_IMPORT_DEBUG
        EXL_DBG("[%u] %s:%s -> %p\n", import_index, exl_name, symbol_name, resolved);
        #endif
    }

    #if EXL_IMPORT_DEBUG
    EXL_DBG("----------------------\n");
    #endif

    for (uint32_t reloc_index = 0; reloc_index < header->reloc_table_count; ++reloc_index)
    {
        uint32_t offset = relocations[reloc_index].reloc_offset;
        uint32_t symbol_index = relocations[reloc_index].symbol_index;
        uint32_t reloc_type = relocations[reloc_index].type;

        if (!range_ok(offset, 4, total_size))
        {
            printf("[EXL] reloc OOR: off=0x%08x (total=%u)\n", offset, total_size);
            
            if (import_pointers)
            {
                kfree(import_pointers);
            }
            
            return -6;
        }

        uint8_t *target = image + offset;
        uint32_t site_address = (uint32_t)(image + offset);
        uint32_t old_value = *(uint32_t *)target;

        switch (reloc_type)
        {
            case DEX_ABS32:
                if (symbol_index >= header->import_table_count)
                {
                    if (import_pointers)
                    {
                        kfree(import_pointers);
                    }

                    return -7;
                }

                *(uint32_t *)target = (uint32_t)import_pointers[symbol_index];
                EXL_DBG("[ABS32] @%08x: %08x -> %08x (S=%p)\n", site_address, old_value, *(uint32_t *)target, import_pointers[symbol_index]);
                break;

            case DEX_PC32:
                if (symbol_index >= header->import_table_count)
                {
                    if (import_pointers)
                    {
                        kfree(import_pointers);
                    }

                    return -8;
                }

                *(int32_t *)target = (int32_t)((uint32_t)import_pointers[symbol_index] - (site_address + 4));
                EXL_DBG("[PC32]  @%08x: P=%08x S=%08x -> disp=%d (old=%08x new=%08x)\n",
                        site_address, site_address + 4, (uint32_t)import_pointers[symbol_index],
                        *(int32_t *)target, old_value, *(uint32_t *)target);
                break;

            case DEX_RELATIVE:
                *(uint32_t *)target = old_value + (uint32_t)image;

#if EXL_REL_DEBUG
                EXL_DBG("[REL]   @%08x: %08x -> %08x (base=%08x)\n", site_address, old_value, *(uint32_t *)target, (uint32_t)image);
#endif

                break;

            default:
                printf("[EXL] UNKNOWN reloc type: %u @ off=0x%08x (old=%08x)\n", reloc_type, offset, old_value);
                if (import_pointers)
                {
                    kfree(import_pointers);
                }
                
                return -13;
        }

        #if EXL_REL_DEBUG
        EXL_DBG("new=0x%08x\n", *(uint32_t *)target);
        #endif
    }

    if (import_pointers)
    {
        kfree(import_pointers);
    }

    return 0;
}

const exl_t *load_exl(const FileTable *file_table_ref, const char *exl_name)
{
    if (exl_count >= MAX_EXL_FILES)
    {
        printf("[EXL] ERROR: out of slots\n");
        
        return NULL;
    }

    EXL_DBG("[EXL] load_exl req='%s'\n", exl_name ? exl_name : "(null)");

    if (g_debug_mask & DEBUG_AREA_EXL)
    {
        printf("load_exl heapdump:\n");
        heap_dump();
    }

    char normalized_name[EXL_NAME_LENGTH];
    canon_exl_name(exl_name, normalized_name, sizeof(normalized_name));

    uint32_t current_cr3 = read_cr3_local();
    EXL_DBG("[EXL] normalized='%s' cr3=%08x exl_count=%u\n", normalized_name, current_cr3, (unsigned)exl_count);

    // Find existing EXL in the same CR3
    for (size_t index = 0; index < exl_count; ++index)
    {
        if (exl_cr3s[index] != current_cr3)
        {
            continue;
        }

        if (exl_name_equals(exl_files[index].name, normalized_name))
        {
            const exl_t *library = &exl_files[index];

            // Check that the image is still mapped in user space
            if (library->image_base && paging_check_user_range((uint32_t)library->image_base, 4) == 0)
            {
                return library;
            }

            EXL_DBG("[EXL] stale cache for CR3=%08x, invalidating\n", current_cr3);
            exl_invalidate_for_cr3(current_cr3);
        
            break;
        }
    }

    if (is_loading(normalized_name))
    {
        EXL_DBG("[EXL] already loading '%s' - skip\n", normalized_name);
        
        return NULL;
    }

    push_loading(normalized_name);

    char path[EXL_NAME_LENGTH * 2];
    (void)snprintf(path, sizeof(path), "/system/exls/%s", normalized_name);

    int file_index = find_entry_by_path(file_table_ref, path);

    if (file_index < 0)
    {
        printf("[EXL] not found: %s\n", path);
        pop_loading(normalized_name);
        
        return NULL;
    }

    const FileEntry *file_entry = &file_table_ref->entries[file_index];
    uint32_t file_size = fe_file_size_bytes(file_entry);

    // Read EXL into a user buffer to avoid large kernel heap use
    uint8_t *file_buffer = umalloc(file_size);

    if (!file_buffer)
    {
        printf("[EXL] umalloc filebuf fail (%u)\n", file_size);
        pop_loading(normalized_name);
        
        return NULL;
    }

    paging_update_flags((uint32_t)file_buffer, file_size, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    if (g_debug_mask & DEBUG_AREA_EXL)
    {
        printf("[EXL DEBUG] filebuf=%p (user) sz=%u\n", file_buffer, file_size);
    }

    int read_bytes = read_file(file_table_ref, path, file_buffer);

    if (read_bytes < 0)
    {
        printf("[EXL] read fail: %s\n", path);
        ufree(file_buffer, file_size);

        if (heap_validate() != 0)
        {
            heap_dump();
        }
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    uint32_t file_bytes = (uint32_t)read_bytes;
    EXL_DBG("[EXL] read bytes=%u from %s into %p\n", file_bytes, path, file_buffer);

    if (!range_ok(0, sizeof(dex_header_t), file_bytes))
    {
        printf("[EXL] file too small for header\n");
        ufree(file_buffer, file_size);
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    const dex_header_t *header = (const dex_header_t *)file_buffer;

    if (header->magic != DEX_MAGIC)
    {
        printf("[EXL] bad magic in %s (0x%08x)\n", path, header->magic);
        ufree(file_buffer, file_size);
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    if (header->version_major != DEX_VERSION_MAJOR || header->version_minor != DEX_VERSION_MINOR)
    {
        printf("[EXL] unsupported EXL version %u.%u (want %u.%u)\n",
               header->version_major, header->version_minor,
               DEX_VERSION_MAJOR, DEX_VERSION_MINOR);
        ufree(file_buffer, file_size);
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    debug_print_hdr(header);
    EXL_DBG("[EXL] sections text@0x%08x sz=%u ro@0x%08x sz=%u data@0x%08x sz=%u bss=%u\n",
            header->text_offset, header->text_size,
            header->rodata_offset, header->rodata_size,
            header->data_offset, header->data_size,
            header->bss_size);
    EXL_DBG("[EXL] tables import_off=0x%08x cnt=%u reloc_off=0x%08x cnt=%u sym_off=0x%08x cnt=%u str_off=0x%08x sz=%u\n",
            header->import_table_offset, header->import_table_count,
            header->reloc_table_offset, header->reloc_table_count,
            header->symbol_table_offset, header->symbol_table_count,
            header->strtab_offset, header->strtab_size);

    if (!range_ok(header->text_offset, header->text_size, file_bytes) ||
        !range_ok(header->rodata_offset, header->rodata_size, file_bytes) ||
        !range_ok(header->data_offset, header->data_size, file_bytes))
    {
        printf("[EXL] section range OOR (fsz=%u)\n", file_bytes);
        ufree(file_buffer, file_size);

        if (heap_validate() != 0)
        {
            heap_dump();
        }
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    if ((header->import_table_count &&
         !range_ok(header->import_table_offset, header->import_table_count * sizeof(dex_import_t), file_bytes)) ||
        (header->reloc_table_count &&
         !range_ok(header->reloc_table_offset, header->reloc_table_count * sizeof(dex_reloc_t), file_bytes)) ||
        (header->symbol_table_count &&
         !range_ok(header->symbol_table_offset, header->symbol_table_count * sizeof(dex_symbol_t), file_bytes)) ||
        (header->strtab_size &&
         !range_ok(header->strtab_offset, header->strtab_size, file_bytes)))
    {
        printf("[EXL] table range OOR\n");
        ufree(file_buffer, file_size);

        if (heap_validate() != 0)
        {
            heap_dump();
        }
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    // Entry must land inside the text range
    uint32_t entry_offset = header->entry_offset;

    if (!(entry_offset >= header->text_offset && entry_offset < header->text_offset + header->text_size))
    {
        printf("[EXL] entry_offset 0x%08x outside .text (text_off=0x%08x sz=0x%08x)\n",
               entry_offset, header->text_offset, header->text_size);
        ufree(file_buffer, file_size);

        if (heap_validate() != 0)
        {
            heap_dump();
        }
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    const dex_symbol_t *symbol_table = (const dex_symbol_t *)(file_buffer + header->symbol_table_offset);
    const char *string_table = (const char *)(file_buffer + header->strtab_offset);

    uint32_t text_size = header->text_size;
    uint32_t rodata_size = header->rodata_size;
    uint32_t data_size = header->data_size;
    uint32_t bss_size = header->bss_size;

    uint32_t end_text = header->text_offset + text_size;
    uint32_t end_rodata = header->rodata_offset + rodata_size;
    uint32_t end_data = header->data_offset + data_size + bss_size;
    uint32_t max_end = end_text;
    
    if (end_rodata > max_end)
    {
        max_end = end_rodata;
    }

    if (end_data > max_end)
    {
        max_end = end_data;
    }

    uint32_t total_size = PAGE_ALIGN_UP(max_end);

    if (total_size < max_end || total_size == 0)
    {
        printf("[EXL] total size overflow\n");
        ufree(file_buffer, file_size);

        if (heap_validate() != 0)
        {
            heap_dump();
        }
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    EXL_DBG("[EXL] image size total_sz=%u max_end=0x%08x\n", total_size, max_end);

    // Allocate the user image and map RW while copying
    uint8_t *image = umalloc(total_size);
    
    if (!image)
    {
        printf("[EXL] umalloc(%u) fail\n", total_size);
        ufree(file_buffer, file_size);

        if (heap_validate() != 0)
        {
            heap_dump();
        }
    
        pop_loading(normalized_name);
    
        return NULL;
    }

    paging_update_flags((uint32_t)image, total_size, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    EXL_DBG("[EXL] image_base=%p\n", image);

    // Zero the image so padding matches the tool output
    memset(image, 0, total_size);

    // Copy sections to the user image
    if (text_size)
    {
        if (copy_to_user(image + header->text_offset, file_buffer + header->text_offset, text_size) != 0)
        {
            printf("[EXL] Failed to copy .text to user image\n");
            ufree(image, total_size);
            ufree(file_buffer, file_size);

            if (heap_validate() != 0)
            {
                heap_dump();
            }
            
            pop_loading(normalized_name);
            
            return NULL;
        }
    }

    if (rodata_size)
    {
        if (copy_to_user(image + header->rodata_offset, file_buffer + header->rodata_offset, rodata_size) != 0)
        {
            printf("[EXL] Failed to copy .rodata to user image\n");
            ufree(image, total_size);
            ufree(file_buffer, file_size);

            if (heap_validate() != 0)
            {
                heap_dump();
            }
            
            pop_loading(normalized_name);
            
            return NULL;
        }
    }

    if (data_size)
    {
        if (copy_to_user(image + header->data_offset, file_buffer + header->data_offset, data_size) != 0)
        {
            printf("[EXL] Failed to copy .data to user image\n");
            ufree(image, total_size);
            ufree(file_buffer, file_size);

            if (heap_validate() != 0)
            {
                heap_dump();
            }
            
            pop_loading(normalized_name);
            
            return NULL;
        }
    }

    if (bss_size)
    {
        memset(image + header->data_offset + data_size, 0, bss_size);
    }

    const dex_import_t *imports = (const dex_import_t *)(file_buffer + header->import_table_offset);
    const dex_reloc_t *relocations = (const dex_reloc_t *)(file_buffer + header->reloc_table_offset);

    if (g_debug_mask & DEBUG_AREA_EXL)
    {
        paging_dump_range((uint32_t)(image + header->text_offset), PAGE_ALIGN_UP(text_size));
    }

    if (do_relocate_exl(image, total_size, header, imports, relocations, symbol_table, string_table, normalized_name) != 0)
    {
        printf("[EXL] relocation failed for %s\n", normalized_name);
        ufree(image, total_size);
        ufree(file_buffer, file_size);

        if (heap_validate() != 0)
        {
            heap_dump();
        }
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    // Text is RX and data bss is RW
    if (text_size)
    {
        paging_update_flags((uint32_t)(image + header->text_offset), PAGE_ALIGN_UP(text_size), 0, PAGE_RW);
    }

    if (data_size || bss_size)
    {
        paging_update_flags((uint32_t)(image + header->data_offset),
                            PAGE_ALIGN_UP(data_size + bss_size),
                            PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    }

    paging_set_user((uint32_t)image, total_size);

    if (paging_check_user_range((uint32_t)image, total_size) != 0)
    {
        printf("[EXL] WARN: not all pages are USER\n");
    }

    // Make sure the full image is mapped now
    if (paging_map_user_range((uint32_t)image, total_size, 1) != 0)
    {
        printf("[EXL] failed to pre-map image region\n");
        ufree(image, total_size);
        ufree(file_buffer, file_size);

        if (heap_validate() != 0)
        {
            heap_dump();
        }
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    // Copy symtab and strtab to kernel memory
    dex_symbol_t *symbol_table_copy = NULL;
    char *string_table_copy = NULL;
    dex_header_t *header_copy = NULL;

    if (header->symbol_table_count)
    {
        size_t sym_bytes = header->symbol_table_count * sizeof(dex_symbol_t);
        symbol_table_copy = kmalloc(sym_bytes);

        if (!symbol_table_copy)
        {
            printf("[EXL] symtab alloc fail\n");
            ufree(file_buffer, file_size);

            if (heap_validate() != 0)
            {
                heap_dump();
            }

            ufree(image, total_size);
        
            pop_loading(normalized_name);
        
            return NULL;
        }

        memcpy(symbol_table_copy, (const void *)(file_buffer + header->symbol_table_offset), sym_bytes);
    }

    if (header->strtab_size)
    {
        string_table_copy = kmalloc(header->strtab_size);

        if (!string_table_copy)
        {
            if (symbol_table_copy)
            {
                kfree(symbol_table_copy);
            }
            printf("[EXL] strtab alloc fail\n");
            ufree(file_buffer, file_size);

            if (heap_validate() != 0)
            {
                heap_dump();
            }

            ufree(image, total_size);
        
            pop_loading(normalized_name);
        
            return NULL;
        }

        memcpy(string_table_copy, (const void *)(file_buffer + header->strtab_offset), header->strtab_size);
    }

    header_copy = kmalloc(sizeof(dex_header_t));

    if (!header_copy)
    {
        printf("[EXL] header alloc fail\n");
        
        if (symbol_table_copy)
        {
            kfree(symbol_table_copy);
        }

        if (string_table_copy)
        {
            kfree(string_table_copy);
        }

        ufree(file_buffer, file_size);

        if (heap_validate() != 0)
        {
            heap_dump();
        }

        ufree(image, total_size);
        
        pop_loading(normalized_name);
        
        return NULL;
    }

    memcpy(header_copy, header, sizeof(dex_header_t));

    // Register lib in cache for this CR3
    exl_t *library = &exl_files[exl_count];
    memset(library, 0, sizeof(*library));
    (void)strlcpy(library->name, normalized_name, sizeof(library->name));

    library->image_base = image;
    library->image_size = total_size;
    library->header = header_copy;
    library->symbol_table = symbol_table_copy;
    library->symbol_count = header->symbol_table_count;
    library->strtab = string_table_copy;
    
    entry_offset = header_copy->entry_offset;

    exl_cr3s[exl_count] = current_cr3;
    exl_count++;

    // Load symbols for profiler
    profiler_load_symbols(file_buffer, file_size, (uint32_t)image, normalized_name);

    // Free file buffer
    ufree(file_buffer, file_size);

    if (heap_validate() != 0)
    {
        heap_dump();
    }

    pop_loading(normalized_name);

    EXL_DBG("[EXL] loaded '%s' base=%p size=%u (.text RX, .data/.bss RW) cr3=%08x\n",
         library->name, library->image_base, library->image_size, current_cr3);

    if (g_debug_mask & DEBUG_AREA_EXL)
    {
        uint32_t entry = (uint32_t)image + entry_offset;
        dump_pde_pte(entry);
        printf("[EXL] entry VA=%08x (off=0x%x)\n", entry, entry_offset);
    }

    return library;
}
