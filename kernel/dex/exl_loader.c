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

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

#define MAX_EXL_IMPORTS 256

// Metadata about of EXL modules
static exl_t exl_files[MAX_EXL_FILES];
static size_t exl_count = 0;

// Loading stack to avoid recursive self-loading
static char loading_names[MAX_EXL_FILES][EXL_NAME_LENGTH];
static size_t loading_depth = 0;

// File table
extern FileTable *file_table;

static void debug_print_hdr(const dex_header_t *h) 
{
#ifndef DIFF_DEBUG
    (void)h;
#endif
    DDBG("=== DEX HEADER DEBUG ===\n");
    DDBG("magic=0x%08x  ver=%u.%u\n",   h->magic,               h->version_major, h->version_minor);
    DDBG("entry_off=0x%08x\n",          h->entry_offset);
    DDBG(".text  off=0x%08x sz=%u\n",   h->text_offset,         h->text_size);
    DDBG(".ro    off=0x%08x sz=%u\n",   h->rodata_offset,       h->rodata_size);
    DDBG(".data  off=0x%08x sz=%u\n",   h->data_offset,         h->data_size);
    DDBG(".bss   sz=%u\n",              h->bss_size);
    DDBG("import off=0x%08x cnt=%u\n",  h->import_table_offset, h->import_table_count);
    DDBG("reloc  off=0x%08x cnt=%u\n",  h->reloc_table_offset,  h->reloc_table_count);
    DDBG("symtab off=0x%08x cnt=%u\n",  h->symbol_table_offset, h->symbol_table_count);
    DDBG("strtab off=0x%08x sz =%u\n",  h->strtab_offset,       h->strtab_size);
    DDBG("========================\n");
}

static int range_ok(uint32_t off, uint32_t sz, uint32_t max) 
{
    if (sz == 0) return 1;
    if (off > max) return 0;
    if (max - off < sz) return 0;
    return 1;
}

static int ptr_in_range(const void *p, const uint8_t *base, uint32_t size) 
{
    uint32_t v = (uint32_t)p, b = (uint32_t)base;
    
    return (v >= b) && (v < b + size);
}

// Normalize EXL name (adds .exl if missing)
static void canon_exl_name(const char *in, char *out, size_t out_sz) 
{
    if (!in || !*in) 
    { 
        snprintf(out, out_sz, "diffc.exl"); 
        
        return; 
    }
    
    const char *base = in;
    const char *slash = strrchr(in, '/');
    
    if (slash)
    {
        base = slash + 1;
    }

    snprintf(out, out_sz, "%s", base);
    size_t len = strlen(out);
    
    if (len < 4 || strcmp(out + (len - 4), ".exl") != 0) 
    {
        strncat(out, ".exl", out_sz - (len + 1));
        out[out_sz-1] = 0;
    }
}

// Compare two EXL names after normalization
static int exl_name_equals(const char *a, const char *b) 
{
    char ca[EXL_NAME_LENGTH], cb[EXL_NAME_LENGTH];

    canon_exl_name(a, ca, sizeof(ca));
    canon_exl_name(b, cb, sizeof(cb));

    return strcmp(ca, cb) == 0;
}

// Check if an EXL is currently in a loading state
static int is_loading(const char *name) 
{
    char norm[EXL_NAME_LENGTH]; canon_exl_name(name, norm, sizeof(norm));

    for (size_t i = 0; i < loading_depth; ++i) 
    {
        if (exl_name_equals(loading_names[i], norm))
        {
            return 1;
        }
    }
    
    return 0;
}

// Push EXL name on the loading stack
static void push_loading(const char *name) 
{
    if (loading_depth < MAX_EXL_FILES) 
    {
        canon_exl_name(name, loading_names[loading_depth], EXL_NAME_LENGTH);
        loading_depth++;
    }
}

// Pop EXL name from the loading stack
static void pop_loading(const char *name) 
{
    char norm[EXL_NAME_LENGTH]; 
    canon_exl_name(name, norm, sizeof(norm));
    
    if (loading_depth > 0 && exl_name_equals(loading_names[loading_depth-1], norm)) 
    {
        loading_depth--; return;
    }
    
    for (size_t i = 0; i < loading_depth; ++i) 
    {
        if (exl_name_equals(loading_names[i], norm)) 
        {
            for (size_t j = i+1; j < loading_depth; ++j) 
            {
                strncpy(loading_names[j-1], loading_names[j], EXL_NAME_LENGTH-1);
                loading_names[j-1][EXL_NAME_LENGTH-1] = 0;
            }
            
            loading_depth--;
            
            return;
        }
    }
}

// Resolve a symbol from the local EXL
static void* resolve_local_symbol(const dex_header_t *hdr,
                                  const dex_symbol_t *symtab,
                                  const char *strtab,
                                  uint8_t *image,
                                  const char *symbol)
{
    if (!symtab || !strtab || !symbol || !*symbol)
    {
        return NULL;
    }

    for (size_t i = 0; i < hdr->symbol_table_count; ++i) 
    {
        const dex_symbol_t *s = &symtab[i];
        const char *nm = strtab + s->name_offset;
    
        if (strcmp(nm, symbol) == 0) 
        {
            return (void*)((uint32_t)image + s->value_offset);
        }
    }
    
    return NULL;
}

// Public symbol resolver (searches loaded EXLs)
void* resolve_exl_symbol(const char* exl_name, const char* symbol)
{
    if (!symbol || !*symbol)
    {
        return NULL;
    }

    for (size_t i = 0; i < exl_count; ++i) 
    {
        if (!exl_name_equals(exl_files[i].name, exl_name))
        {
            continue;
        }

        const exl_t *lib = &exl_files[i];
        
        for (size_t s = 0; s < lib->symbol_count; ++s) 
        {
            const dex_symbol_t *sym = &lib->symbol_table[s];
            const char *nm = lib->strtab + sym->name_offset;
        
            if (strcmp(nm, symbol) == 0) 
            {
                return (void*)((uint32_t)lib->image_base + sym->value_offset);
            }
        }
    }
    
    return NULL;
}

// Apply relocations in the EXL
static int do_relocate_exl(uint8_t *image, uint32_t total_sz, 
                           const dex_header_t *hdr,
                           const dex_import_t *imp,
                           const dex_reloc_t  *rel,
                           const dex_symbol_t *symtab,
                           const char *strtab,
                           const char *self_name)
{
    if (hdr->import_table_count > MAX_EXL_IMPORTS) 
    {
        printf("[EXL] too many imports: %u\n", hdr->import_table_count);
    
        return -1;
    }

    void *import_ptrs[MAX_EXL_IMPORTS];

    DDBG("--- IMPORTS DEBUG ---\n");
    for (uint32_t i = 0; i < hdr->import_table_count; ++i) 
    {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;
        void *p = NULL;

        // Check if it's an internal symbol
        if (exl_name_equals(exl, self_name)) 
        {
            p = resolve_local_symbol(hdr, symtab, strtab, image, sym);
            
            if (p)
            {
                DDBG("[EXL] resolved locally %s:%s -> %p\n", exl, sym, p);
            }
        }

        if (!p && is_loading(exl)) 
        {
            // Avoid recursion
            p = resolve_local_symbol(hdr, symtab, strtab, image, sym);
        }

        if (!p) 
        {
            p = resolve_exl_symbol(exl, sym);
        }

        if (!p && !exl_name_equals(exl, self_name)) 
        {
            if (!load_exl(file_table, exl)) 
            {
                printf("[EXL] cannot load dependency: %s\n", exl);
            
                return -2;
            }
            
            p = resolve_exl_symbol(exl, sym);
        }

        if (!p) 
        {
            printf("[EXL] unresolved %s:%s\n", exl, sym);
        
            return -3;
        }

        if (ptr_in_range(p, image, total_sz)) 
        {
            printf("[EXL] FATAL ERROR: import '%s' resolves inside EXL image (%p)\n", sym, p);
            
            return -4;
        }

        import_ptrs[i] = p;
        DDBG("[%u] %s:%s -> %p\n", i, exl, sym, p);
    }
    DDBG("----------------------\n");

    // Relocactions, make pages RW before, RX after 
    // (This is enforced in load_exl)
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i) 
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (!range_ok(off, 4, total_sz)) 
        {
            printf("[EXL] reloc OOR: off=0x%08x (total=%u)\n", off, total_sz);
        
            return -5;
        }

        uint8_t *target = image + off;
        uint32_t site = (uint32_t)(image + off);
        uint32_t old = *(uint32_t*)target;

        switch (typ) 
        {
            case DEX_ABS32:
                if (idx >= hdr->import_table_count) 
                { 
                    printf("= idx OOR\n"); 
                    
                    return -6; 
                }
                *(uint32_t*)target = (uint32_t)import_ptrs[idx];
                
                break;
            case DEX_PC32: 
                {
                    if (idx >= hdr->import_table_count) 
                    { 
                        printf("= idx OOR\n"); 
                        
                        return -7; 
                    }
                    uint32_t target_addr = (uint32_t)import_ptrs[idx];
                    int32_t disp = (int32_t)target_addr - (int32_t)(site + 4);
                    *(int32_t*)target = disp;
                    
                    DDBG("site=%08x disp=%d ", site, disp);
                    break;
                }
            case DEX_RELATIVE:
                *(uint32_t*)target = old + (uint32_t)image;
                break;

            default:
                printf("= UNKNOWN\n");
                
                return -8;
        }

        DDBG("new=0x%08x\n", *(uint32_t*)target);
    }

    return 0;
}

// EXL Loader
const exl_t* load_exl(const FileTable *ft, const char *exl_name)
{
    if (exl_count >= MAX_EXL_FILES) 
    {
        printf("[EXL] ERROR: out of slots\n");
    
        return NULL;
    }

    char tmp_name[EXL_NAME_LENGTH];
    canon_exl_name(exl_name, tmp_name, sizeof(tmp_name));

    // Check if it's already loaded
    for (size_t i = 0; i < exl_count; ++i) 
    {
        if (exl_name_equals(exl_files[i].name, tmp_name)) 
        {
            return &exl_files[i];
        }
    }

    if (is_loading(tmp_name)) 
    {
        DDBG("[EXL] already loading '%s' – skip\n", tmp_name);
    
        return NULL;
    }
    
    push_loading(tmp_name);

    // Set the name to /system/exls/<name>
    char path[EXL_NAME_LENGTH * 2];
    snprintf(path, sizeof(path), "/system/exls/%s", tmp_name);

    int fidx = find_entry_by_path(ft, path);
    if (fidx < 0) 
    {
        printf("[EXL] not found: %s\n", path);
        pop_loading(tmp_name);
    
        return NULL;
    }
    
    const FileEntry *fe = &ft->entries[fidx];

    uint8_t *filebuf = kmalloc(fe->file_size_bytes);
    if (!filebuf) 
    {
        printf("[EXL] kmalloc filebuf fail (%u)\n", fe->file_size_bytes);
        pop_loading(tmp_name);
    
        return NULL;
    }
    
    int rbytes = read_file(ft, path, filebuf);
    if (rbytes < 0) 
    {
        printf("[EXL] read fail: %s\n", path);
        kfree(filebuf); 
        pop_loading(tmp_name); 
        
        return NULL;
    }
    
    uint32_t fsz = (uint32_t)rbytes;

    if (!range_ok(0, sizeof(dex_header_t), fsz)) 
    {
        printf("[EXL] file too small for header\n");
        kfree(filebuf); 
        pop_loading(tmp_name); 
        
        return NULL;
    }

    const dex_header_t *hdr = (const dex_header_t*)filebuf;
    if (hdr->magic != DEX_MAGIC) 
    {
        printf("[EXL] bad magic in %s (0x%08x)\n", path, hdr->magic);
        kfree(filebuf); 
        pop_loading(tmp_name); 
        
        return NULL;
    }

    debug_print_hdr(hdr);

    // Section bounds
    if (!range_ok(hdr->text_offset,   hdr->text_size,   fsz) ||
        !range_ok(hdr->rodata_offset, hdr->rodata_size, fsz) ||
        !range_ok(hdr->data_offset,   hdr->data_size,   fsz)) 
    {
        printf("[EXL] section range OOR (fsz=%u)\n", fsz);
        kfree(filebuf); 
        pop_loading(tmp_name); 
        
        return NULL;
    }

    if ((hdr->import_table_count && !range_ok(hdr->import_table_offset, hdr->import_table_count * sizeof(dex_import_t), fsz)) ||
        (hdr->reloc_table_count  && !range_ok(hdr->reloc_table_offset,  hdr->reloc_table_count  * sizeof(dex_reloc_t),  fsz)) ||
        (hdr->symbol_table_count && !range_ok(hdr->symbol_table_offset, hdr->symbol_table_count * sizeof(dex_symbol_t), fsz)) ||
        (hdr->strtab_size        && !range_ok(hdr->strtab_offset,       hdr->strtab_size,                                fsz))) 
    {
        printf("[EXL] table range OOR\n");
        kfree(filebuf); 
        pop_loading(tmp_name); 
        
        return NULL;
    }

    const dex_symbol_t *symtab = (const dex_symbol_t*)(filebuf + hdr->symbol_table_offset);
    const char *strtab = (const char*)(filebuf + hdr->strtab_offset);

    // Allocate user image
    uint32_t text_sz = hdr->text_size;
    uint32_t ro_sz = hdr->rodata_size;
    uint32_t data_sz = hdr->data_size;
    uint32_t bss_sz = hdr->bss_size;

    uint32_t total_sz = PAGE_ALIGN_UP(text_sz) + PAGE_ALIGN_UP(ro_sz) + PAGE_ALIGN_UP(data_sz + bss_sz);
    uint8_t *image = umalloc(total_sz);

    if (!image) 
    {
        printf("[EXL] umalloc(%u) fail\n", total_sz);
        kfree(filebuf); 
        pop_loading(tmp_name); 
        
        return NULL;
    }

    // Make everything RW+USER during copy/relocs
    paging_update_flags((uint32_t)image, total_sz, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    // Copy sections
    memcpy(image + hdr->text_offset, filebuf + hdr->text_offset, text_sz);
    memcpy(image + hdr->rodata_offset, filebuf + hdr->rodata_offset, ro_sz);
    memcpy(image + hdr->data_offset, filebuf + hdr->data_offset, data_sz);
    memset(image + hdr->data_offset + data_sz, 0, bss_sz);

    const dex_import_t *imp = (const dex_import_t*)(filebuf + hdr->import_table_offset);
    const dex_reloc_t *rel = (const dex_reloc_t *)(filebuf + hdr->reloc_table_offset);

#ifdef DIFF_DEBUG
    // Verify that the area is RWU before relocations
    paging_dump_range((uint32_t)(image + hdr->text_offset), PAGE_ALIGN_UP(text_sz));
#endif

    if (do_relocate_exl(image, total_sz, hdr, imp, rel, symtab, strtab, tmp_name) != 0) 
    {
        printf("[EXL] relocation failed for %s\n", tmp_name);
        kfree(filebuf); 
        pop_loading(tmp_name); 
        
        return NULL;
    }

    // Lock .text to RX
    paging_update_flags((uint32_t)(image + hdr->text_offset), PAGE_ALIGN_UP(text_sz), 0, PAGE_RW);
    paging_set_user((uint32_t)image, total_sz);

    // Sanity check, make sure all pages are user
    if (paging_check_user_range((uint32_t)image, total_sz) != 0) 
    {
        printf("[EXL] WARN: not all pages are USER\n");
    }

    // Copy symbol/strtab to resolve 
    dex_symbol_t *symtab_copy = NULL;
    char *strtab_copy = NULL;

    if (hdr->symbol_table_count) 
    {
        symtab_copy = kmalloc(hdr->symbol_table_count * sizeof(dex_symbol_t));
        
        if (!symtab_copy) 
        { 
            printf("[EXL] symtab alloc fail\n"); 
            kfree(filebuf); 
            pop_loading(tmp_name); 
            
            return NULL; 
        }
        
        memcpy(symtab_copy, (const void*)(filebuf + hdr->symbol_table_offset), hdr->symbol_table_count * sizeof(dex_symbol_t));
    }
    
    if (hdr->strtab_size) 
    {
        strtab_copy = kmalloc(hdr->strtab_size);
        
        if (!strtab_copy) 
        { 
            if (symtab_copy)
            { 
                kfree(symtab_copy); 
                printf("[EXL] strtab alloc fail\n"); 
                kfree(filebuf); 
                pop_loading(tmp_name); 
                
                return NULL; 
            }
        }
        
        memcpy(strtab_copy, (const void*)(filebuf + hdr->strtab_offset), hdr->strtab_size);
    }

    // Register loaded EXL
    exl_t *lib = &exl_files[exl_count++];
    memset(lib, 0, sizeof(*lib));
    strncpy(lib->name, tmp_name, sizeof(lib->name) - 1);
    
    lib->image_base = image;
    lib->image_size = total_sz;
    lib->header = NULL;           // Do not keep the file header in RAM
    lib->symbol_table = symtab_copy;
    lib->symbol_count = hdr->symbol_table_count;
    lib->strtab = strtab_copy;

    kfree(filebuf);
    pop_loading(tmp_name);

    DDBG("[EXL] loaded '%s' base=%p size=%u (.text RX)\n", lib->name, lib->image_base, lib->image_size);

#ifdef DIFF_DEBUG
    // Dump first instruction at entry
    uint32_t entry = (uint32_t)image + hdr->entry_offset;
    dump_pde_pte(entry);
    DDBG("[EXL] entry VA=%08x (off=0x%x)\n", entry, hdr->entry_offset);
#endif

    return lib;
}

