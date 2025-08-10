#include "dex/dex.h"
#include "dex/exl.h"
#include "diff.h"
#include "string.h"
#include "stdint.h"
#include "stddef.h"
#include "stdio.h"
#include "console.h"
#include "paging.h"
#include "heap.h"

extern void enter_user_mode(uint32_t entry, uint32_t user_stack_top);

extern FileTable *file_table;

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x)  (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

static int ptr_in_range(void *p, uint8_t *base, uint32_t size) 
{
    uint32_t v = (uint32_t)p;
    uint32_t b = (uint32_t)base;
    
    return (v >= b) && (v < b + size);
}

static uint8_t* build_user_exit_stub(uint32_t entry_va)
{
    // 16–32 bytes is enough
    uint8_t *stub = (uint8_t*)umalloc(32);
    
    if (!stub) 
    {
        printf("[DEX] stub alloc failed\n");
        
        return NULL;
    }

    paging_update_flags((uint32_t)stub, 32, PAGE_PRESENT|PAGE_USER|PAGE_RW, 0);

    uint8_t *p = stub;

    *p++ = 0xE8;
    int32_t rel = (int32_t)entry_va - (int32_t)((uint32_t)stub + 5);
    *(int32_t*)p = rel; 
    
    p += 4;
    *p++ = 0x31; 
    *p++ = 0xC0;
    *p++ = 0x31; 
    *p++ = 0xDB;
    *p++ = 0xCD; 
    *p++ = 0x66;
    *p++ = 0xF4;

    paging_set_user((uint32_t)stub, 32);

    DDBG("[DEX] stub@%p -> call %08x (rel=%d)\n", stub, entry_va, rel);
    
    return stub;
}

// Load a DEX program 
int dex_load(const void *file_data, size_t file_size, dex_executable_t *out) 
{
    if (!file_data || file_size < sizeof(dex_header_t))
    {
        return -1;
    }

    const dex_header_t *hdr = (const dex_header_t*)file_data;
    
    if (hdr->magic != DEX_MAGIC) 
    {
        printf("[DEX] Invalid DEX file!\n");
     
        return -2;
    }

    uint32_t text_sz = hdr->text_size;
    uint32_t ro_sz   = hdr->rodata_size;
    uint32_t data_sz = hdr->data_size;
    uint32_t bss_sz  = hdr->bss_size;

    uint32_t total_sz = PAGE_ALIGN_UP(text_sz)
                      + PAGE_ALIGN_UP(ro_sz)
                      + PAGE_ALIGN_UP(data_sz + bss_sz);

    uint8_t *image = umalloc(total_sz);
    
    if (!image) 
    {
        printf("[DEX] Unable to allocate %u byte(s) for program.\n", total_sz);
    
        return -3;
    }

    // Temporarily mark User during copy/relocations
    paging_set_user((uint32_t)image, total_sz);
    paging_flush_tlb();

    // Copy sections
    memcpy(image + hdr->text_offset, (const uint8_t*)file_data + hdr->text_offset, text_sz);
    memcpy(image + hdr->rodata_offset, (const uint8_t*)file_data + hdr->rodata_offset, ro_sz);
    memcpy(image + hdr->data_offset, (const uint8_t*)file_data + hdr->data_offset, data_sz);
    memset(image + hdr->data_offset + data_sz, 0, bss_sz);

    // Tables
    const dex_import_t *imp = (const dex_import_t*)((const uint8_t*)file_data + hdr->import_table_offset);
    const dex_reloc_t *rel = (const dex_reloc_t*)((const uint8_t*)file_data + hdr->reloc_table_offset);
    const char *strtab = (const char*)((const uint8_t*)file_data + hdr->strtab_offset);

    void *import_ptrs[256];

    if (hdr->import_table_count > 256) 
    {
        printf("[DEX] Too many imports\n");
        
        return -4;
    }

    // Resolve imports via EXLs
    for (size_t i = 0; i < hdr->import_table_count; ++i) 
    {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;

        // Load EXL if symbol is not resolved yet
        if (!resolve_exl_symbol(exl, sym)) 
        {
            if (!load_exl(file_table, exl)) 
            {
                printf("[DEX] ERROR: Failed to load EXL: %s\n", exl);
                
                return -5;
            }
        }

        import_ptrs[i] = resolve_exl_symbol(exl, sym);
        
        if (!import_ptrs[i]) 
        {
            printf("[DEX] ERROR: Unresolved symbol '%s' in '%s'\n", sym, exl);
          
            return -6;
        }

        // Sanity Check: import must not point inside the loaded program image
        if (ptr_in_range(import_ptrs[i], image, total_sz)) 
        {
            printf("[DEX] FATAL ERROR: import '%s' resolves inside program image (0x%08x)\n", sym, (uint32_t)import_ptrs[i]);
            
            return -7;
        }
    }

    // Apply relocations
    for (size_t i = 0; i < hdr->reloc_table_count; ++i) 
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (off + 4 > total_sz) 
        {
            printf("[DEX] Relocation OOR: off=0x%08x\n", off);
            
            continue;
        }

        uint8_t *target = image + off;
        uint32_t reloc_addr = (uint32_t)(image + off);

        switch (typ) 
        {
            case DEX_ABS32:
                *(uint32_t*)target = (uint32_t)import_ptrs[idx];
                break;
            case DEX_PC32: 
                { 
                    // call/jmp disp32 = import - (site+4))
                    uint32_t import_addr = (uint32_t)import_ptrs[idx];
                    int32_t disp = (int32_t)import_addr - (int32_t)(reloc_addr + 4);

                    DDBG("[PC32] off=%08x import=%08x site=%08x disp=%d\n", off, import_addr, reloc_addr, disp);

                    // Make sure a DEX offset doesn't go low -4
                    if (disp == -4) 
                    {
                        printf("[RELOC] FATAL ERROR: PC32 disp=-4 at off=0x%08x (import=0x%08x)\n", off, import_addr);
                        return -8;
                    }

                    *(uint32_t*)target = (uint32_t)disp;
                    break;
                }
            case 8: // DEX_RELATIVE: *(u32*)target += image_base
                *(uint32_t*)target += (uint32_t)image;
                break;
            default:
                printf("[DEX] Unknown relocation type %u at off=0x%08x\n", typ, off);
                break;
        }
    }

    // Lock .text to RX and mark User
    paging_update_flags((uint32_t)(image + hdr->text_offset), PAGE_ALIGN_UP(text_sz), 0, PAGE_RW);
    paging_set_user((uint32_t)image, total_sz);

    // Entrypoint = image_base + entry_offset
    void (*entry)(void) = (void(*)(void))((uint32_t)image + hdr->entry_offset);

#ifdef DIFF_DEBUG
    hexdump_bytes((void*)((uint32_t)image + hdr->entry_offset), 64);
#endif

    out->image_base = image;
    out->header = (dex_header_t*)file_data; // Points to the buffer where the header resides
    out->dex_entry  = entry;
    out->image_size = total_sz;

    return 0;
}

// Start the program
void dex_run(const FileTable *ft, const char *path) 
{
    int idx = find_entry_by_path(ft, path);

    if (idx < 0) 
    {
        printf("[DEX] ERROR: File not found: %s\n", path);
    
        return;
    }

    const FileEntry *fe = &ft->entries[idx];
    uint8_t *buf = kmalloc(fe->file_size_bytes);
    
    if (!buf) 
    {
        printf("[DEX] ERROR: Unable to allocate %u bytes for the program!\n", fe->file_size_bytes);
    
        return;
    }

    if (read_file(ft, path, buf) < 0) 
    {
        printf("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buf);
    
        return;
    }

    dex_executable_t dex;
    if (dex_load(buf, fe->file_size_bytes, &dex) == 0) 
    {
        uint32_t ustk_base = (uint32_t)umalloc(16 * 1024);
        
        if (!ustk_base) 
        { 
            printf("[DEX] ERROR: Unable to allocate stack for program!\n"); 
            kfree(buf); 
            
            return; 
        }
        uint32_t user_sp = ustk_base + 16*1024 - 16;

        // Build C stub
        uint8_t *stub = build_user_exit_stub((uint32_t)dex.dex_entry);
        
        if (!stub) 
        { 
            printf("[DEX] ERROR: No stub found!\n"); 
            kfree(buf); 
            
            return; 
        }

#ifdef DIFF_DEBUG
        // Debug: verify the stack really is P=1 RW=1 U=1
        paging_dump_range(user_sp - 64, 128);
        paging_check_user_range(user_sp - 64, 128);
        DDBG("[DEX] jump to stub=%p, entry=%p, esp=%08x\n", stub, dex.dex_entry, user_sp);
#endif

        enter_user_mode((uint32_t)stub, user_sp);
    }

    kfree(buf);
}
