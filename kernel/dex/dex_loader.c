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

// file_table comes from diff.c
extern FileTable *file_table;

// Page-align helper (kept here in case it's not defined elsewhere)
#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x)  (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

// Debug macro: prints only when DIFF_DEBUG is defined
#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

// Small sanity helper: check if pointer lies within [base, base+size)
static int ptr_in_range(void *p, uint8_t *base, uint32_t size) {
    uint32_t v = (uint32_t)p;
    uint32_t b = (uint32_t)base;
    return (v >= b) && (v < b + size);
}

static uint8_t* build_user_exit_stub(uint32_t entry_va)
{
    // 16–32 bytes is enough
    uint8_t *stub = (uint8_t*)umalloc(32);
    if (!stub) {
        printf("[DEX] stub alloc failed\n");
        return NULL;
    }

    // Make RW+USER for safety (execute is implicit on i386 without NX)
    paging_update_flags((uint32_t)stub, 32, PAGE_PRESENT|PAGE_USER|PAGE_RW, 0);

    uint8_t *p = stub;

    // E8 <rel32>   ; call entry
    *p++ = 0xE8;
    int32_t rel = (int32_t)entry_va - (int32_t)((uint32_t)stub + 5);
    *(int32_t*)p = rel; p += 4;

    // 31 C0        ; xor eax,eax  (SYSTEM_EXIT = 0)
    *p++ = 0x31; *p++ = 0xC0;

    // 31 DB        ; xor ebx,ebx  (exit code = 0)
    *p++ = 0x31; *p++ = 0xDB;

    // CD 66        ; int 0x66
    *p++ = 0xCD; *p++ = 0x66;

    // F4           ; hlt (fallback if int does not return)
    *p++ = 0xF4;

    // (optional) EB FE ; jmp $
    // *p++ = 0xEB; *p++ = 0xFE;

    // Mark as USER (keep RW, we do not care to make it RO here)
    paging_set_user((uint32_t)stub, 32);

    DDBG("[DEX] stub@%p -> call %08x (rel=%d)\n", stub, entry_va, rel);
    return stub;
}

// --------------------------------------------------------------------------
// Load a DEX program from memory and prepare it for execution
// Signature matches dex.h: int dex_load(const void*, size_t, dex_executable_t*)
// --------------------------------------------------------------------------
int dex_load(const void *file_data, size_t file_size, dex_executable_t *out) {
    if (!file_data || file_size < sizeof(dex_header_t))
        return -1;

    const dex_header_t *hdr = (const dex_header_t*)file_data;
    if (hdr->magic != DEX_MAGIC) {
        printf("[DEX] bad magic\n");
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
    if (!image) {
        printf("[DEX] umalloc(%u) fail\n", total_sz);
        return -3;
    }

    // Temporarily mark USER during copy/relocs
    // paging_update_flags((uint32_t)image, total_sz, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    paging_set_user((uint32_t)image, total_sz);
    paging_flush_tlb();

    // Copy sections
    memcpy(image + hdr->text_offset,   (const uint8_t*)file_data + hdr->text_offset,   text_sz);
    memcpy(image + hdr->rodata_offset, (const uint8_t*)file_data + hdr->rodata_offset, ro_sz);
    memcpy(image + hdr->data_offset,   (const uint8_t*)file_data + hdr->data_offset,   data_sz);
    memset(image + hdr->data_offset + data_sz, 0, bss_sz);

    // Tables
    const dex_import_t *imp = (const dex_import_t*)((const uint8_t*)file_data + hdr->import_table_offset);
    const dex_reloc_t  *rel = (const dex_reloc_t*)((const uint8_t*)file_data + hdr->reloc_table_offset);
    const char *strtab      = (const char*)((const uint8_t*)file_data + hdr->strtab_offset);

    void *import_ptrs[256];
    if (hdr->import_table_count > 256) {
        printf("[DEX] too many imports\n");
        return -4;
    }

    // Resolve imports via EXL libraries (uses global file_table)
    for (size_t i = 0; i < hdr->import_table_count; ++i) {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;

        // Load EXL if symbol not yet resolved
        if (!resolve_exl_symbol(exl, sym)) {
            if (!load_exl(file_table, exl)) {
                printf("[DEX] ERROR: Failed to load EXL: %s\n", exl);
                return -5;
            }
        }

        import_ptrs[i] = resolve_exl_symbol(exl, sym);
        if (!import_ptrs[i]) {
            printf("[DEX] ERROR: Unresolved symbol '%s' in '%s'\n", sym, exl);
            return -6;
        }

        // Sanity: import must not point inside the loaded program image
        if (ptr_in_range(import_ptrs[i], image, total_sz)) {
            printf("[DEX] FATAL: import '%s' resolves inside program image (0x%08x)\n",
                   sym, (uint32_t)import_ptrs[i]);
            return -7;
        }
    }

    // Apply relocations
    for (size_t i = 0; i < hdr->reloc_table_count; ++i) {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (off + 4 > total_sz) {
            printf("[DEX] Reloc OOR: off=0x%08x\n", off);
            continue;
        }

        uint8_t *target = image + off;
        uint32_t reloc_addr = (uint32_t)(image + off);

        switch (typ) {
            case 0: // DEX_ABS32
                *(uint32_t*)target = (uint32_t)import_ptrs[idx];
                break;

            case 2: { // DEX_PC32 (safe: call/jmp disp32 = import - (site+4))
                uint32_t import_addr = (uint32_t)import_ptrs[idx];
                int32_t disp = (int32_t)import_addr - (int32_t)(reloc_addr + 4);

                DDBG("[PC32] off=%08x import=%08x site=%08x disp=%d\n",
                     off, import_addr, reloc_addr, disp);

                // Catch a broken DEX offset that yields call -4
                if (disp == -4) {
                    printf("[RELOC][FATAL] PC32 disp=-4 at off=0x%08x (import=0x%08x)\n", off, import_addr);
                    return -8;
                }

                *(uint32_t*)target = (uint32_t)disp;
                break;
            }

            case 8: // DEX_RELATIVE: *(u32*)target += image_base
                *(uint32_t*)target += (uint32_t)image;
                break;

            default:
                printf("[DEX] Unknown reloc type %u at off=0x%08x\n", typ, off);
                break;
        }
    }

    // Lock .text to RX and mark USER
    paging_update_flags((uint32_t)(image + hdr->text_offset), PAGE_ALIGN_UP(text_sz), 0, PAGE_RW);
    paging_set_user((uint32_t)image, total_sz);

    // Entrypoint = image_base + entry_offset
    void (*entry)(void) = (void(*)(void))((uint32_t)image + hdr->entry_offset);

#ifdef DIFF_DEBUG
    hexdump_bytes((void*)((uint32_t)image + hdr->entry_offset), 64);
#endif

    out->image_base = image;
    out->header     = (dex_header_t*)file_data; // points to the buffer where the header resides
    out->dex_entry  = entry;
    out->image_size = total_sz;

    return 0;
}

// Simple runner according to dex.h signature
void dex_run(const FileTable *ft, const char *path) {
    int idx = find_entry_by_path(ft, path);
    if (idx < 0) {
        printf("[DEX] File not found: %s\n", path);
        return;
    }

    const FileEntry *fe = &ft->entries[idx];
    uint8_t *buf = kmalloc(fe->file_size_bytes);
    if (!buf) {
        printf("[DEX] kmalloc fail for %u bytes\n", fe->file_size_bytes);
        return;
    }

    if (read_file(ft, path, buf) < 0) {
        printf("[DEX] Failed to read file: %s\n", path);
        kfree(buf);
        return;
    }

    dex_executable_t dex;
    if (dex_load(buf, fe->file_size_bytes, &dex) == 0) {
        uint32_t ustk_base = (uint32_t)umalloc(16 * 1024);
        if (!ustk_base) { printf("[DEX] umalloc stack failed\n"); kfree(buf); return; }
        uint32_t user_sp = ustk_base + 16*1024 - 16;

        // Build a stub that calls entry and then does exit(0)
        uint8_t *stub = build_user_exit_stub((uint32_t)dex.dex_entry);
        if (!stub) { printf("[DEX] No stub found!\n"); kfree(buf); return; }

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

