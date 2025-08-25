#include "dex/dex.h"
#include "dex/exl.h"
#include "system/process.h"
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

// Paging and process helpers
extern uint32_t paging_new_address_space(void);
extern void paging_switch_address_space(uint32_t cr3);
extern void paging_destroy_address_space(uint32_t cr3);

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

// Check if address is in user range
static inline int is_user_va(uint32_t a)
{
    return (a >= USER_MIN) && (a < USER_MAX);
}

// Safe range check for file sections
static inline int in_range(uint32_t off, uint32_t sz, uint32_t max)
{
    if (sz == 0)
    {
        return 1;
    }
    if (off > max)
    {
        return 0;
    }
    if (max - off < sz)
    {
        return 0;
    }
    return 1;
}

// Check if pointer lies inside an image buffer
static int ptr_in_image(const void *p, const uint8_t *base, uint32_t size)
{
    uint32_t v = (uint32_t)p;
    uint32_t b = (uint32_t)base;

    return (v >= b) && (v < b + size);
}

// Read CR3
static inline uint32_t read_cr3_local(void)
{
    uint32_t v;

    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));

    return v;
}

// Exit stub and user stack

static uint8_t *build_user_exit_stub(uint32_t entry_va)
{
    // Small stub that calls entry and then exits
    uint8_t *stub = (uint8_t *)umalloc(32);
    if (!stub)
    {
        printf("[DEX] Stub alloc failed\n");
        return NULL;
    }

    paging_update_flags(
        (uint32_t)stub,
        32,
        PAGE_PRESENT | PAGE_USER | PAGE_RW,
        0
    );

    uint8_t *p = stub;

    *p++ = 0xE8; // call rel32
    int32_t rel = (int32_t)entry_va - (int32_t)((uint32_t)stub + 5);
    *(int32_t *)p = rel;
    p += 4;

    *p++ = 0x31; *p++ = 0xC0; // xor eax, eax
    *p++ = 0x31; *p++ = 0xDB; // xor ebx, ebx
    *p++ = 0xCD; *p++ = 0x66; // int 0x66
    *p++ = 0xF4;              // hlt safety

    paging_set_user((uint32_t)stub, 32);

    DDBG("[DEX] stub@%p -> call %08x rel=%d\n", stub, entry_va, rel);
    return stub;
}

static uint32_t build_user_stack(
    const char *prog_path,
    int argc_in,
    char *const argv_in[]
)
{
    const uint32_t STK_SZ = 64 * 1024;

    uint8_t *stk = umalloc(STK_SZ);
    if (!stk)
    {
        printf("[DEX] Stack alloc failed %u bytes\n", STK_SZ);
        return 0;
    }

    paging_update_flags(
        (uint32_t)stk,
        STK_SZ,
        PAGE_PRESENT | PAGE_USER | PAGE_RW,
        0
    );

    int argc = (argc_in > 0 && argv_in) ? argc_in : 1;

    uint32_t *argv_ptrs = (uint32_t *)kmalloc(
        sizeof(uint32_t) * (size_t)argc
    );
    if (!argv_ptrs)
    {
        printf("[DEX] argv_ptrs alloc failed\n");
        return 0;
    }

    uint32_t sp = (uint32_t)stk + STK_SZ;
    uint32_t base = (uint32_t)stk;

    // Push strings in reverse
    for (int i = argc - 1; i >= 0; --i)
    {
        const char *src =
            (argc_in > 0 && argv_in) ? argv_in[i] : (i == 0 ? prog_path : "");

        size_t len = strlen(src) + 1;

        if (sp < base + (uint32_t)len + 64)
        {
            printf("[DEX] Stack overflow while building argv\n");
            kfree(argv_ptrs);
            return 0;
        }

        sp -= (uint32_t)len;
        memcpy((void *)sp, src, len);
        argv_ptrs[i] = sp;
    }

    sp &= ~0xFu; // 16 byte alignment

    // envp terminator
    if (sp < base + 4)
    {
        kfree(argv_ptrs);
        return 0;
    }
    sp -= 4;
    *(uint32_t *)sp = 0;

    // argv array and terminator
    uint32_t argv_bytes = (uint32_t)((argc + 1) * sizeof(uint32_t));
    if (sp < base + argv_bytes)
    {
        kfree(argv_ptrs);
        return 0;
    }
    sp -= argv_bytes;

    uint32_t argv_array = sp;

    for (int i = 0; i < argc; ++i)
    {
        ((uint32_t *)argv_array)[i] = argv_ptrs[i];
    }
    ((uint32_t *)argv_array)[argc] = 0;

    // push argv pointer
    if (sp < base + 4)
    {
        kfree(argv_ptrs);
        return 0;
    }
    sp -= 4;
    *(uint32_t *)sp = argv_array;

    // push argc
    if (sp < base + 4)
    {
        kfree(argv_ptrs);
        return 0;
    }
    sp -= 4;
    *(uint32_t *)sp = (uint32_t)argc;

    kfree(argv_ptrs);

    DDBG("[DEX] stack built base=%08x top=%08x size=%u\n", base, sp, STK_SZ);
    return sp;
}

// Imports and relocations

static int resolve_imports_user(
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const char *strtab,
    void **out_ptrs,
    uint8_t *image,
    uint32_t image_sz
)
{
    if (hdr->import_table_count > 256)
    {
        printf("[DEX] Too many imports (%u)\n", hdr->import_table_count);
        return -1;
    }

    for (uint32_t i = 0; i < hdr->import_table_count; ++i)
    {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;

        // Try resolve from already loaded EXL
        void *addr = resolve_exl_symbol(exl, sym);

        // Load EXL lazily if missing
        if (!addr)
        {
            const exl_t *lib = load_exl(file_table, exl);
            if (!lib)
            {
                printf("[DEX] Cannot load EXL %s\n", exl);
                return -2;
            }
            addr = resolve_exl_symbol(exl, sym);
        }

        if (!addr)
        {
            printf("[DEX] Unresolved import %s:%s\n", exl, sym);
            return -3;
        }

        // Forbid pointers into the image to prevent self aliasing
        if (ptr_in_image(addr, image, image_sz))
        {
            printf("[DEX] Import %s:%s resolves inside image %p\n", exl, sym, addr);
            return -4;
        }

        // Enforce user address space for imports
        if (!is_user_va((uint32_t)addr))
        {
            printf("[DEX] Import %s:%s -> kernel VA %p\n", exl, sym, addr);
            return -5;
        }

        out_ptrs[i] = addr;
        DDBG("[IMP] %s:%s -> %p\n", exl, sym, addr);
    }

    return 0;
}

static int relocate_image(
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const dex_reloc_t *rel,
    const char *strtab,
    uint8_t *image,
    uint32_t image_sz
)
{
    void **import_ptrs = NULL;

    if (hdr->import_table_count > 256)
    {
        printf("[DEX] Too many imports (%u)\n", hdr->import_table_count);
        
        return -1;
    }

    // Allocate import pointer array if needed
    if (hdr->import_table_count)
    {
        size_t bytes = (size_t)hdr->import_table_count * sizeof(void *);
        import_ptrs = (void **)kmalloc(bytes);
        
        if (!import_ptrs)
        {
            printf("[DEX] kmalloc import_ptrs=%u failed\n", (unsigned)bytes);

            return -2;
        }

        memset(import_ptrs, 0, bytes);
    }

    // Resolve imports against EXLs
    if (resolve_imports_user(hdr, imp, strtab, import_ptrs, image, image_sz) != 0)
    {
        if (import_ptrs)
        {
            kfree(import_ptrs);
        }

        return -3;
    }

    DDBG("[RELOC] Applying %u relocations\n", hdr->reloc_table_count);

    // Apply relocations
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (off > image_sz || image_sz - off < 4)
        {
            printf("[DEX] Reloc out of range off=0x%08x image=%u\n", off, image_sz);

            if (import_ptrs)
            {
                kfree(import_ptrs);
            }

            return -4;
        }

        uint8_t *target = image + off;
        uint32_t old = *(uint32_t *)target;

        switch (typ)
        {
            case DEX_ABS32:
            {
                if (idx >= hdr->import_table_count)
                {
                    if (import_ptrs)
                    {
                        kfree(import_ptrs);
                    }

                    return -5;
                }
                *(uint32_t *)target = (uint32_t)import_ptrs[idx];

                DDBG("[REL] ABS32 @%08x %08x -> %08x S=%08x\n",
                     (uint32_t)(uintptr_t)target, old, *(uint32_t *)target, (uint32_t)import_ptrs[idx]);
                break;
            }

            case DEX_PC32:
            {
                if (idx >= hdr->import_table_count)
                {
                    if (import_ptrs)
                    {
                        kfree(import_ptrs);
                    }

                    return -6;
                }

                uint32_t S = (uint32_t)import_ptrs[idx];
                int32_t disp = (int32_t)S - (int32_t)((uint32_t)(uintptr_t)target + 4);
                *(int32_t *)target = disp;

                DDBG("[REL] PC32  @%08x P=%08x S=%08x disp=%d old=%08x new=%08x\n",
                     (uint32_t)(uintptr_t)target,
                     (uint32_t)(uintptr_t)target + 4,
                     S, disp, old, *(uint32_t *)target);

                break;
            }

            case DEX_RELATIVE:
            {
                uint32_t val = old + (uint32_t)image;
                *(uint32_t *)target = val;

                DDBG("[REL] REL   @%08x %08x -> %08x base=%08x\n",
                     (uint32_t)(uintptr_t)target, old, val, (uint32_t)image);

                break;
            }

            default:
            {
                printf("[DEX] Unknown reloc type=%u off=0x%08x old=%08x\n", typ, off, old);

                if (import_ptrs)
                {
                    kfree(import_ptrs);
                }

                return -11;
            }
        }

        DDBG("new=0x%08x\n", *(uint32_t *)target);
    }

    if (import_ptrs)
    {
        kfree(import_ptrs);
    }

    // Post check for kernel addresses in ABS32 slots
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t typ = rel[i].type;

        if (typ == DEX_ABS32)
        {
            uint32_t val = *(uint32_t *)(image + off);

            if (!is_user_va(val))
            {
                printf("[DEX] Post check ABS32 off=0x%08x -> kernel VA %08x\n", off, val);

                return -12;
            }
        }
    }

    return 0;
}

// Loader API
int dex_load(const void *file_data, size_t file_size, dex_executable_t *out)
{
    const dex_header_t *hdr;
    uint32_t text_sz;
    uint32_t ro_sz;
    uint32_t data_sz;
    uint32_t bss_sz;
    uint32_t entry_off;
    uint32_t max_end;
    uint32_t tmp;
    uint32_t total_sz;
    uint8_t *image;
    const dex_import_t *imp;
    const dex_reloc_t *rel;
    const char *stab;

    if (!file_data || file_size < sizeof(dex_header_t) || !out)
    {

        return -1;
    }

    hdr = (const dex_header_t *)file_data;

    // Validate magic
    if (hdr->magic != DEX_MAGIC)
    {
        printf("[DEX] Invalid DEX file\n");

        return -2;
    }

    // Validate section ranges inside file
    if (!in_range(hdr->text_offset,   hdr->text_size,   (uint32_t)file_size) ||
        !in_range(hdr->rodata_offset, hdr->rodata_size, (uint32_t)file_size) ||
        !in_range(hdr->data_offset,   hdr->data_size,   (uint32_t)file_size) ||
        !in_range(hdr->strtab_offset, hdr->strtab_size, (uint32_t)file_size))
    {
        printf("[DEX] Section offsets or sizes out of file\n");

        return -3;
    }

    // Validate entry inside .text
    if (!in_range(hdr->entry_offset, 1, (uint32_t)file_size) ||
        hdr->entry_offset < hdr->text_offset ||
        hdr->entry_offset >= hdr->text_offset + hdr->text_size)
    {
        printf("[DEX] Entry offset out of range off=0x%x\n", (unsigned)hdr->entry_offset);

        return -3;
    }

    // Cache sizes and compute total image span
    text_sz   = hdr->text_size;
    ro_sz     = hdr->rodata_size;
    data_sz   = hdr->data_size;
    bss_sz    = hdr->bss_size;
    entry_off = hdr->entry_offset;

    max_end = hdr->data_offset + data_sz + bss_sz;
    tmp = hdr->rodata_offset + ro_sz; if (tmp > max_end) max_end = tmp;
    tmp = hdr->text_offset   + text_sz; if (tmp > max_end) max_end = tmp;
    tmp = entry_off + 16u; if (tmp > max_end) max_end = tmp;

    total_sz = PAGE_ALIGN_UP(max_end);

    // Allocate user image
    image = (uint8_t *)umalloc(total_sz);
    if (!image)
    {
        printf("[DEX] Unable to allocate %u bytes for program\n", total_sz);

        return -4;
    }

    // Map as user and ensure fresh view
    paging_set_user((uint32_t)image, total_sz);
    paging_flush_tlb();

    // Copy sections and clear bss
    if (text_sz)
    {
        memcpy(image + hdr->text_offset,
               (const uint8_t *)file_data + hdr->text_offset,
               text_sz);
    }

    if (ro_sz)
    {
        memcpy(image + hdr->rodata_offset,
               (const uint8_t *)file_data + hdr->rodata_offset,
               ro_sz);
    }

    if (data_sz)
    {
        memcpy(image + hdr->data_offset,
               (const uint8_t *)file_data + hdr->data_offset,
               data_sz);
    }

    if (bss_sz)
    {
        memset(image + hdr->data_offset + data_sz, 0, bss_sz);
    }

    // Validate table windows
    if ((hdr->import_table_count &&
         !in_range(hdr->import_table_offset,
                   hdr->import_table_count * sizeof(dex_import_t),
                   (uint32_t)file_size)) ||
        (hdr->reloc_table_count  &&
         !in_range(hdr->reloc_table_offset,
                   hdr->reloc_table_count * sizeof(dex_reloc_t),
                   (uint32_t)file_size)) ||
        (hdr->strtab_size &&
         !in_range(hdr->strtab_offset,
                   hdr->strtab_size,
                   (uint32_t)file_size)))
    {
        printf("[DEX] Table offsets or sizes out of file\n");
        kfree(image);

        return -5;
    }

    // Table pointers
    imp  = (const dex_import_t *)((const uint8_t *)file_data + hdr->import_table_offset);
    rel  = (const dex_reloc_t  *)((const uint8_t *)file_data + hdr->reloc_table_offset);
    stab = (const char         *)((const uint8_t *)file_data + hdr->strtab_offset);

#ifdef DIFF_DEBUG
    DDBG("=== DEX HEADER DEBUG ===\n");
    DDBG("magic=0x%08x ver=%u.%u\n", hdr->magic, hdr->version_major, hdr->version_minor);
    DDBG("entry_off=0x%08x\n", hdr->entry_offset);
    DDBG(".text off=0x%08x sz=%u\n", hdr->text_offset, hdr->text_size);
    DDBG(".ro   off=0x%08x sz=%u\n", hdr->rodata_offset, hdr->rodata_size);
    DDBG(".data off=0x%08x sz=%u\n", hdr->data_offset, hdr->data_size);
    DDBG(".bss  sz=%u\n", hdr->bss_size);
    DDBG("import off=0x%08x cnt=%u\n", hdr->import_table_offset, hdr->import_table_count);
    DDBG("reloc  off=0x%08x cnt=%u\n", hdr->reloc_table_offset,  hdr->reloc_table_count);
    DDBG("========================\n");
#endif

    // Apply relocations and imports
    if (relocate_image(hdr, imp, rel, stab, image, total_sz) != 0)
    {
        kfree(image);

        return -6;
    }

    // Make .text read execute
    if (text_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->text_offset),
                            PAGE_ALIGN_UP(text_sz),
                            0,
                            PAGE_RW);
    }

    // Ensure .data and .bss are writable
    if (data_sz || bss_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->data_offset),
                            PAGE_ALIGN_UP(data_sz + bss_sz),
                            PAGE_PRESENT | PAGE_USER | PAGE_RW,
                            0);
    }

    // Reassert user mapping
    paging_set_user((uint32_t)image, total_sz);

    // Fill output
    out->image_base = image;
    out->header     = (dex_header_t *)file_data;
    out->dex_entry  = (void (*)(void))((uint32_t)image + entry_off);
    out->image_size = total_sz;

#ifdef DIFF_DEBUG
    hexdump_bytes((void *)((uint32_t)image + entry_off), 64);
    DDBG("[DEX] entry VA=%08x off=0x%x\n", (uint32_t)image + entry_off, entry_off);
#endif

    return 0;
}

// Run DEX inside current process address space
int dex_run(const FileTable *ft, const char *path, int argc, char **argv)
{
    int file_index;
    const FileEntry *fe;
    uint8_t *buffer;
    dex_executable_t dex;
    int rc;
    uint32_t user_sp;
    uint8_t *stub;

    if (!ft || !path || !path[0])
    {

        return -1;
    }

    // Locate file
    file_index = find_entry_by_path(ft, path);
    if (file_index < 0)
    {
        printf("[DEX] ERROR: File not found: %s\n", path);

        return -1;
    }

    fe = &ft->entries[file_index];
    if (!fe->file_size_bytes)
    {
        printf("[DEX] ERROR: Empty file: %s\n", path);

        return -2;
    }

    // Read whole file into temporary buffer
    buffer = (uint8_t *)kmalloc(fe->file_size_bytes);
    if (!buffer)
    {
        printf("[DEX] ERROR: Unable to allocate %u bytes\n", fe->file_size_bytes);

        return -3;
    }

    if (read_file(ft, path, buffer) < 0)
    {
        printf("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buffer);

        return -4;
    }

    // Load image into user space
    rc = dex_load(buffer, fe->file_size_bytes, &dex);
    if (rc != 0)
    {
        kfree(buffer);

        return rc;
    }

    // Build initial user stack
    user_sp = build_user_stack(path, argc, argv);
    if (!user_sp)
    {
        kfree(buffer);

        return -5;
    }

    // Build small exit stub that calls int 0x66
    stub = build_user_exit_stub((uint32_t)dex.dex_entry);
    if (!stub)
    {
        printf("[DEX] ERROR: No stub found\n");
        kfree(buffer);

        return -6;
    }

    // Ensure stub is user present and writable while patching
    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    DDBG("[DEX] run: entry=%08x stub=%08x sp=%08x (no process)\n",
         (uint32_t)dex.dex_entry, (uint32_t)stub, user_sp);

    // Jump to user mode
    enter_user_mode((uint32_t)stub, user_sp);

    // Not reached in normal flow
    kfree(buffer);

    return 0;
}

// Spawn new process and load DEX into child address space
int dex_spawn_process(const FileTable *ft, const char *path, int argc, char **argv)
{
    int file_index;
    const FileEntry *fe;
    uint8_t *buffer;
    uint32_t cr3_parent;
    uint32_t cr3_child;
    dex_executable_t dex;
    int load_rc;
    uint32_t user_sp;
    uint32_t entry_va;
    uint8_t *stub;
    process_t *p;
    int pid;

    if (!ft || !path || !path[0])
    {

        return -1;
    }

    // Locate file
    file_index = find_entry_by_path(ft, path);
    if (file_index < 0)
    {
        printf("[DEX] ERROR: File not found: %s\n", path);

        return -2;
    }

    fe = &ft->entries[file_index];
    if (!fe->file_size_bytes)
    {
        printf("[DEX] ERROR: Empty file: %s\n", path);

        return -3;
    }

    // Read whole file into temporary buffer
    buffer = (uint8_t *)kmalloc(fe->file_size_bytes);
    if (!buffer)
    {
        printf("[DEX] ERROR: Unable to allocate %u bytes\n", fe->file_size_bytes);

        return -4;
    }

    if (read_file(ft, path, buffer) < 0)
    {
        printf("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buffer);

        return -5;
    }

    // Create child address space
    cr3_parent = read_cr3_local();
    cr3_child  = paging_new_address_space();
    if (!cr3_child)
    {
        printf("[DEX] ERROR: paging_new_address_space failed");
        kfree(buffer);

        return -6;
    }

    // Switch to child and load image and stack in child space
    paging_switch_address_space(cr3_child);

    load_rc = dex_load(buffer, fe->file_size_bytes, &dex);
    if (load_rc != 0)
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: dex_load rc=%d\n", load_rc);

        return -7;
    }

    user_sp = build_user_stack(path, argc, argv);
    if (!user_sp || !is_user_va(user_sp))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: bad user_sp=%08x\n", user_sp);

        return -8;
    }

    entry_va = (uint32_t)dex.dex_entry;
    if (!is_user_va(entry_va))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: bad entry_va=%08x\n", entry_va);

        return -9;
    }

    stub = build_user_exit_stub(entry_va);
    if (!stub || !is_user_va((uint32_t)stub))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: stub build failed (%p)\n", stub);

        return -10;
    }

    // Make stub user present and writable while patching
    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

#ifdef DIFF_DEBUG
    DDBG("[DEX] spawn(child): entry=%08x stub=%08x sp=%08x\n",
         entry_va, (uint32_t)stub, user_sp);
#endif

    // Return to parent address space before creating process object
    paging_switch_address_space(cr3_parent);

    // Create process bound to prepared child CR3
    p = process_create_user_with_cr3((uint32_t)stub, user_sp, cr3_child, 16384);
    if (!p)
    {
        // Tear down failed child space
        paging_switch_address_space(cr3_child);
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: process_create_user_with_as failed");

        return -11;
    }

    pid = process_pid(p);
    DDBG("[DEX] spawn: pid=%d parent_cr3=%08x child_cr3=%08x\n",
         pid, cr3_parent, cr3_child);

    kfree(buffer);

    return pid;
}

