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

/* === paging/proc helpers we rely on === */
extern uint32_t paging_new_address_space(void);
extern void paging_switch_address_space(uint32_t cr3);
extern void paging_destroy_address_space(uint32_t cr3);

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x)  (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

static inline int is_user_va(uint32_t a)
{
    return (a >= USER_MIN) && (a < USER_MAX);
}

static inline int in_range(uint32_t off, uint32_t sz, uint32_t max)
{
    if (sz == 0) return 1;
    if (off > max) return 0;
    if (max - off < sz) return 0;
    return 1;
}

static int ptr_in_image(const void *p, const uint8_t *base, uint32_t size)
{
    uint32_t v = (uint32_t)p;
    uint32_t b = (uint32_t)base;
    return (v >= b) && (v < b + size);
}

static inline uint32_t read_cr3_local(void)
{
    uint32_t v;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));
    return v;
}

/* ----------------- exit-stub + stack ----------------- */

static uint8_t* build_user_exit_stub(uint32_t entry_va)
{
    /* call entry; xor eax,eax; xor ebx,ebx; int 0x66; hlt */
    uint8_t *stub = (uint8_t*)umalloc(32);
    if (!stub)
    {
        printf("[DEX] stub alloc failed\n");
        return NULL;
    }

    paging_update_flags((uint32_t)stub, 32, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    uint8_t *p = stub;

    *p++ = 0xE8; /* call rel32 */
    int32_t rel = (int32_t)entry_va - (int32_t)((uint32_t)stub + 5);
    *(int32_t*)p = rel; p += 4;

    *p++ = 0x31; *p++ = 0xC0; /* xor eax,eax */
    *p++ = 0x31; *p++ = 0xDB; /* xor ebx,ebx */
    *p++ = 0xCD; *p++ = 0x66; /* int 0x66 (exit) */
    *p++ = 0xF4;             /* hlt (safety) */

    paging_set_user((uint32_t)stub, 32);

    DDBG("[DEX] stub@%p -> call %08x (rel=%d)\n", stub, entry_va, rel);
    return stub;
}

static uint32_t build_user_stack(const char *prog_path, int argc_in, char *const argv_in[])
{
    const uint32_t STK_SZ = 64 * 1024;
    uint8_t *stk = umalloc(STK_SZ);
    if (!stk)
    {
        printf("[DEX] stack alloc failed (%u bytes)\n", STK_SZ);
        return 0;
    }

    paging_update_flags((uint32_t)stk, STK_SZ, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    int argc = (argc_in > 0 && argv_in) ? argc_in : 1;
    uint32_t *argv_ptrs = (uint32_t*)kmalloc(sizeof(uint32_t) * (size_t)argc);
    if (!argv_ptrs)
    {
        printf("[DEX] argv_ptrs alloc failed\n");
        return 0;
    }

    uint32_t sp = (uint32_t)stk + STK_SZ;
    uint32_t base = (uint32_t)stk;

    for (int i = argc - 1; i >= 0; --i)
    {
        const char *src = (argc_in > 0 && argv_in) ? argv_in[i] : (i == 0 ? prog_path : "");
        size_t len = strlen(src) + 1;

        if (sp < base + len + 64)
        {
            printf("[DEX] stack overflow while building argv\n");
            kfree(argv_ptrs);
            return 0;
        }

        sp -= (uint32_t)len;
        memcpy((void*)sp, src, len);
        argv_ptrs[i] = sp;
    }

    sp &= ~0xFu; /* 16-byte alignment */

    /* envp NULL */
    if (sp < base + 4) { kfree(argv_ptrs); return 0; }
    sp -= 4; *(uint32_t*)sp = 0;

    /* argv[] + NULL */
    uint32_t argv_bytes = (uint32_t)((argc + 1) * sizeof(uint32_t));
    if (sp < base + argv_bytes) { kfree(argv_ptrs); return 0; }
    sp -= argv_bytes;

    uint32_t argv_array = sp;
    for (int i = 0; i < argc; ++i) ((uint32_t*)argv_array)[i] = argv_ptrs[i];
    ((uint32_t*)argv_array)[argc] = 0;

    if (sp < base + 4) { kfree(argv_ptrs); return 0; }
    sp -= 4; *(uint32_t*)sp = argv_array;

    if (sp < base + 4) { kfree(argv_ptrs); return 0; }
    sp -= 4; *(uint32_t*)sp = (uint32_t)argc;

    kfree(argv_ptrs);

    DDBG("[DEX] stack built: base=%08x top=%08x size=%u\n", base, sp, STK_SZ);
    return sp;
}

/* ----------------- imports + reloc ----------------- */

static int resolve_imports_user(const dex_header_t *hdr,
                                const dex_import_t *imp,
                                const char *strtab,
                                void **out_ptrs,
                                uint8_t *image,
                                uint32_t image_sz)
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

        void *addr = resolve_exl_symbol(exl, sym);
        if (!addr)
        {
            const exl_t *lib = load_exl(file_table, exl);
            if (!lib)
            {
                printf("[DEX] cannot load EXL: %s\n", exl);
                return -2;
            }
            addr = resolve_exl_symbol(exl, sym);
        }

        if (!addr)
        {
            printf("[DEX] ERROR: Unresolved import %s:%s\n", exl, sym);
            return -3;
        }

        if (ptr_in_image(addr, image, image_sz))
        {
            printf("[DEX] FATAL: import %s:%s resolves inside image (%p)\n", exl, sym, addr);
            return -4;
        }

        if (!is_user_va((uint32_t)addr))
        {
            printf("[DEX] ERROR: import %s:%s -> kernel VA %p\n", exl, sym, addr);
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
    const dex_reloc_t  *rel,
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

    if (hdr->import_table_count)
    {
        size_t bytes = (size_t)hdr->import_table_count * sizeof(void*);
        import_ptrs = (void**)kmalloc(bytes);
        if (!import_ptrs)
        {
            printf("[DEX] kmalloc(import_ptrs=%u) failed\n", (unsigned)bytes);
            return -2;
        }
        memset(import_ptrs, 0, bytes);
    }

    if (resolve_imports_user(hdr, imp, strtab, import_ptrs, image, image_sz) != 0)
    {
        if (import_ptrs) kfree(import_ptrs);
        return -3;
    }

    DDBG("[RELOC] Applying %u relocations\n", hdr->reloc_table_count);

    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (off > image_sz || image_sz - off < 4)
        {
            printf("[DEX] reloc out of range: off=0x%08x (image=%u)\n", off, image_sz);
            if (import_ptrs) kfree(import_ptrs);
            return -4;
        }

        uint8_t  *target = image + off;
        uint32_t old     = *(uint32_t*)target;

        switch (typ)
        {
            case DEX_ABS32:
            {
                if (idx >= hdr->import_table_count) { if (import_ptrs) kfree(import_ptrs); return -5; }
                *(uint32_t*)target = (uint32_t)import_ptrs[idx];
                DDBG("[REL] ABS32  @%08x: %08x -> %08x (S=%08x)\n",
                     (uint32_t)(uintptr_t)target, old, *(uint32_t*)target, (uint32_t)import_ptrs[idx]);
                break;
            }
            case DEX_PC32:
            {
                if (idx >= hdr->import_table_count) { if (import_ptrs) kfree(import_ptrs); return -6; }
                uint32_t S   = (uint32_t)import_ptrs[idx];
                int32_t  disp = (int32_t)S - (int32_t)((uint32_t)(uintptr_t)target + 4);
                *(int32_t*)target = disp;
                DDBG("[REL] PC32   @%08x: P=%08x S=%08x -> disp=%d (old=%08x new=%08x)\n",
                     (uint32_t)(uintptr_t)target,
                     (uint32_t)(uintptr_t)target + 4,
                     S, disp, old, *(uint32_t*)target);
                break;
            }
            case DEX_RELATIVE:
            {
                uint32_t val = old + (uint32_t)image;
                *(uint32_t*)target = val;
                DDBG("[REL] REL    @%08x: %08x -> %08x (base=%08x)\n",
                     (uint32_t)(uintptr_t)target, old, val, (uint32_t)image);
                break;
            }
            default:
                printf("[DEX] UNKNOWN reloc type=%u @ off=0x%08x (old=%08x)\n", typ, off, old);
                if (import_ptrs) kfree(import_ptrs);
                return -11;
        }

        DDBG("new=0x%08x\n", *(uint32_t*)target);
    }

    if (import_ptrs) kfree(import_ptrs);

    /* Post-check: inga kernel-VAs i ABS-ställen */
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t typ = rel[i].type;

        if (typ == DEX_ABS32)
        {
            uint32_t val = *(uint32_t*)(image + off);
            if (!is_user_va(val))
            {
                printf("[DEX] POST-CHECK: ABS-style reloc @0x%08x -> kernel VA %08x\n", off, val);
                return -12;
            }
        }
    }

    return 0;
}

/* ----------------- loader API ----------------- */

int dex_load(const void *file_data, size_t file_size, dex_executable_t *out)
{
    if (!file_data || file_size < sizeof(dex_header_t) || !out)
        return -1;

    const dex_header_t *hdr = (const dex_header_t*)file_data;

    if (hdr->magic != DEX_MAGIC)
    {
        printf("[DEX] Invalid DEX file!\n");
        return -2;
    }

    if (!in_range(hdr->text_offset,   hdr->text_size,      (uint32_t)file_size) ||
        !in_range(hdr->rodata_offset, hdr->rodata_size,    (uint32_t)file_size) ||
        !in_range(hdr->data_offset,   hdr->data_size,      (uint32_t)file_size) ||
        !in_range(hdr->strtab_offset, hdr->strtab_size,    (uint32_t)file_size))
    {
        printf("[DEX] ERROR: section offsets/sizes out of file\n");
        return -3;
    }

    if (!in_range(hdr->entry_offset, 1, (uint32_t)file_size) ||
        hdr->entry_offset < hdr->text_offset ||
        hdr->entry_offset >= hdr->text_offset + hdr->text_size)
    {
        printf("[DEX] ERROR: entry_offset OOR: off=0x%x\n", (unsigned)hdr->entry_offset);
        return -3;
    }

    uint32_t text_sz = hdr->text_size;
    uint32_t ro_sz   = hdr->rodata_size;
    uint32_t data_sz = hdr->data_size;
    uint32_t bss_sz  = hdr->bss_size;
    uint32_t entry_off = hdr->entry_offset;

    uint32_t max_end = hdr->data_offset + data_sz + bss_sz;
    uint32_t tmp;
    tmp = hdr->rodata_offset + ro_sz; if (tmp > max_end) max_end = tmp;
    tmp = hdr->text_offset + text_sz; if (tmp > max_end) max_end = tmp;
    tmp = entry_off + 16u;            if (tmp > max_end) max_end = tmp;

    uint32_t total_sz = PAGE_ALIGN_UP(max_end);

    uint8_t *image = (uint8_t*)umalloc(total_sz);
    if (!image)
    {
        printf("[DEX] Unable to allocate %u byte(s) for program.\n", total_sz);
        return -4;
    }

    paging_set_user((uint32_t)image, total_sz);
    paging_flush_tlb();

    if (text_sz) memcpy(image + hdr->text_offset,   (const uint8_t*)file_data + hdr->text_offset,   text_sz);
    if (ro_sz)   memcpy(image + hdr->rodata_offset, (const uint8_t*)file_data + hdr->rodata_offset, ro_sz);
    if (data_sz) memcpy(image + hdr->data_offset,   (const uint8_t*)file_data + hdr->data_offset,   data_sz);
    if (bss_sz)  memset(image + hdr->data_offset + data_sz, 0, bss_sz);

    if ((hdr->import_table_count && !in_range(hdr->import_table_offset, hdr->import_table_count * sizeof(dex_import_t), (uint32_t)file_size)) ||
        (hdr->reloc_table_count  && !in_range(hdr->reloc_table_offset,  hdr->reloc_table_count  * sizeof(dex_reloc_t),  (uint32_t)file_size)) ||
        (hdr->strtab_size        && !in_range(hdr->strtab_offset,       hdr->strtab_size,                               (uint32_t)file_size)))
    {
        printf("[DEX] ERROR: table offsets/sizes out of file\n");
        kfree(image);
        return -5;
    }

    const dex_import_t *imp  = (const dex_import_t*)((const uint8_t*)file_data + hdr->import_table_offset);
    const dex_reloc_t  *rel  = (const dex_reloc_t *)((const uint8_t*)file_data + hdr->reloc_table_offset);
    const char         *stab = (const char         *)((const uint8_t*)file_data + hdr->strtab_offset);

    DDBG("=== DEX HEADER DEBUG ===\n");
    DDBG("magic=0x%08x  ver=%u.%u\n", hdr->magic, hdr->version_major, hdr->version_minor);
    DDBG("entry_off=0x%08x\n", hdr->entry_offset);
    DDBG(".text off=0x%08x sz=%u\n", hdr->text_offset, hdr->text_size);
    DDBG(".ro   off=0x%08x sz=%u\n", hdr->rodata_offset, hdr->rodata_size);
    DDBG(".data off=0x%08x sz=%u\n", hdr->data_offset, hdr->data_size);
    DDBG(".bss  sz=%u\n", hdr->bss_size);
    DDBG("import off=0x%08x cnt=%u\n", hdr->import_table_offset, hdr->import_table_count);
    DDBG("reloc  off=0x%08x cnt=%u\n", hdr->reloc_table_offset,  hdr->reloc_table_count);
    DDBG("========================\n");

    if (relocate_image(hdr, imp, rel, stab, image, total_sz) != 0)
    {
        kfree(image);
        return -6;
    }

    if (text_sz)
        paging_update_flags((uint32_t)(image + hdr->text_offset), PAGE_ALIGN_UP(text_sz), 0, PAGE_RW);

    if (data_sz || bss_sz)
        paging_update_flags((uint32_t)(image + hdr->data_offset),
                            PAGE_ALIGN_UP(data_sz + bss_sz),
                            PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    paging_set_user((uint32_t)image, total_sz);

    out->image_base = image;
    out->header     = (dex_header_t*)file_data;
    out->dex_entry  = (void(*)(void))((uint32_t)image + entry_off);
    out->image_size = total_sz;

#ifdef DIFF_DEBUG
    hexdump_bytes((void*)((uint32_t)image + entry_off), 64);
    DDBG("[DEX] entry VA=%08x (off=0x%x)\n", (uint32_t)image + entry_off, entry_off);
#endif

    return 0;
}

/* Kör i *nuvarande* process (ingen process-isolering) – kvar som förr. */
int dex_run(const FileTable* ft, const char* path, int argc, char** argv)
{
    int file_index = find_entry_by_path(ft, path);
    if (file_index < 0) { printf("[DEX] ERROR: File not found: %s\n", path); return -1; }

    const FileEntry* fe = &ft->entries[file_index];
    if (!fe->file_size_bytes) { printf("[DEX] ERROR: Empty file: %s\n", path); return -2; }

    uint8_t* buffer = (uint8_t*)kmalloc(fe->file_size_bytes);
    if (!buffer) { printf("[DEX] ERROR: Unable to allocate %u bytes!\n", fe->file_size_bytes); return -3; }

    if (read_file(ft, path, buffer) < 0) {
        printf("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buffer);
        return -4;
    }

    dex_executable_t dex;
    int rc = dex_load(buffer, fe->file_size_bytes, &dex);
    if (rc != 0) { kfree(buffer); return rc; }

    uint32_t user_sp = build_user_stack(path, argc, argv);
    if (!user_sp) { kfree(buffer); return -5; }

    uint8_t* stub = build_user_exit_stub((uint32_t)dex.dex_entry);
    if (!stub) { printf("[DEX] ERROR: No stub found!\n"); kfree(buffer); return -6; }

    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    DDBG("[DEX] run: entry=%08x stub=%08x sp=%08x (no process)\n",
         (uint32_t)dex.dex_entry, (uint32_t)stub, user_sp);

    enter_user_mode((uint32_t)stub, user_sp);

    kfree(buffer);
    return 0;
}

/* ---------- RÄTTAD process-spawn: ladda i barnets CR3 ---------- */
int dex_spawn_process(const FileTable *ft, const char *path, int argc, char **argv)
{
    if (!ft || !path || !path[0]) return -1;

    int file_index = find_entry_by_path(ft, path);
    if (file_index < 0) { printf("[DEX] ERROR: File not found: %s\n", path); return -2; }

    const FileEntry *fe = &ft->entries[file_index];
    if (!fe->file_size_bytes) { printf("[DEX] ERROR: Empty file: %s\n", path); return -3; }

    uint8_t *buffer = (uint8_t*)kmalloc(fe->file_size_bytes);
    if (!buffer) { printf("[DEX] ERROR: Unable to allocate %u bytes!\n", fe->file_size_bytes); return -4; }

    if (read_file(ft, path, buffer) < 0)
    {
        printf("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buffer);
        return -5;
    }

    uint32_t cr3_parent = read_cr3_local();
    uint32_t cr3_child  = paging_new_address_space();
    if (!cr3_child)
    {
        printf("[DEX] ERROR: paging_new_address_space failed\n");
        kfree(buffer);
        return -6;
    }

    /* Byt adressrymd: allt nedan allokeras/mappas i BARNETS CR3 */
    paging_switch_address_space(cr3_child);

    dex_executable_t dex;
    int load_rc = dex_load(buffer, fe->file_size_bytes, &dex);
    if (load_rc != 0)
    {
        /* tillbaka och städa */
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: dex_load rc=%d\n", load_rc);
        return -7;
    }

    uint32_t user_sp = build_user_stack(path, argc, argv);
    if (!user_sp || !is_user_va(user_sp))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: bad user_sp=%08x\n", user_sp);
        return -8;
    }

    uint32_t entry_va = (uint32_t)dex.dex_entry;
    if (!is_user_va(entry_va))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: bad entry_va=%08x\n", entry_va);
        return -9;
    }

    uint8_t *stub = build_user_exit_stub(entry_va);
    if (!stub || !is_user_va((uint32_t)stub))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: stub build failed (%p)\n", stub);
        return -10;
    }

    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

#ifdef DIFF_DEBUG
    DDBG("[DEX] spawn(child): entry=%08x stub=%08x sp=%08x\n", entry_va, (uint32_t)stub, user_sp);
#endif

    /* Tillbaka till förälderns CR3 innan vi skapar processobjektet */
    paging_switch_address_space(cr3_parent);

    process_t *p = process_create_user_with_cr3((uint32_t)stub, user_sp, cr3_child, 16384);
    if (!p)
    {
        /* Misslyckades skapa processen – riv adressrymden */
        paging_switch_address_space(cr3_child);
        /* (valfritt) här hade vi kunnat unmappa image/stack/stub, men destroy räcker. */
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: process_create_user_with_as failed\n");
        return -11;
    }

    int pid = process_pid(p);
    DDBG("[DEX] spawn: pid=%d (parent CR3 %08x, child CR3 %08x)\n", pid, cr3_parent, cr3_child);

    kfree(buffer);
    return pid;
}

