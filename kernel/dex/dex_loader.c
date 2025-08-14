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

#ifndef DEX_RELATIVE
# ifdef DEX_REL
#  define DEX_RELATIVE DEX_REL
# else
#  define DEX_RELATIVE 8u
# endif
#endif

static int ptr_in_range(void *p, uint8_t *base, uint32_t size)
{
    uint32_t v = (uint32_t)p;
    uint32_t b = (uint32_t)base;

    return (v >= b) && (v < b + size);
}

static uint8_t* build_user_exit_stub(uint32_t entry_va)
{
    uint8_t *stub = (uint8_t*)umalloc(32);

    if (!stub)
    {
        printf("[DEX] stub alloc failed\n");

        return NULL;
    }

    paging_update_flags((uint32_t)stub, 32, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

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

static uint32_t build_user_stack(const char *prog_path, int argc_in, char *const argv_in[])
{
    const uint32_t STK_SZ = 64 * 1024;
    uint8_t *stk = umalloc(STK_SZ);

    if (!stk)
    {
        return 0;
    }

    paging_update_flags((uint32_t)stk, STK_SZ, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    int argc = (argc_in > 0 && argv_in) ? argc_in : 1;

    uint32_t *argv_ptrs = (uint32_t*)kmalloc(sizeof(uint32_t) * (size_t)argc);

    if (!argv_ptrs)
    {
        return 0;
    }

    uint32_t sp = (uint32_t)stk + STK_SZ;
    uint32_t stack_base = (uint32_t)stk;

    for (int i = argc - 1; i >= 0; --i)
    {
        const char *src = (argc_in > 0 && argv_in) ? argv_in[i] : (i == 0 ? prog_path : "");
        size_t len = strlen(src) + 1;

        if (sp < stack_base + len + 64)
        {
            kfree(argv_ptrs);

            return 0;
        }

        sp -= (uint32_t)len;
        memcpy((void*)sp, src, len);
        argv_ptrs[i] = sp;
    }

    sp &= ~0xFu;

    if (sp < stack_base + 4)
    {
        kfree(argv_ptrs);

        return 0;
    }

    sp -= 4;
    *(uint32_t*)sp = 0;

    uint32_t argv_array_size = (uint32_t)((argc + 1) * sizeof(uint32_t));

    if (sp < stack_base + argv_array_size)
    {
        kfree(argv_ptrs);

        return 0;
    }

    sp -= argv_array_size;

    uint32_t argv_array_addr = sp;

    for (int i = 0; i < argc; ++i)
    {
        ((uint32_t*)argv_array_addr)[i] = argv_ptrs[i];
    }

    ((uint32_t*)argv_array_addr)[argc] = 0;

    if (sp < stack_base + 4)
    {
        kfree(argv_ptrs);

        return 0;
    }

    sp -= 4;
    *(uint32_t*)sp = argv_array_addr;

    if (sp < stack_base + 4)
    {
        kfree(argv_ptrs);

        return 0;
    }

    sp -= 4;
    *(uint32_t*)sp = (uint32_t)argc;

    kfree(argv_ptrs);

    return sp;
}

int dex_load(const void *file_data, size_t file_size, dex_executable_t *out)
{
    if (!file_data || file_size < sizeof(dex_header_t) || !out)
    {
        return -1;
    }

    const dex_header_t *hdr = (const dex_header_t*)file_data;

    if (hdr->magic != DEX_MAGIC)
    {
        printf("[DEX] Invalid DEX file!\n");

        return -2;
    }

    if (hdr->text_offset + hdr->text_size > file_size ||
        hdr->rodata_offset + hdr->rodata_size > file_size ||
        hdr->data_offset + hdr->data_size > file_size ||
        hdr->strtab_offset + hdr->strtab_size > file_size)
    {
        printf("[DEX] ERROR: section offsets/sizes out of file\n");
        printf(" text   off=%u sz=%u\n", (unsigned)hdr->text_offset, (unsigned)hdr->text_size);
        printf(" rodata off=%u sz=%u\n", (unsigned)hdr->rodata_offset, (unsigned)hdr->rodata_size);
        printf(" data   off=%u sz=%u\n", (unsigned)hdr->data_offset, (unsigned)hdr->data_size);
        printf(" strtab off=%u sz=%u\n", (unsigned)hdr->strtab_offset, (unsigned)hdr->strtab_size);

        return -3;
    }

    uint32_t text_sz = hdr->text_size;
    uint32_t ro_sz = hdr->rodata_size;
    uint32_t data_sz = hdr->data_size;
    uint32_t bss_sz = hdr->bss_size;

    uint32_t highest_end = hdr->data_offset + data_sz + bss_sz;

    if (hdr->rodata_offset + ro_sz > highest_end)
    {
        highest_end = hdr->rodata_offset + ro_sz;
    }

    if (hdr->text_offset + text_sz > highest_end)
    {
        highest_end = hdr->text_offset + text_sz;
    }

    uint32_t total_sz = PAGE_ALIGN_UP(highest_end);
    uint8_t *image = (uint8_t*)umalloc(total_sz);

    if (!image)
    {
        printf("[DEX] Unable to allocate %u byte(s) for program.\n", total_sz);

        return -4;
    }

    paging_set_user((uint32_t)image, total_sz);
    paging_flush_tlb();

    if (text_sz)
    {
        memcpy(image + hdr->text_offset, (const uint8_t*)file_data + hdr->text_offset, text_sz);
    }

    if (ro_sz)
    {
        memcpy(image + hdr->rodata_offset, (const uint8_t*)file_data + hdr->rodata_offset, ro_sz);
    }

    if (data_sz)
    {
        memcpy(image + hdr->data_offset, (const uint8_t*)file_data + hdr->data_offset, data_sz);
    }

    if (bss_sz)
    {
        memset(image + hdr->data_offset + data_sz, 0, bss_sz);
    }

    if (hdr->import_table_offset + hdr->import_table_count * sizeof(dex_import_t) > file_size ||
        hdr->reloc_table_offset + hdr->reloc_table_count * sizeof(dex_reloc_t) > file_size ||
        hdr->strtab_offset + hdr->strtab_size > file_size)
    {
        printf("[DEX] ERROR: table offsets/sizes out of file\n");

        goto fail_image;
    }

    const dex_import_t *imp = (const dex_import_t*)((const uint8_t*)file_data + hdr->import_table_offset);
    const dex_reloc_t *rel = (const dex_reloc_t*)((const uint8_t*)file_data + hdr->reloc_table_offset);
    const char *stab = (const char*)((const uint8_t*)file_data + hdr->strtab_offset);

    void *import_ptrs[256];

    if (hdr->import_table_count > 256)
    {
        printf("[DEX] Too many imports\n");

        goto fail_image;
    }

    for (uint32_t i = 0; i < hdr->import_table_count; ++i)
    {
        const char *exl = stab + imp[i].exl_name_offset;
        const char *sym = stab + imp[i].symbol_name_offset;

        void *addr = resolve_exl_symbol(exl, sym);

        if (!addr)
        {
            if (!load_exl(file_table, exl))
            {
            }
            else
            {
                addr = resolve_exl_symbol(exl, sym);
            }
        }

        if (!addr)
        {
            printf("[DEX] ERROR: Unresolved import %s:%s\n", exl, sym);

            goto fail_image;
        }

        if (ptr_in_range(addr, image, total_sz))
        {
            printf("[DEX] FATAL: import %s:%s resolves inside image (%p)\n", exl, sym, addr);

            goto fail_image;
        }

        import_ptrs[i] = addr;
    }

    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (off + 4 > total_sz)
        {
            printf("[DEX] Relocation OOR: off=0x%08x\n", off);

            goto fail_image;
        }

        if (typ == DEX_ABS32)
        {
            if (idx >= hdr->import_table_count)
            {
                printf("[DEX] ABS32 bad symidx\n");

                goto fail_image;
            }

            *(uint32_t*)(image + off) = (uint32_t)import_ptrs[idx];
        }
        else if (typ == DEX_PC32)
        {
            if (idx >= hdr->import_table_count)
            {
                printf("[DEX] PC32 bad symidx\n");

                goto fail_image;
            }

            uint32_t import_addr = (uint32_t)import_ptrs[idx];
            uint32_t site = (uint32_t)(image + off);
            int32_t disp = (int32_t)import_addr - (int32_t)(site + 4);

            *(uint32_t*)(image + off) = (uint32_t)disp;
        }
        else if (typ == DEX_RELATIVE)
        {
            *(uint32_t*)(image + off) += (uint32_t)image;
        }
        else
        {
            printf("[DEX] Unknown relocation type %u at off=0x%08x\n", typ, off);

            goto fail_image;
        }
    }

    if (text_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->text_offset), PAGE_ALIGN_UP(text_sz), 0, PAGE_RW);
    }

    if (data_sz || bss_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->data_offset), PAGE_ALIGN_UP(data_sz + bss_sz), PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    }

    paging_set_user((uint32_t)image, total_sz);

    out->image_base = image;
    out->header = (dex_header_t*)file_data;
    out->dex_entry = (void(*)(void))((uint32_t)image + hdr->entry_offset);
    out->image_size = total_sz;

#ifdef DIFF_DEBUG
    hexdump_bytes((void*)((uint32_t)image + hdr->entry_offset), 64);
#endif

    return 0;

fail_image:
    kfree(image);

    return -1;
}

void dex_run(const FileTable *ft, const char *path, int argc, char **argv)
{
    int idx = find_entry_by_path(ft, path);

    if (idx < 0)
    {
        printf("[DEX] ERROR: File not found: %s\n", path);

        return;
    }

    const FileEntry *fe = &ft->entries[idx];

    if (!fe->file_size_bytes)
    {
        printf("[DEX] ERROR: Empty file: %s\n", path);

        return;
    }

    uint8_t *buf = (uint8_t*)kmalloc(fe->file_size_bytes);

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
        uint32_t user_sp = build_user_stack(path, argc, argv);

        if (!user_sp)
        {
            kfree(buf);

            return;
        }

        uint8_t *stub = build_user_exit_stub((uint32_t)dex.dex_entry);

        if (!stub)
        {
            printf("[DEX] ERROR: No stub found!\n");
            kfree(buf);

            return;
        }

#ifdef DIFF_DEBUG
        paging_dump_range(user_sp - 64, 128);
        paging_check_user_range(user_sp - 64, 128);
        DDBG("[DEX] jump to stub=%p, entry=%p, esp=%08x\n", stub, dex.dex_entry, user_sp);
#endif

        paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER, 0);
        enter_user_mode((uint32_t)stub, user_sp);
    }

    kfree(buf);
}

