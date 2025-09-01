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

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

#define MAX_EXL_IMPORTS 256

/* External symbols we rely on (avoid implicit-decl warnings) */
extern FileTable *file_table;
extern int find_entry_by_path(const FileTable *table, const char *path);
extern int read_file(const FileTable *table, const char *path, void *buffer);
extern uint32_t read_cr3_local(void);

/* Per-CR3 cache (types come from exl.h) */
static exl_t exl_files[MAX_EXL_FILES];
static uint32_t exl_cr3s[MAX_EXL_FILES];
static size_t exl_count = 0;

/* Re-entrancy guard for circular loads */
static char loading_names[MAX_EXL_FILES][EXL_NAME_LENGTH];
static size_t loading_depth = 0;

/* ---------------------------------------------------------
 * Helpers
 * --------------------------------------------------------- */

static int range_ok(uint32_t off, uint32_t sz, uint32_t max)
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

static int ptr_in_range(const void *p, const uint8_t *base, uint32_t size)
{
    uint32_t v = (uint32_t)p;
    uint32_t b = (uint32_t)base;

    return (v >= b) && (v < b + size);
}

static const char *basename_ptr_safe(const char *path)
{
    if (!path)
    {
        return "";
    }

    const char *base = path;

    for (const char *p = path; *p; ++p)
    {
        if (*p == '/' || *p == '\\')
        {
            base = p + 1;
        }
    }

    return base;
}

static void canon_exl_name(const char *in, char *out, size_t out_sz)
{
    if (!in || !*in)
    {
        (void)strlcpy(out, "diffc.exl", out_sz);
        return;
    }

    const char *base = basename_ptr_safe(in);

    (void)strlcpy(out, base, out_sz);

    size_t len = strlen(out);

    if (len < 4 || strcmp(out + (len - 4), ".exl") != 0)
    {
        (void)strlcat(out, ".exl", out_sz);
    }
}

static int exl_name_equals(const char *a, const char *b)
{
    char ca[EXL_NAME_LENGTH];
    char cb[EXL_NAME_LENGTH];

    canon_exl_name(a, ca, sizeof(ca));
    canon_exl_name(b, cb, sizeof(cb));

    return strcmp(ca, cb) == 0;
}

/* Relaxed symbol compare: ignore leading '_' and stdcall '@N' suffix */
static int symname_eq(const char *a, const char *b)
{
    if (!a || !b)
    {
        return 0;
    }

    while (*a == '_') ++a;
    while (*b == '_') ++b;

    while (*a && *b)
    {
        if (*a == '@' || *b == '@')
        {
            break;
        }

        if (*a != *b)
        {
            return 0;
        }

        ++a;
        ++b;
    }

    if (*a == '@') while (*a) ++a;
    if (*b == '@') while (*b) ++b;

    return *a == 0 && *b == 0;
}

static int is_loading(const char *name)
{
    char norm[EXL_NAME_LENGTH];

    canon_exl_name(name, norm, sizeof(norm));

    for (size_t i = 0; i < loading_depth; ++i)
    {
        if (exl_name_equals(loading_names[i], norm))
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
    if (loading_depth == 0)
    {
        return;
    }

    char norm[EXL_NAME_LENGTH];

    canon_exl_name(name, norm, sizeof(norm));

    if (exl_name_equals(loading_names[loading_depth - 1], norm))
    {
        loading_depth--;
        return;
    }

    for (size_t i = 0; i < loading_depth; ++i)
    {
        if (exl_name_equals(loading_names[i], norm))
        {
            for (size_t j = i + 1; j < loading_depth; ++j)
            {
                (void)strlcpy(loading_names[j - 1], loading_names[j], EXL_NAME_LENGTH);
            }

            loading_depth--;
            return;
        }
    }
}

/* Zero a USER range via copy_to_user in small chunks so demand faults are OK */
static int zero_user(void *udst, size_t n)
{
    if (!udst || n == 0)
    {
        return 0;
    }

    unsigned char zbuf[256];
    memset(zbuf, 0, sizeof(zbuf));

    unsigned char *p = (unsigned char *)udst;
    size_t left = n;

    while (left)
    {
        size_t chunk = left > sizeof(zbuf) ? sizeof(zbuf) : left;

        if (copy_to_user(p, zbuf, chunk) != 0)
        {
            return -1;
        }

        p += chunk;
        left -= chunk;
    }

    return 0;
}

/* ---------------------------------------------------------
 * Cache & symbol resolution
 * --------------------------------------------------------- */

void exl_invalidate_for_cr3(uint32_t cr3)
{
    if (!cr3)
    {
        return;
    }

    size_t i = 0;

    while (i < exl_count)
    {
        if (exl_cr3s[i] == cr3)
        {
            if (exl_files[i].symbol_table)
            {
                kfree((void *)exl_files[i].symbol_table);
            }

            if (exl_files[i].strtab)
            {
                kfree((void *)exl_files[i].strtab);
            }

            if (i != exl_count - 1)
            {
                exl_files[i] = exl_files[exl_count - 1];
                exl_cr3s[i]  = exl_cr3s[exl_count - 1];
            }

            exl_count--;
            continue;
        }

        i++;
    }
}

static void* resolve_local_symbol(const dex_header_t *hdr,
                                  const dex_symbol_t *symtab,
                                  const char *strtab,
                                  uint8_t *image,
                                  const char *symbol)
{
    if (!hdr || !symtab || !strtab || !symbol || !*symbol)
    {
        return NULL;
    }

    for (size_t i = 0; i < hdr->symbol_table_count; ++i)
    {
        const dex_symbol_t *s = &symtab[i];
        const char *nm = strtab + s->name_offset;

        if (nm && (strcmp(nm, symbol) == 0 || symname_eq(nm, symbol)))
        {
            return (void *)((uint32_t)image + s->value_offset);
        }
    }

    return NULL;
}

void* resolve_exl_symbol(const char* exl_name, const char* symbol)
{
    if (!exl_name || !*exl_name || !symbol || !*symbol)
    {
        return NULL;
    }

    uint32_t cur_cr3 = read_cr3_local();

    for (size_t i = 0; i < exl_count; ++i)
    {
        if (exl_cr3s[i] != cur_cr3)
        {
            continue;
        }

        const exl_t *lib = &exl_files[i];

        if (!exl_name_equals(lib->name, exl_name))
        {
            continue;
        }

        if (!lib->symbol_table || !lib->strtab || lib->symbol_count == 0)
        {
            return NULL;
        }

        for (size_t s = 0; s < lib->symbol_count; ++s)
        {
            const dex_symbol_t *sym = &lib->symbol_table[s];
            const char *nm = lib->strtab + sym->name_offset;

            if (nm && (strcmp(nm, symbol) == 0 || symname_eq(nm, symbol)))
            {
                return (void *)((uint32_t)lib->image_base + sym->value_offset);
            }
        }

        return NULL;
    }

    return NULL;
}

/* ---------------------------------------------------------
 * Relocations
 * --------------------------------------------------------- */

static int do_relocate_exl(uint8_t *image,
                           uint32_t total_sz,
                           const dex_header_t *hdr,
                           const dex_import_t *imp,
                           const dex_reloc_t  *rel,
                           const dex_symbol_t *symtab,
                           const char *strtab,
                           const char *self_name)
{
    if (!image || !hdr)
    {
        return -1;
    }

    if (hdr->import_table_count > MAX_EXL_IMPORTS)
    {
        printf("[EXL] too many imports: %u\n", hdr->import_table_count);
        return -2;
    }

    void **import_ptrs = NULL;

    if (hdr->import_table_count)
    {
        size_t bytes = (size_t)hdr->import_table_count * sizeof(void *);
        import_ptrs = (void **)kmalloc(bytes);

        if (!import_ptrs)
        {
            printf("[EXL] kmalloc(import_ptrs=%u) failed\n", (unsigned)bytes);
            return -3;
        }

        memset(import_ptrs, 0, bytes);
    }

    for (uint32_t i = 0; i < hdr->import_table_count; ++i)
    {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;
        void *p = NULL;

        if (exl_name_equals(exl, self_name))
        {
            p = resolve_local_symbol(hdr, symtab, strtab, image, sym);
        }

        if (!p && is_loading(exl))
        {
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
                if (import_ptrs) kfree(import_ptrs);
                return -4;
            }

            p = resolve_exl_symbol(exl, sym);
        }

        if (!p)
        {
            printf("[EXL] unresolved %s:%s\n", exl, sym);
            if (import_ptrs) kfree(import_ptrs);
            return -5;
        }

        if (ptr_in_range(p, image, total_sz))
        {
            printf("[EXL] import resolves inside image (%p)\n", p);
            if (import_ptrs) kfree(import_ptrs);
            return -6;
        }

        import_ptrs[i] = p;
    }

    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (!range_ok(off, 4, total_sz))
        {
            printf("[EXL] reloc OOR: off=0x%08x (total=%u)\n", off, total_sz);
            if (import_ptrs) kfree(import_ptrs);
            return -7;
        }

        uint8_t *target = image + off;
        uint32_t P = (uint32_t)(uintptr_t)target + 4;
        uint32_t old = *(uint32_t *)target;

        switch (typ)
        {
            case DEX_ABS32:
            {
                if (idx >= hdr->import_table_count)
                {
                    if (import_ptrs) kfree(import_ptrs);
                    return -8;
                }

                *(uint32_t *)target = (uint32_t)(uintptr_t)import_ptrs[idx];
                break;
            }

            case DEX_PC32:
            {
                if (idx >= hdr->import_table_count)
                {
                    if (import_ptrs) kfree(import_ptrs);
                    return -9;
                }

                uint32_t S = (uint32_t)(uintptr_t)import_ptrs[idx];
                int32_t disp = (int32_t)S - (int32_t)P;
                *(int32_t *)target = disp;
                (void)old; /* old not needed here */
                break;
            }

            case DEX_RELATIVE:
            {
                uint32_t S = (uint32_t)(uintptr_t)image;
                *(uint32_t *)target = S + old;
                break;
            }

            default:
            {
                printf("[EXL] unknown reloc type %u\n", typ);
                if (import_ptrs) kfree(import_ptrs);
                return -10;
            }
        }
    }

    if (import_ptrs)
    {
        kfree(import_ptrs);
    }

    return 0;
}

/* ---------------------------------------------------------
 * Loader
 * --------------------------------------------------------- */

const exl_t* load_exl(const FileTable *ft, const char *exl_name)
{
    if (!ft || !exl_name || !*exl_name)
    {
        return NULL;
    }

    if (exl_count >= MAX_EXL_FILES)
    {
        printf("[EXL] ERROR: out of slots\n");
        return NULL;
    }

    char tmp_name[EXL_NAME_LENGTH];
    canon_exl_name(exl_name, tmp_name, sizeof(tmp_name));

    uint32_t cur_cr3 = read_cr3_local();

    for (size_t i = 0; i < exl_count; ++i)
    {
        if (exl_cr3s[i] != cur_cr3)
        {
            continue;
        }

        if (exl_name_equals(exl_files[i].name, tmp_name))
        {
            const exl_t *lib = &exl_files[i];

            if (lib->image_base && paging_check_user_range((uint32_t)lib->image_base, 4) == 0)
            {
                return lib;
            }

            DDBG("[EXL] stale cache for CR3=%08x, invalidating\n", cur_cr3);
            exl_invalidate_for_cr3(cur_cr3);
            break;
        }
    }

    if (is_loading(tmp_name))
    {
        DDBG("[EXL] already loading '%s' – skip\n", tmp_name);
        return NULL;
    }

    push_loading(tmp_name);

    char path[EXL_NAME_LENGTH * 2];
    (void)snprintf(path, sizeof(path), "/system/exls/%s", tmp_name);

    int fidx = find_entry_by_path(ft, path);

    if (fidx < 0)
    {
        printf("[EXL] not found: %s\n", path);
        pop_loading(tmp_name);
        return NULL;
    }

    const FileEntry *fe = &ft->entries[fidx];
    uint32_t sz = fe->file_size_bytes;

    /* Try USER buffer first (saves kernel heap); fallback to kernel buffer with temp PAGE_USER flag */
    uint8_t *filebuf = NULL;
    int filebuf_is_user = 0;
    int marked_user_flag = 0;

    filebuf = (uint8_t *)umalloc(sz);

    if (filebuf)
    {
        filebuf_is_user = 1;

        paging_update_flags((uint32_t)filebuf, sz, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

        int r = read_file(ft, path, filebuf);

        if (r < 0)
        {
            ufree(filebuf, sz);
            filebuf = NULL;
            filebuf_is_user = 0;
        }
        else
        {
            sz = (uint32_t)r;
        }
    }

    if (!filebuf)
    {
        filebuf = (uint8_t *)kmalloc(sz);

        if (!filebuf)
        {
            printf("[EXL] alloc failed for %s (%u bytes)\n", path, fe->file_size_bytes);
            pop_loading(tmp_name);
            return NULL;
        }

        /* If read_file uses copy_to_user internally, mark pages as USER temporarily */
        paging_update_flags((uint32_t)filebuf, sz, PAGE_USER, 0);
        marked_user_flag = 1;

        int r = read_file(ft, path, filebuf);

        if (marked_user_flag)
        {
            paging_update_flags((uint32_t)filebuf, sz, 0, PAGE_USER);
            marked_user_flag = 0;
        }

        if (r < 0)
        {
            kfree(filebuf);
            printf("[EXL] read fail: %s\n", path);
            pop_loading(tmp_name);
            return NULL;
        }

        sz = (uint32_t)r;
    }

    if (!range_ok(0, sizeof(dex_header_t), sz))
    {
        printf("[EXL] file too small for header\n");

        if (filebuf_is_user)
        {
            ufree(filebuf, sz);
        }
        else
        {
            kfree(filebuf);
        }

        pop_loading(tmp_name);
        return NULL;
    }

    const dex_header_t *hdr = (const dex_header_t *)filebuf;

    if (hdr->magic != DEX_MAGIC)
    {
        printf("[EXL] bad magic in %s (0x%08x)\n", path, hdr->magic);

        if (filebuf_is_user)
        {
            ufree(filebuf, sz);
        }
        else
        {
            kfree(filebuf);
        }

        pop_loading(tmp_name);
        return NULL;
    }

    DDBG("=== DEX HEADER DEBUG ===\n");
    DDBG("entry=0x%08x text@0x%08x/%u ro@0x%08x/%u data@0x%08x/%u bss=%u\n",
         hdr->entry_offset,
         hdr->text_offset, hdr->text_size,
         hdr->rodata_offset, hdr->rodata_size,
         hdr->data_offset, hdr->data_size,
         hdr->bss_size);

    if (!range_ok(hdr->text_offset,   hdr->text_size,   sz) ||
        !range_ok(hdr->rodata_offset, hdr->rodata_size, sz) ||
        !range_ok(hdr->data_offset,   hdr->data_size,   sz))
    {
        printf("[EXL] section OOR\n");

        if (filebuf_is_user)
        {
            ufree(filebuf, sz);
        }
        else
        {
            kfree(filebuf);
        }

        pop_loading(tmp_name);
        return NULL;
    }

    if ((hdr->symbol_table_count &&
         !range_ok(hdr->symbol_table_offset, hdr->symbol_table_count * sizeof(dex_symbol_t), sz)) ||
        (hdr->strtab_size &&
         !range_ok(hdr->strtab_offset, hdr->strtab_size, sz)) ||
        (hdr->reloc_table_count &&
         !range_ok(hdr->reloc_table_offset, hdr->reloc_table_count * sizeof(dex_reloc_t), sz)) ||
        (hdr->import_table_count &&
         !range_ok(hdr->import_table_offset, hdr->import_table_count * sizeof(dex_import_t), sz)))
    {
        printf("[EXL] table OOR\n");

        if (filebuf_is_user)
        {
            ufree(filebuf, sz);
        }
        else
        {
            kfree(filebuf);
        }

        pop_loading(tmp_name);
        return NULL;
    }

    /* Build user image */
    uint32_t end_text = hdr->text_offset + hdr->text_size;
    uint32_t end_ro   = hdr->rodata_offset + hdr->rodata_size;
    uint32_t end_dat  = hdr->data_offset + hdr->data_size + hdr->bss_size;

    uint32_t max_end = end_text;
    if (end_ro  > max_end) max_end = end_ro;
    if (end_dat > max_end) max_end = end_dat;

    uint32_t total_sz = PAGE_ALIGN_UP(max_end);

    uint8_t *image = (uint8_t *)umalloc(total_sz);

    if (!image)
    {
        printf("[EXL] umalloc(%u) failed\n", total_sz);

        if (filebuf_is_user)
        {
            ufree(filebuf, sz);
        }
        else
        {
            kfree(filebuf);
        }

        pop_loading(tmp_name);
        return NULL;
    }

    paging_update_flags((uint32_t)image, total_sz, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    if (hdr->text_size &&
        copy_to_user(image + hdr->text_offset, filebuf + hdr->text_offset, hdr->text_size) != 0)
    {
        printf("[EXL] copy .text failed\n");
        ufree(image, total_sz);

        if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf);
        pop_loading(tmp_name);
        return NULL;
    }

    if (hdr->rodata_size &&
        copy_to_user(image + hdr->rodata_offset, filebuf + hdr->rodata_offset, hdr->rodata_size) != 0)
    {
        printf("[EXL] copy .rodata failed\n");
        ufree(image, total_sz);

        if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf);
        pop_loading(tmp_name);
        return NULL;
    }

    if (hdr->data_size &&
        copy_to_user(image + hdr->data_offset, filebuf + hdr->data_offset, hdr->data_size) != 0)
    {
        printf("[EXL] copy .data failed\n");
        ufree(image, total_sz);

        if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf);
        pop_loading(tmp_name);
        return NULL;
    }

    if (hdr->bss_size &&
        zero_user(image + hdr->data_offset + hdr->data_size, hdr->bss_size) != 0)
    {
        printf("[EXL] zero .bss failed\n");
        ufree(image, total_sz);

        if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf);
        pop_loading(tmp_name);
        return NULL;
    }

    /* Relocations + imports */
    const dex_import_t *imp = (const dex_import_t *)(filebuf + hdr->import_table_offset);
    const dex_reloc_t  *rel = (const dex_reloc_t  *)(filebuf + hdr->reloc_table_offset);
    const dex_symbol_t *sym = (const dex_symbol_t *)(filebuf + hdr->symbol_table_offset);
    const char *strtab      = (const char *)(filebuf + hdr->strtab_offset);

    if (do_relocate_exl(image, total_sz, hdr, imp, rel, sym, strtab, tmp_name) != 0)
    {
        printf("[EXL] relocation failed for %s\n", tmp_name);
        ufree(image, total_sz);

        if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf);
        pop_loading(tmp_name);
        return NULL;
    }

    /* Set final protections */
    if (hdr->text_size)
    {
        paging_update_flags((uint32_t)(image + hdr->text_offset),
                            PAGE_ALIGN_UP(hdr->text_size),
                            0, PAGE_RW);
    }

    if (hdr->rodata_size)
    {
        paging_update_flags((uint32_t)(image + hdr->rodata_offset),
                            PAGE_ALIGN_UP(hdr->rodata_size),
                            0, PAGE_RW);
    }

    if (hdr->data_size || hdr->bss_size)
    {
        paging_update_flags((uint32_t)(image + hdr->data_offset),
                            PAGE_ALIGN_UP(hdr->data_size + hdr->bss_size),
                            PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    }

    paging_set_user((uint32_t)image, total_sz);

    /* Copy small metadata to kernel heap for stable lookups */
    dex_symbol_t *symtab_copy = NULL;
    char *strtab_copy = NULL;

    if (hdr->symbol_table_count)
    {
        size_t sym_bytes = (size_t)hdr->symbol_table_count * sizeof(dex_symbol_t);

        symtab_copy = (dex_symbol_t *)kmalloc(sym_bytes);

        if (!symtab_copy)
        {
            printf("[EXL] symtab alloc fail\n");
            ufree(image, total_sz);

            if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf);
            pop_loading(tmp_name);
            return NULL;
        }

        memcpy(symtab_copy, filebuf + hdr->symbol_table_offset, sym_bytes);
    }

    if (hdr->strtab_size)
    {
        strtab_copy = (char *)kmalloc(hdr->strtab_size);

        if (!strtab_copy)
        {
            if (symtab_copy) kfree(symtab_copy);

            printf("[EXL] strtab alloc fail\n");
            ufree(image, total_sz);

            if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf);
            pop_loading(tmp_name);
            return NULL;
        }

        memcpy(strtab_copy, filebuf + hdr->strtab_offset, hdr->strtab_size);
    }

    /* Register library in cache (do not retain the entire file in kernel heap) */
    exl_t *lib = &exl_files[exl_count];

    memset(lib, 0, sizeof(*lib));
    (void)strlcpy(lib->name, tmp_name, sizeof(lib->name));

    lib->image_base   = image;
    lib->image_size   = total_sz;
    lib->header       = NULL;                  /* We do not keep the full file mapped */
    lib->symbol_table = symtab_copy;
    lib->symbol_count = hdr->symbol_table_count;
    lib->strtab       = strtab_copy;

    exl_cr3s[exl_count] = cur_cr3;
    exl_count++;

    if (filebuf_is_user)
    {
        ufree(filebuf, sz);
    }
    else
    {
        kfree(filebuf);
    }

    pop_loading(tmp_name);

    DDBG("[EXL] loaded '%s' base=%p size=%u (.text RX, .data/.bss RW) cr3=%08x\n",
         lib->name, lib->image_base, lib->image_size, cur_cr3);

#ifdef DIFF_DEBUG
    {
        uint32_t entry = (uint32_t)image + hdr->entry_offset;
        dump_pde_pte(entry);
        DDBG("[EXL] entry VA=%08x (off=0x%x)\n", entry, hdr->entry_offset);
    }
#endif

    return lib;
}

