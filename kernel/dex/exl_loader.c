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

/* --- add: zero a userspace range via copy_to_user to fault-in pages --- */
static int zero_user(void *udst, size_t n)
{
    if (!udst || n == 0) return 0;
    unsigned char zbuf[256];
    memset(zbuf, 0, sizeof(zbuf));
    unsigned char *p = (unsigned char *)udst;
    size_t left = n;
    while (left)
    {
        size_t chunk = left > sizeof(zbuf) ? sizeof(zbuf) : left;
        if (copy_to_user(p, zbuf, chunk) != 0) return -1;
        p += chunk;
        left -= chunk;
    }
    return 0;
}
/* --- end add --- */

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

/* relaxed symbol compare: ignore leading '_' and stdcall '@N' suffix */
static int symname_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a == '_') ++a;
    while (*b == '_') ++b;
    while (*a && *b)
    {
        if (*a == '@' || *b == '@') break;
        if (*a != *b) return 0;
        ++a; ++b;
    }
    if (*a == '@') while (*a) ++a;
    if (*b == '@') while (*b) ++b;
    return *a == 0 && *b == 0;
}

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

#define MAX_EXL_IMPORTS 256

static exl_t  exl_files[MAX_EXL_FILES];
static uint32_t exl_cr3s[MAX_EXL_FILES];   /* CR3-tag per inläst EXL */
static size_t exl_count = 0;

static char loading_names[MAX_EXL_FILES][EXL_NAME_LENGTH];
static size_t loading_depth = 0;

extern FileTable *file_table;

static void debug_print_hdr(const dex_header_t *h)
{
#ifndef DIFF_DEBUG
    (void)h;
#endif
    DDBG("=== DEX HEADER DEBUG ===\n");
    DDBG("magic=0x%08x  ver=%u.%u\n", h->magic, h->version_major, h->version_minor);
    DDBG("entry_off=0x%08x\n", h->entry_offset);
    DDBG(".text  off=0x%08x sz=%u\n", h->text_offset, h->text_size);
    DDBG(".ro    off=0x%08x sz=%u\n", h->rodata_offset, h->rodata_size);
    DDBG(".data  off=0x%08x sz=%u\n", h->data_offset, h->data_size);
    DDBG(".bss   sz=%u\n", h->bss_size);
    DDBG("import off=0x%08x cnt=%u\n", h->import_table_offset, h->import_table_count);
    DDBG("reloc  off=0x%08x cnt=%u\n", h->reloc_table_offset, h->reloc_table_count);
    DDBG("symtab off=0x%08x cnt=%u\n", h->symbol_table_offset, h->symbol_table_count);
    DDBG("strtab off=0x%08x sz =%u\n", h->strtab_offset, h->strtab_size);
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
    uint32_t v = (uint32_t)p;
    uint32_t b = (uint32_t)base;
    return (v >= b) && (v < b + size);
}

/* ---------------- Safe path/name helpers ---------------- */
static const char *basename_ptr_safe(const char *path)
{
    if (!path) return "";
    const char *base = path;
    for (const char *p = path; *p; ++p) if (*p == '/' || *p == '\\') base = p + 1;
    return base;
}

static void canon_exl_name(const char *in, char *out, size_t out_sz)
{
    if (!in || !*in) { (void)strlcpy(out, "diffc.exl", out_sz); return; }
    const char *base = basename_ptr_safe(in);
    (void)strlcpy(out, base, out_sz);
    size_t len = strlen(out);
    if (len < 4 || strcmp(out + (len - 4), ".exl") != 0) (void)strlcat(out, ".exl", out_sz);
}

static int exl_name_equals(const char *a, const char *b)
{
    char ca[EXL_NAME_LENGTH], cb[EXL_NAME_LENGTH];
    canon_exl_name(a, ca, sizeof(ca));
    canon_exl_name(b, cb, sizeof(cb));
    return strcmp(ca, cb) == 0;
}

static int is_loading(const char *name)
{
    char norm[EXL_NAME_LENGTH];
    canon_exl_name(name, norm, sizeof(norm));
    for (size_t i = 0; i < loading_depth; ++i)
        if (exl_name_equals(loading_names[i], norm)) return 1;
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
    char norm[EXL_NAME_LENGTH];
    canon_exl_name(name, norm, sizeof(norm));

    if (loading_depth > 0 && exl_name_equals(loading_names[loading_depth - 1], norm))
    {
        loading_depth--;
        return;
    }

    for (size_t i = 0; i < loading_depth; ++i)
    {
        if (exl_name_equals(loading_names[i], norm))
        {
            for (size_t j = i + 1; j < loading_depth; ++j)
                (void)strlcpy(loading_names[j - 1], loading_names[j], EXL_NAME_LENGTH);
            loading_depth--;
            return;
        }
    }
}

/* ---------------- EXL cache invalidation (per CR3) ---------------- */
void exl_invalidate_for_cr3(uint32_t cr3)
{
    if (!cr3) return;

    size_t i = 0;
    while (i < exl_count)
    {
        if (exl_cr3s[i] == cr3)
        {
            /* Frigör kernel-kopior (umalloc-området tillhör user-CR3 och rivs av paging_destroy_address_space) */
            if (exl_files[i].symbol_table) kfree((void*)exl_files[i].symbol_table);
            if (exl_files[i].strtab)       kfree((void*)exl_files[i].strtab);

            /* Komprimera listan genom att flytta sista posten hit */
            if (i != exl_count - 1)
            {
                exl_files[i] = exl_files[exl_count - 1];
                exl_cr3s[i]  = exl_cr3s[exl_count - 1];
            }
            exl_count--;
            continue; /* stanna på samma index, vi har flyttat in en ny post */
        }
        i++;
    }
}

/* ---------------- Symbol resolution ---------------- */
static void* resolve_local_symbol(const dex_header_t *hdr,
                                  const dex_symbol_t *symtab,
                                  const char *strtab,
                                  uint8_t *image,
                                  const char *symbol)
{
    if (!symtab || !strtab || !symbol || !*symbol) return NULL;
    for (size_t i = 0; i < hdr->symbol_table_count; ++i)
    {
        const dex_symbol_t *s = &symtab[i];
        const char *nm = strtab + s->name_offset;
        if (strcmp(nm, symbol) == 0)
            return (void*)((uint32_t)image + s->value_offset);
    }
    return NULL;
}

void* resolve_exl_symbol(const char* exl_name, const char* symbol)
{
    if (!symbol || !*symbol) return NULL;

    uint32_t cur_cr3 = read_cr3_local();

    /* pass 1: match requested EXL only */
    for (size_t i = 0; i < exl_count; ++i)
    {
        if (exl_cr3s[i] != cur_cr3) continue;
        if (!exl_name_equals(exl_files[i].name, exl_name)) continue;

        const exl_t *lib = &exl_files[i];
        const dex_header_t *fh = lib->header; /* points to persisted kfilebuf base if available */

        for (size_t s = 0; s < lib->symbol_count; ++s)
        {
            const dex_symbol_t *sym = &lib->symbol_table[s];

            /* primary: treat name_offset as relative to strtab */
            const char *nm_rel = lib->strtab ? (lib->strtab + sym->name_offset) : NULL;
            int ok_rel = 0;
            if (fh && lib->strtab)
            {
                uint32_t so = fh->strtab_offset; (void)so;
                uint32_t ss = fh->strtab_size;
                uintptr_t lo = (uintptr_t)lib->strtab;
                uintptr_t hi = lo + ss;
                uintptr_t nr = (uintptr_t)nm_rel;
                ok_rel = (nr >= lo) && (nr < hi);
            }

            /* fallback: treat name_offset as absolute file offset */
            const char *nm_abs = NULL;
            if (fh)
            {
                nm_abs = (const char*)((const uint8_t*)fh + sym->name_offset);
                /* sanity: enforce into [header+strtab_offset, +strtab_size) when we can */
                uintptr_t base = (uintptr_t)fh + fh->strtab_offset;
                uintptr_t end  = base + fh->strtab_size;
                if (!((uintptr_t)nm_abs >= base && (uintptr_t)nm_abs < end))
                {
                    nm_abs = NULL;
                }
            }

            const char *nm = NULL;
            if (ok_rel) nm = nm_rel;
            else if (nm_abs) nm = nm_abs;
            else nm = nm_rel ? nm_rel : nm_abs;

            if (!nm) continue;

            if (strcmp(nm, symbol) == 0 || symname_eq(nm, symbol))
            {
                return (void*)((uint32_t)lib->image_base + sym->value_offset);
            }
        }
    }

    /* pass 2: cross-lib search within same CR3 */
    for (size_t i = 0; i < exl_count; ++i)
    {
        if (exl_cr3s[i] != cur_cr3) continue;

        const exl_t *lib = &exl_files[i];
        const dex_header_t *fh = lib->header;

        for (size_t s = 0; s < lib->symbol_count; ++s)
        {
            const dex_symbol_t *sym = &lib->symbol_table[s];
            const char *nm_rel = lib->strtab ? (lib->strtab + sym->name_offset) : NULL;
            const char *nm_abs = NULL;
            if (fh)
            {
                const char *cand = (const char*)((const uint8_t*)fh + sym->name_offset);
                uintptr_t base = (uintptr_t)fh + fh->strtab_offset;
                uintptr_t end  = base + fh->strtab_size;
                if ((uintptr_t)cand >= base && (uintptr_t)cand < end) nm_abs = cand;
            }
            const char *nm = nm_rel ? nm_rel : nm_abs;
            if (!nm) continue;

            if (strcmp(nm, symbol) == 0 || symname_eq(nm, symbol))
            {
                return (void*)((uint32_t)lib->image_base + sym->value_offset);
            }
        }
    }

    return NULL;

}

/* ---------------- Relocation ---------------- */
static int do_relocate_exl(
    uint8_t *image,
    uint32_t total_sz,
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const dex_reloc_t  *rel,
    const dex_symbol_t *symtab,
    const char *strtab,
    const char *self_name
)
{
    if (hdr->import_table_count > MAX_EXL_IMPORTS)
    {
        printf("[EXL] too many imports: %u\n", hdr->import_table_count);
        return -1;
    }

    void **import_ptrs = NULL;

    if (hdr->import_table_count)
    {
        size_t bytes = (size_t)hdr->import_table_count * sizeof(void*);
        import_ptrs = (void**)kmalloc(bytes);
        if (!import_ptrs)
        {
            printf("[EXL] kmalloc(import_ptrs=%u) failed\n", (unsigned)bytes);
            return -2;
        }
        memset(import_ptrs, 0, bytes);
    }

    DDBG("--- IMPORTS DEBUG ---\n");

    for (uint32_t i = 0; i < hdr->import_table_count; ++i)
    {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;
        void *p = NULL;

        if (exl_name_equals(exl, self_name))
        {
            p = resolve_local_symbol(hdr, symtab, strtab, image, sym);
            if (p) DDBG("[EXL] resolved locally %s:%s -> %p\n", exl, sym, p);
        }

        if (!p && is_loading(exl))
            p = resolve_local_symbol(hdr, symtab, strtab, image, sym);

        if (!p)
            p = resolve_exl_symbol(exl, sym);

        if (!p && !exl_name_equals(exl, self_name))
        {
            if (!load_exl(file_table, exl))
            {
                printf("[EXL] cannot load dependency: %s\n", exl);
                if (import_ptrs) kfree(import_ptrs);
                return -3;
            }
            p = resolve_exl_symbol(exl, sym);
        }

        if (!p)
        {
            printf("[EXL] unresolved %s:%s\n", exl, sym);
            if (import_ptrs) kfree(import_ptrs);
            return -4;
        }

        if (ptr_in_range(p, image, total_sz))
        {
            printf("[EXL] FATAL ERROR: import '%s' resolves inside EXL image (%p)\n", sym, p);
            if (import_ptrs) kfree(import_ptrs);
            return -5;
        }

        import_ptrs[i] = p;
        DDBG("[%u] %s:%s -> %p\n", i, exl, sym, p);
    }

    DDBG("----------------------\n");

    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (!range_ok(off, 4, total_sz))
        {
            printf("[EXL] reloc OOR: off=0x%08x (total=%u)\n", off, total_sz);
            if (import_ptrs) kfree(import_ptrs);
            return -6;
        }

        uint8_t *target = image + off;
        uint32_t site_la = (uint32_t)(image + off);
        uint32_t old = *(uint32_t*)target;

        switch (typ)
        {
            case DEX_ABS32:
                if (idx >= hdr->import_table_count) { if (import_ptrs) kfree(import_ptrs); return -7; }
                *(uint32_t*)target = (uint32_t)import_ptrs[idx];
                DDBG("[ABS32] @%08x: %08x -> %08x (S=%p)\n", site_la, old, *(uint32_t*)target, import_ptrs[idx]);
                break;

            case DEX_PC32:
                if (idx >= hdr->import_table_count) { if (import_ptrs) kfree(import_ptrs); return -8; }
                *(int32_t*)target = (int32_t)( (uint32_t)import_ptrs[idx] - (site_la + 4) );
                DDBG("[PC32]  @%08x: P=%08x S=%08x -> disp=%d (old=%08x new=%08x)\n",
                     site_la, site_la + 4, (uint32_t)import_ptrs[idx],
                     *(int32_t*)target, old, *(uint32_t*)target);
                break;

            case DEX_RELATIVE:
                *(uint32_t*)target = old + (uint32_t)image;
                DDBG("[REL]   @%08x: %08x -> %08x (base=%08x)\n",
                     site_la, old, *(uint32_t*)target, (uint32_t)image);
                break;

            default:
                printf("[EXL] UNKNOWN reloc type: %u @ off=0x%08x (old=%08x)\n", typ, off, old);
                if (import_ptrs) kfree(import_ptrs);
                return -13;
        }

        DDBG("new=0x%08x\n", *(uint32_t*)target);
    }

    if (import_ptrs) 
        kfree(import_ptrs);
    
    return 0;
}

const exl_t* load_exl(const FileTable *ft, const char *exl_name)
{
    if (exl_count >= MAX_EXL_FILES)
    {
        printf("[EXL] ERROR: out of slots\n");
        return NULL;
    }

#ifdef DIFF_DEBUG
    printf("load_exl heapdump:\n");
    heap_dump();
#endif

    char tmp_name[EXL_NAME_LENGTH];
    canon_exl_name(exl_name, tmp_name, sizeof(tmp_name));

    uint32_t cur_cr3 = read_cr3_local();

    /* Hitta redan laddat EXL i *samma CR3* */
    for (size_t i = 0; i < exl_count; ++i)
    {
        if (exl_cr3s[i] != cur_cr3) continue;
        if (exl_name_equals(exl_files[i].name, tmp_name))
        {
            const exl_t *lib = &exl_files[i];
            /* Stale-skydd: säkerställ att bilden fortfarande är mappad i user */
            if (lib->image_base && paging_check_user_range((uint32_t)lib->image_base, 4) == 0)
                return lib;

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
    /* --- add: read into kernel buffer first (avoid USER faults during early load) --- */
    uint8_t *kfilebuf = (uint8_t*)kmalloc(sz);
    if (kfilebuf)
    {
        /* make kernel buffer look like USER for read_file() */
        paging_update_flags((uint32_t)kfilebuf, sz, PAGE_USER, 0);
        int rkb = read_file(ft, path, kfilebuf);
        paging_update_flags((uint32_t)kfilebuf, sz, 0, PAGE_USER);
        if (rkb >= 0)
        {
            uint32_t fsz = (uint32_t)rkb;
            if (!range_ok(0, sizeof(dex_header_t), fsz))
            {
                printf("[EXL] file too small for header\n");
                kfree(kfilebuf);
                pop_loading(tmp_name);
                return NULL;
            }
            const dex_header_t *hdr = (const dex_header_t*)kfilebuf;
            if (hdr->magic != DEX_MAGIC)
            {
                printf("[EXL] bad magic in %s (0x%08x)\n", path, hdr->magic);
                kfree(kfilebuf);
                pop_loading(tmp_name);
                return NULL;
            }
            debug_print_hdr(hdr);
            if (!range_ok(hdr->text_offset, hdr->text_size, fsz) ||
                !range_ok(hdr->rodata_offset, hdr->rodata_size, fsz) ||
                !range_ok(hdr->data_offset, hdr->data_size, fsz))
            {
                printf("[EXL] section range OOR (fsz=%u)\n", fsz);
                kfree(kfilebuf);
                pop_loading(tmp_name);
                return NULL;
            }
            if ((hdr->import_table_count &&
                 !range_ok(hdr->import_table_offset, hdr->import_table_count * sizeof(dex_import_t), fsz)) ||
                (hdr->reloc_table_count &&
                 !range_ok(hdr->reloc_table_offset, hdr->reloc_table_count * sizeof(dex_reloc_t), fsz)) ||
                (hdr->symbol_table_count &&
                 !range_ok(hdr->symbol_table_offset, hdr->symbol_table_count * sizeof(dex_symbol_t), fsz)) ||
                (hdr->strtab_size &&
                 !range_ok(hdr->strtab_offset, hdr->strtab_size, fsz)))
            {
                printf("[EXL] table range OOR\n");
                kfree(kfilebuf);
                pop_loading(tmp_name);
                return NULL;
            }

            /* Build user image */
            uint32_t text_sz = hdr->text_size;
            uint32_t ro_sz   = hdr->rodata_size;
            uint32_t data_sz = hdr->data_size;
            uint32_t bss_sz  = hdr->bss_size;
            uint32_t end_text = hdr->text_offset + text_sz;
            uint32_t end_ro   = hdr->rodata_offset + ro_sz;
            uint32_t end_dat  = hdr->data_offset + data_sz + bss_sz;
            uint32_t max_end = end_text;
            if (end_ro  > max_end) max_end = end_ro;
            if (end_dat > max_end) max_end = end_dat;
            uint32_t total_sz = PAGE_ALIGN_UP(max_end);

            uint8_t *image = umalloc(total_sz);
            if (!image)
            {
                printf("[EXL] umalloc(%u) fail\n", total_sz);
                kfree(kfilebuf);
                pop_loading(tmp_name);
                return NULL;
            }
            paging_update_flags((uint32_t)image, total_sz,
                                PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

            if (text_sz && copy_to_user(image + hdr->text_offset, kfilebuf + hdr->text_offset, text_sz) != 0) { ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }
            if (ro_sz   && copy_to_user(image + hdr->rodata_offset, kfilebuf + hdr->rodata_offset, ro_sz) != 0) { ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }
            if (data_sz && copy_to_user(image + hdr->data_offset, kfilebuf + hdr->data_offset, data_sz) != 0) { ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }
            if (bss_sz  && zero_user(image + hdr->data_offset + data_sz, bss_sz) != 0) { ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }

            const dex_import_t *imp = (const dex_import_t*)(kfilebuf + hdr->import_table_offset);
            const dex_reloc_t  *rel = (const dex_reloc_t *)(kfilebuf + hdr->reloc_table_offset);
            const dex_symbol_t *symtab = (const dex_symbol_t*)(kfilebuf + hdr->symbol_table_offset);
            const char *strtab         = (const char*)(kfilebuf + hdr->strtab_offset);

            if (do_relocate_exl(image, total_sz, hdr, imp, rel, symtab, strtab, tmp_name) != 0)
            {
                printf("[EXL] relocation failed for %s\n", tmp_name);
                ufree(image, total_sz);
                kfree(kfilebuf);
                pop_loading(tmp_name);
                return NULL;
            }

            if (text_sz) paging_update_flags((uint32_t)(image + hdr->text_offset), PAGE_ALIGN_UP(text_sz), 0, PAGE_RW);
            if (ro_sz)   paging_update_flags((uint32_t)(image + hdr->rodata_offset), PAGE_ALIGN_UP(ro_sz), 0, PAGE_RW);
            if (data_sz || bss_sz) paging_update_flags((uint32_t)(image + hdr->data_offset), PAGE_ALIGN_UP(data_sz + bss_sz), PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
            paging_set_user((uint32_t)image, total_sz);

            /* Copy small metadata to kernel */
            dex_symbol_t *symtab_copy = NULL;
            char *strtab_copy = NULL;
            if (hdr->symbol_table_count)
            {
                size_t sym_bytes = hdr->symbol_table_count * sizeof(dex_symbol_t);
                symtab_copy = kmalloc(sym_bytes);
                if (!symtab_copy) { ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }
                memcpy(symtab_copy, (const void*)(kfilebuf + hdr->symbol_table_offset), sym_bytes);
            }
            if (hdr->strtab_size)
            {
                strtab_copy = kmalloc(hdr->strtab_size);
                if (!strtab_copy) { if (symtab_copy) kfree(symtab_copy); ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }
                memcpy(strtab_copy, (const void*)(kfilebuf + hdr->strtab_offset), hdr->strtab_size);
            }

            exl_t *lib = &exl_files[exl_count];
            memset(lib, 0, sizeof(*lib));
            (void)strlcpy(lib->name, tmp_name, sizeof(lib->name));
            lib->image_base   = image;
            lib->image_size   = total_sz;
            lib->header       = (const dex_header_t*)kfilebuf; /* keep for absolute offsets */
            lib->symbol_table = symtab_copy;
            lib->symbol_count = hdr->symbol_table_count;
            lib->strtab       = strtab_copy;

            exl_cr3s[exl_count] = cur_cr3;
            exl_count++;

            pop_loading(tmp_name);
            return lib;
        }
        /* else: fall back to USER scratch path */
        kfree(kfilebuf);
    }
    /* --- end add --- */


    /* Läs in hela EXL-filen i temporär buffer (kernel → fallback till user) */
    uint8_t *filebuf = kmalloc(sz);
    int filebuf_is_user = 0;
    if (!filebuf)
    {
        filebuf = umalloc(sz);
        if (filebuf) filebuf_is_user = 1;
    }

    if (!filebuf)
    {
        printf("[EXL] kmalloc/umalloc filebuf fail (%u)\n", sz);
        pop_loading(tmp_name);
        return NULL;
    }

    /* read_file() använder sannolikt copy_to_user → bufferten måste vara USER */
    int marked_user = 0;
    if (!filebuf_is_user)
    {
        paging_update_flags((uint32_t)filebuf, sz, PAGE_USER, 0);
        marked_user = 1;
    }

    int rbytes = read_file(ft, path, filebuf);

    if (marked_user)
    {
        paging_update_flags((uint32_t)filebuf, sz, 0, PAGE_USER);
    }

    if (rbytes < 0)
    {
        printf("[EXL] read fail: %s\n", path);
        do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
        pop_loading(tmp_name);
        return NULL;
    }

    uint32_t fsz = (uint32_t)rbytes;

    if (!range_ok(0, sizeof(dex_header_t), fsz))
    {
        printf("[EXL] file too small for header\n");
        do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
        pop_loading(tmp_name);
        return NULL;
    }

    const dex_header_t *hdr = (const dex_header_t*)filebuf;

    if (hdr->magic != DEX_MAGIC)
    {
        printf("[EXL] bad magic in %s (0x%08x)\n", path, hdr->magic);
        do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
        pop_loading(tmp_name);
        return NULL;
    }

    debug_print_hdr(hdr);

    if (!range_ok(hdr->text_offset, hdr->text_size, fsz) ||
        !range_ok(hdr->rodata_offset, hdr->rodata_size, fsz) ||
        !range_ok(hdr->data_offset, hdr->data_size, fsz))
    {
        printf("[EXL] section range OOR (fsz=%u)\n", fsz);
        do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
        pop_loading(tmp_name);
        return NULL;
    }

    if ((hdr->import_table_count &&
         !range_ok(hdr->import_table_offset, hdr->import_table_count * sizeof(dex_import_t), fsz)) ||
        (hdr->reloc_table_count &&
         !range_ok(hdr->reloc_table_offset, hdr->reloc_table_count * sizeof(dex_reloc_t), fsz)) ||
        (hdr->symbol_table_count &&
         !range_ok(hdr->symbol_table_offset, hdr->symbol_table_count * sizeof(dex_symbol_t), fsz)) ||
        (hdr->strtab_size &&
         !range_ok(hdr->strtab_offset, hdr->strtab_size, fsz)))
    {
        printf("[EXL] table range OOR\n");
        do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
        pop_loading(tmp_name);
        return NULL;
    }

    const dex_symbol_t *symtab = (const dex_symbol_t*)(filebuf + hdr->symbol_table_offset);
    const char *strtab         = (const char*)(filebuf + hdr->strtab_offset);

    uint32_t text_sz = hdr->text_size;
    uint32_t ro_sz   = hdr->rodata_size;
    uint32_t data_sz = hdr->data_size;
    uint32_t bss_sz  = hdr->bss_size;

    uint32_t end_text = hdr->text_offset + text_sz;
    uint32_t end_ro   = hdr->rodata_offset + ro_sz;
    uint32_t end_dat  = hdr->data_offset + data_sz + bss_sz;

    uint32_t max_end = end_text;
    if (end_ro  > max_end) max_end = end_ro;
    if (end_dat > max_end) max_end = end_dat;

    uint32_t total_sz = PAGE_ALIGN_UP(max_end);

    /* Allokera user-image och mappa RW under kopiering */
    uint8_t *image = umalloc(total_sz);
    if (!image)
    {
        printf("[EXL] umalloc(%u) fail\n", total_sz);
        do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
        pop_loading(tmp_name);
        return NULL;
    }

    paging_update_flags((uint32_t)image, total_sz,
                        PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    /* Kopiera sektioner till user-image */
    if (text_sz)
    {
        if (copy_to_user(image + hdr->text_offset,
                         filebuf + hdr->text_offset,
                         text_sz) != 0)
        {
            printf("[EXL] Failed to copy .text to user image\n");
            ufree(image, total_sz);
            do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
            pop_loading(tmp_name);
            return NULL;
        }
    }

    if (ro_sz)
    {
        if (copy_to_user(image + hdr->rodata_offset,
                         filebuf + hdr->rodata_offset,
                         ro_sz) != 0)
        {
            printf("[EXL] Failed to copy .rodata to user image\n");
            ufree(image, total_sz);
            do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
            pop_loading(tmp_name);
            return NULL;
        }
    }

    if (data_sz)
    {
        if (copy_to_user(image + hdr->data_offset,
                         filebuf + hdr->data_offset,
                         data_sz) != 0)
        {
            printf("[EXL] Failed to copy .data to user image\n");
            ufree(image, total_sz);
            do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
            pop_loading(tmp_name);
            return NULL;
        }
    }

    if (bss_sz)
    {
        memset(image + hdr->data_offset + data_sz, 0, bss_sz);
    }

    const dex_import_t *imp = (const dex_import_t*)(filebuf + hdr->import_table_offset);
    const dex_reloc_t  *rel = (const dex_reloc_t *)(filebuf + hdr->reloc_table_offset);

#ifdef DIFF_DEBUG
    paging_dump_range((uint32_t)(image + hdr->text_offset), PAGE_ALIGN_UP(text_sz));
#endif

    if (do_relocate_exl(image, total_sz, hdr, imp, rel, symtab, strtab, tmp_name) != 0)
    {
        printf("[EXL] relocation failed for %s\n", tmp_name);
        ufree(image, total_sz);
        do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
        pop_loading(tmp_name);
        return NULL;
    }

    /* .text RX, .data/.bss RW */
    if (text_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->text_offset),
                            PAGE_ALIGN_UP(text_sz),
                            0, PAGE_RW);
    }
    if (data_sz || bss_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->data_offset),
                            PAGE_ALIGN_UP(data_sz + bss_sz),
                            PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    }

    paging_set_user((uint32_t)image, total_sz);

    if (paging_check_user_range((uint32_t)image, total_sz) != 0)
        printf("[EXL] WARN: not all pages are USER\n");

    /* Kopiera symbol- och strtab till kernel (små, persistenta) */
    dex_symbol_t *symtab_copy = NULL;
    char *strtab_copy = NULL;

    if (hdr->symbol_table_count)
    {
        size_t sym_bytes = hdr->symbol_table_count * sizeof(dex_symbol_t);
        symtab_copy = kmalloc(sym_bytes);
        if (!symtab_copy)
        {
            printf("[EXL] symtab alloc fail\n");
            do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
            ufree(image, total_sz);
            pop_loading(tmp_name);
            return NULL;
        }
        memcpy(symtab_copy, (const void*)(filebuf + hdr->symbol_table_offset), sym_bytes);
    }

    if (hdr->strtab_size)
    {
        strtab_copy = kmalloc(hdr->strtab_size);
        if (!strtab_copy)
        {
            if (symtab_copy) kfree(symtab_copy);
            printf("[EXL] strtab alloc fail\n");
            do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
            ufree(image, total_sz);
            pop_loading(tmp_name);
            return NULL;
        }
        memcpy(strtab_copy, (const void*)(filebuf + hdr->strtab_offset), hdr->strtab_size);
    }

    /* Registrera lib i cache för nuvarande CR3 */
    exl_t *lib = &exl_files[exl_count];
    memset(lib, 0, sizeof(*lib));
    (void)strlcpy(lib->name, tmp_name, sizeof(lib->name));

    lib->image_base   = image;
    lib->image_size   = total_sz;
    lib->header       = (const dex_header_t*)kfilebuf; /* vi behåller inte hela filheadern i kernel */
    lib->symbol_table = symtab_copy;
    lib->symbol_count = hdr->symbol_table_count;
    lib->strtab       = strtab_copy;

    exl_cr3s[exl_count] = cur_cr3;
    exl_count++;

    do { if (filebuf_is_user) ufree(filebuf, sz); else kfree(filebuf); } while (0);
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


