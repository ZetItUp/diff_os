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

//#define IGNORE_DEBUG

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

#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
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

static inline int user_range_ok_w(uint8_t *image, uint32_t total_sz, uint32_t off, size_t sz)
{
    if (off > total_sz || total_sz - off < sz) return 0;
    uint32_t va = (uint32_t)((uintptr_t)image + off);
    return paging_check_user_range_writable(va, (uint32_t)sz) == 0;
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

static int do_relocate_exl(
    uint8_t *image,
    uint32_t total_sz,
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const dex_reloc_t  *rel,
    const dex_symbol_t *symtab,
    const char *strtab,
    const char *self_name   /* oanvänd här; behåll signaturen */
)
{
    (void)symtab; (void)self_name;

    if (!image || !hdr || !imp || !rel || !strtab) return -1;
    if (hdr->import_table_count > MAX_EXL_IMPORTS) {
        printf("[EXL] too many imports: %u\n", hdr->import_table_count);
        return -1;
    }

    /* 1) Lös imports (utan att skriva i bilden) */
    void **import_ptrs = NULL;
    if (hdr->import_table_count) {
        size_t bytes = (size_t)hdr->import_table_count * sizeof(void*);
        import_ptrs = (void**)kmalloc(bytes);
        if (!import_ptrs) {
            printf("[EXL] kmalloc import_ptrs failed (%u bytes)\n", (unsigned)bytes);
            return -2;
        }
        memset(import_ptrs, 0, bytes);

        for (uint32_t i = 0; i < hdr->import_table_count; ++i) {
            const char *exl = strtab + imp[i].exl_name_offset;
            const char *sym = strtab + imp[i].symbol_name_offset;

            if (!exl || !*exl || !sym || !*sym) {
                printf("[EXL] bad import strings @%u\n", i);
                kfree(import_ptrs);
                return -3;
            }

            void *p = resolve_exl_symbol(exl, sym);
            if (!p) {
                const exl_t *m = load_exl(file_table, exl);
                if (!m) {
                    printf("[EXL] cannot load dependency: %s\n", exl);
                    kfree(import_ptrs);
                    return -3;
                }
                (void)m;
                p = resolve_exl_symbol(exl, sym);
            }

            if (!p) {
                printf("[EXL] unresolved %s:%s\n", exl, sym);
                kfree(import_ptrs);
                return -4;
            }

            uintptr_t a = (uintptr_t)p;
            if (!is_user_addr((uint32_t)a)) {
                printf("[EXL] import %s:%s -> kernel VA %p\n", exl, sym, p);
                kfree(import_ptrs);
                return -5;
            }

            /* får inte råka peka in i denna bild */
            if (a >= (uintptr_t)image && a < ((uintptr_t)image + total_sz)) {
                printf("[EXL] FATAL: import '%s' resolves inside EXL image (%p)\n", sym, p);
                kfree(import_ptrs);
                return -6;
            }

            import_ptrs[i] = p;
            printf("[EXL][imp] %u: %s:%s -> %p\n", i, exl, sym, p);
        }
    }

    /* 2) Applicera relocs (ALLT via copy_*_user) */
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (!user_range_ok_w(image, total_sz, off, 4)) {
            printf("[EXL] reloc out of range/writable off=0x%08x total=%u\n", off, total_sz);
            if (import_ptrs) kfree(import_ptrs);
            return -7;
        }

        uint8_t *target = image + off;
        uint32_t site_va = (uint32_t)((uintptr_t)image + off);

        uint32_t old = 0;
        if (copy_from_user(&old, target, 4) != 0) {
            if (import_ptrs) kfree(import_ptrs);
            return -7;
        }

        switch (typ)
        {
            case DEX_ABS32:
            {
                if (idx >= hdr->import_table_count) {
                    if (import_ptrs) kfree(import_ptrs);
                    return -8;
                }
                uint32_t W = (uint32_t)(uintptr_t)import_ptrs[idx];
                if (!is_user_addr(W)) {
                    printf("[EXL] ABS32 -> kernel VA %08x (idx=%u)\n", W, idx);
                    if (import_ptrs) kfree(import_ptrs);
                    return -8;
                }
                if (copy_to_user(target, &W, 4) != 0) {
                    if (import_ptrs) kfree(import_ptrs);
                    return -8;
                }
                printf("[REL] ABS32 @%08x %08x -> %08x\n", site_va, old, W);
                break;
            }

            case DEX_PC32:
            {
                if (idx >= hdr->import_table_count) {
                    if (import_ptrs) kfree(import_ptrs);
                    return -9;
                }
                uint32_t S = (uint32_t)(uintptr_t)import_ptrs[idx];
                int32_t disp = (int32_t)S - (int32_t)(site_va + 4);
                if (copy_to_user(target, &disp, 4) != 0) {
                    if (import_ptrs) kfree(import_ptrs);
                    return -9;
                }
                printf("[REL] PC32  @%08x P=%08x S=%08x disp=%d old=%08x\n",
                       site_va, site_va + 4, S, disp, old);
                break;
            }

            case DEX_RELATIVE:
            {
                uint32_t val = old + (uint32_t)(uintptr_t)image;
                if (copy_to_user(target, &val, 4) != 0) {
                    if (import_ptrs) kfree(import_ptrs);
                    return -10;
                }
                printf("[REL] REL   @%08x %08x -> %08x base=%08x\n",
                       site_va, old, val, (uint32_t)(uintptr_t)image);
                break;
            }

            default:
                printf("[EXL] UNKNOWN reloc type: %u @ off=0x%08x (old=%08x)\n", typ, off, old);
                if (import_ptrs) kfree(import_ptrs);
                return -13;
        }
    }

    /* 3) Efterkontroll: ABS32 får inte peka in i kernel */
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i) {
        if (rel[i].type != DEX_ABS32) continue;
        uint32_t off = rel[i].reloc_offset;
        if (off > total_sz || total_sz - off < 4) return -14;

        uint32_t val = 0;
        if (copy_from_user(&val, image + off, 4) != 0) return -14;
        if (!is_user_addr(val)) {
            printf("[EXL] Post check ABS32 off=0x%08x -> kernel VA %08x\n", off, val);
            return -14;
        }
    }

    if (import_ptrs) kfree(import_ptrs);
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

    /* Hitta redan laddat EXL i samma CR3 */
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
    uint32_t fsize = fe->file_size_bytes;

    /* Läs EXL helt till en KERNEL-buffert (så vi slipper userfaults under laddning) */
    uint8_t *kfilebuf = (uint8_t*)kmalloc(fsize);
    if (!kfilebuf)
    {
        printf("[EXL] kmalloc(%u) failed\n", fsize);
        pop_loading(tmp_name);
        return NULL;
    }

    /* read_file förväntar sig USER-buffert; markera temporärt som USER */
    paging_update_flags((uint32_t)kfilebuf, fsize, PAGE_USER, 0);
    int rkb = read_file(ft, path, kfilebuf);
    paging_update_flags((uint32_t)kfilebuf, fsize, 0, PAGE_USER);

    if (rkb < 0)
    {
        printf("[EXL] read fail: %s\n", path);
        kfree(kfilebuf);
        pop_loading(tmp_name);
        return NULL;
    }
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

    /* Validera sektioners omfång i filen */
    if (!range_ok(hdr->text_offset,   hdr->text_size,   fsz) ||
        !range_ok(hdr->rodata_offset, hdr->rodata_size, fsz) ||
        !range_ok(hdr->data_offset,   hdr->data_size,   fsz))
    {
        printf("[EXL] section range OOR (fsz=%u)\n", fsz);
        kfree(kfilebuf);
        pop_loading(tmp_name);
        return NULL;
    }

    if ((hdr->import_table_count &&
         !range_ok(hdr->import_table_offset, hdr->import_table_count * sizeof(dex_import_t), fsz)) ||
        (hdr->reloc_table_count &&
         !range_ok(hdr->reloc_table_offset,  hdr->reloc_table_count  * sizeof(dex_reloc_t),  fsz)) ||
        (hdr->symbol_table_count &&
         !range_ok(hdr->symbol_table_offset, hdr->symbol_table_count * sizeof(dex_symbol_t), fsz)) ||
        (hdr->strtab_size &&
         !range_ok(hdr->strtab_offset,       hdr->strtab_size,                              fsz)))
    {
        printf("[EXL] table range OOR\n");
        kfree(kfilebuf);
        pop_loading(tmp_name);
        return NULL;
    }

    /* Storlekar */
    uint32_t text_sz = hdr->text_size;
    uint32_t ro_sz   = hdr->rodata_size;
    uint32_t data_sz = hdr->data_size;
    uint32_t bss_sz  = hdr->bss_size;

    uint32_t end_text = hdr->text_offset   + text_sz;
    uint32_t end_ro   = hdr->rodata_offset + ro_sz;
    uint32_t end_dat  = hdr->data_offset   + data_sz + bss_sz;

    uint32_t max_end = end_text;
    if (end_ro  > max_end) max_end = end_ro;
    if (end_dat > max_end) max_end = end_dat;

    uint32_t total_sz = PAGE_ALIGN_UP(max_end);

    /* Bygg user-image: en privat, sammanhängande bild per process */
    uint8_t *image = umalloc(total_sz);
    if (!image)
    {
        printf("[EXL] umalloc(%u) fail\n", total_sz);
        kfree(kfilebuf);
        pop_loading(tmp_name);
        return NULL;
    }

    /* gör RW under kopiering */
    paging_update_flags((uint32_t)image, total_sz, PAGE_PRESENT|PAGE_USER|PAGE_RW, 0);

    /* Kopiera sektioner */
    if (text_sz &&
        copy_to_user(image + hdr->text_offset, kfilebuf + hdr->text_offset, text_sz) != 0)
    { ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }

    if (ro_sz &&
        copy_to_user(image + hdr->rodata_offset, kfilebuf + hdr->rodata_offset, ro_sz) != 0)
    { ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }

    if (data_sz &&
        copy_to_user(image + hdr->data_offset, kfilebuf + hdr->data_offset, data_sz) != 0)
    { ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }

    if (bss_sz &&
        zero_user(image + hdr->data_offset + data_sz, bss_sz) != 0)
    { ufree(image, total_sz); kfree(kfilebuf); pop_loading(tmp_name); return NULL; }

    /* Relocation */
    const dex_import_t *imp    = (const dex_import_t*)(kfilebuf + hdr->import_table_offset);
    const dex_reloc_t  *rel    = (const dex_reloc_t *)(kfilebuf + hdr->reloc_table_offset);
    const dex_symbol_t *symtab = (const dex_symbol_t*)(kfilebuf + hdr->symbol_table_offset);
    const char         *strtab = (const char*)(kfilebuf + hdr->strtab_offset);

    if (do_relocate_exl(image, total_sz, hdr, imp, rel, symtab, strtab, tmp_name) != 0)
    {
        printf("[EXL] relocation failed for %s\n", tmp_name);
        ufree(image, total_sz);
        kfree(kfilebuf);
        pop_loading(tmp_name);
        return NULL;
    }

    /* Sätt korrekta rättigheter:
       - text: RX (ta bort RW)
       - rodata: RX (ta bort RW)
       - data+bss: RW
     */
    if (text_sz)
        paging_update_flags((uint32_t)(image + hdr->text_offset),
                            PAGE_ALIGN_UP(text_sz), 0, PAGE_RW);
    if (ro_sz)
        paging_update_flags((uint32_t)(image + hdr->rodata_offset),
                            PAGE_ALIGN_UP(ro_sz), 0, PAGE_RW);
    if (data_sz || bss_sz)
        paging_update_flags((uint32_t)(image + hdr->data_offset),
                            PAGE_ALIGN_UP(data_sz + bss_sz),
                            PAGE_PRESENT|PAGE_USER|PAGE_RW, 0);

    /* Märk hela som USER (säkerhetsbälte) */
    paging_set_user((uint32_t)image, total_sz);

    /* Kopiera små metadata till kernel (persistenta) */
    dex_symbol_t *symtab_copy = NULL;
    char *strtab_copy = NULL;
    if (hdr->symbol_table_count)
    {
        size_t sym_bytes = hdr->symbol_table_count * sizeof(dex_symbol_t);
        symtab_copy = (dex_symbol_t*)kmalloc(sym_bytes);
        if (!symtab_copy)
        {
            printf("[EXL] symtab alloc fail\n");
            ufree(image, total_sz);
            kfree(kfilebuf);
            pop_loading(tmp_name);
            return NULL;
        }
        memcpy(symtab_copy, (const void*)(kfilebuf + hdr->symbol_table_offset), sym_bytes);
    }
    if (hdr->strtab_size)
    {
        strtab_copy = (char*)kmalloc(hdr->strtab_size);
        if (!strtab_copy)
        {
            if (symtab_copy) kfree(symtab_copy);
            printf("[EXL] strtab alloc fail\n");
            ufree(image, total_sz);
            kfree(kfilebuf);
            pop_loading(tmp_name);
            return NULL;
        }
        memcpy(strtab_copy, (const void*)(kfilebuf + hdr->strtab_offset), hdr->strtab_size);
    }

    /* Spara också en liten kopia av headern i kernel (så pekaren alltid är giltig) */
    dex_header_t *hdr_copy = (dex_header_t*)kmalloc(sizeof(dex_header_t));
    if (!hdr_copy)
    {
        if (symtab_copy) kfree(symtab_copy);
        if (strtab_copy) kfree(strtab_copy);
        ufree(image, total_sz);
        kfree(kfilebuf);
        pop_loading(tmp_name);
        return NULL;
    }
    memcpy(hdr_copy, hdr, sizeof(dex_header_t));

    /* Registrera biblioteket i cache för nuvarande CR3 */
    exl_t *lib = &exl_files[exl_count];
    memset(lib, 0, sizeof(*lib));
    (void)strlcpy(lib->name, tmp_name, sizeof(lib->name));
    lib->image_base   = image;
    lib->image_size   = total_sz;
    lib->header       = hdr_copy;       /* giltig kernelkopiera */
    lib->symbol_table = symtab_copy;
    lib->symbol_count = hdr->symbol_table_count;
    lib->strtab       = strtab_copy;

    exl_cr3s[exl_count] = cur_cr3;
    exl_count++;

    /* Vi behåller kfilebuf bara tills nu – den behövs inte längre */
    kfree(kfilebuf);
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


