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

/* #define DIFF_DEBUG */
/* #define IGNORE_DEBUG */

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

/* relaxed symbol compare: ignore leading '_' and stdcall '@N' suffix */
static int symname_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a == '_') ++a;
    while (*b == '_') ++b;
    while (*a && *b) {
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

static exl_t    exl_files[MAX_EXL_FILES];
static uint32_t exl_cr3s [MAX_EXL_FILES];
static size_t   exl_count = 0;

static char  loading_names[MAX_EXL_FILES][EXL_NAME_LENGTH];
static size_t loading_depth = 0;

extern FileTable *file_table;

/* ------------ utils ------------ */

static void debug_print_hdr(const dex_header_t *h)
{
#ifndef DIFF_DEBUG
    (void)h;
#endif
    DDBG("=== DEX HEADER DEBUG ===\n");
    DDBG("magic=0x%08x  ver=%u.%u\n", h->magic, h->version_major, h->version_minor);
    DDBG("entry_off=0x%08x\n", h->entry_offset);
    DDBG(".text  off=0x%08x sz=%u\n", h->text_offset,   h->text_size);
    DDBG(".ro    off=0x%08x sz=%u\n", h->rodata_offset, h->rodata_size);
    DDBG(".data  off=0x%08x sz=%u\n", h->data_offset,   h->data_size);
    DDBG(".bss   sz=%u\n", h->bss_size);
    DDBG("import off=0x%08x cnt=%u\n", h->import_table_offset, h->import_table_count);
    DDBG("reloc  off=0x%08x cnt=%u\n", h->reloc_table_offset,  h->reloc_table_count);
    DDBG("symtab off=0x%08x cnt=%u\n", h->symbol_table_offset, h->symbol_table_count);
    DDBG("strtab off=0x%08x sz =%u\n", h->strtab_offset, h->strtab_size);
    DDBG("========================\n");
}

static int in_file(uint32_t off, uint32_t sz, uint32_t max)
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

/* ---------------- Safe path/name helpers ---------------- */
static const char *basename_ptr_safe(const char *path)
{
    if (!path) return "";
    const char *base = path;
    for (const char *p = path; *p; ++p)
        if (*p == '/' || *p == '\\') base = p + 1;
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
    if (loading_depth < MAX_EXL_FILES) {
        canon_exl_name(name, loading_names[loading_depth], EXL_NAME_LENGTH);
        loading_depth++;
    }
}
static void pop_loading(const char *name)
{
    char norm[EXL_NAME_LENGTH];
    canon_exl_name(name, norm, sizeof(norm));

    if (loading_depth > 0 && exl_name_equals(loading_names[loading_depth - 1], norm)) {
        loading_depth--;
        return;
    }
    for (size_t i = 0; i < loading_depth; ++i) {
        if (exl_name_equals(loading_names[i], norm)) {
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
    while (i < exl_count) {
        if (exl_cr3s[i] == cr3) {
            if (exl_files[i].symbol_table) kfree((void*)exl_files[i].symbol_table);
            if (exl_files[i].strtab)       kfree((void*)exl_files[i].strtab);
            if (i != exl_count - 1) {
                exl_files[i] = exl_files[exl_count - 1];
                exl_cr3s[i]  = exl_cr3s[exl_count - 1];
            }
            exl_count--;
            continue;
        }
        i++;
    }
}

/* ---------------- Symbol resolution helpers ---------------- */

static void* resolve_local_symbol(const dex_header_t *hdr,
                                  const dex_symbol_t *symtab,
                                  const char *strtab,
                                  uint8_t *image,
                                  const char *symbol)
{
    if (!symtab || !strtab || !symbol || !*symbol) return NULL;
    for (size_t i = 0; i < hdr->symbol_table_count; ++i) {
        const dex_symbol_t *s = &symtab[i];
        const char *nm = strtab + s->name_offset;
        if (strcmp(nm, symbol) == 0 || symname_eq(nm, symbol))
            return (void*)((uint32_t)image + s->value_offset);
    }
    return NULL;
}

static const exl_t* cache_find_lib(uint32_t cr3, const char *name)
{
    for (size_t i = 0; i < exl_count; ++i)
        if (exl_cr3s[i] == cr3 && exl_name_equals(exl_files[i].name, name))
            return &exl_files[i];
    return NULL;
}

static void* cache_symbol_lookup_any(uint32_t cr3, const char *sym, const char **owner_out)
{
    if (owner_out) *owner_out = NULL;
    for (size_t i = 0; i < exl_count; ++i) {
        if (exl_cr3s[i] != cr3) continue;
        const exl_t *lib = &exl_files[i];
        const dex_header_t *fh = lib->header;
        for (size_t s = 0; s < lib->symbol_count; ++s) {
            const dex_symbol_t *ds = &lib->symbol_table[s];
            const char *nm_rel = lib->strtab ? (lib->strtab + ds->name_offset) : NULL;
            const char *nm_abs = NULL;
            if (fh) {
                const char *cand = (const char *)((const uint8_t*)fh + ds->name_offset);
                uintptr_t base = (uintptr_t)fh + fh->strtab_offset;
                uintptr_t end  = base + fh->strtab_size;
                if ((uintptr_t)cand >= base && (uintptr_t)cand < end) nm_abs = cand;
            }
            const char *nm = nm_rel ? nm_rel : nm_abs;
            if (!nm) continue;
            if (strcmp(nm, sym) == 0 || symname_eq(nm, sym)) {
                if (owner_out) *owner_out = lib->name;
                return (void *)((uint32_t)lib->image_base + ds->value_offset);
            }
        }
    }
    return NULL;
}

void* resolve_exl_symbol(const char* exl_name, const char* symbol)
{
    if (!symbol || !*symbol) return NULL;
    uint32_t cur_cr3 = read_cr3_local();

    /* pass 1: specific lib */
    for (size_t i = 0; i < exl_count; ++i) {
        if (exl_cr3s[i] != cur_cr3) continue;
        if (!exl_name_equals(exl_files[i].name, exl_name)) continue;

        const exl_t *lib = &exl_files[i];
        const dex_header_t *fh = lib->header;
        for (size_t s = 0; s < lib->symbol_count; ++s) {
            const dex_symbol_t *sym = &lib->symbol_table[s];
            const char *nm_rel = lib->strtab ? (lib->strtab + sym->name_offset) : NULL;
            const char *nm_abs = NULL;
            if (fh) {
                const char *cand = (const char *)((const uint8_t*)fh + sym->name_offset);
                uintptr_t base = (uintptr_t)fh + fh->strtab_offset;
                uintptr_t end  = base + fh->strtab_size;
                if ((uintptr_t)cand >= base && (uintptr_t)cand < end) nm_abs = cand;
            }
            const char *nm = nm_rel ? nm_rel : nm_abs;
            if (!nm) continue;
            if (strcmp(nm, symbol) == 0 || symname_eq(nm, symbol))
                return (void*)((uint32_t)lib->image_base + sym->value_offset);
        }
    }

    /* pass 2: any lib in same CR3 */
    for (size_t i = 0; i < exl_count; ++i) {
        if (exl_cr3s[i] != cur_cr3) continue;
        const exl_t *lib = &exl_files[i];
        const dex_header_t *fh = lib->header;
        for (size_t s = 0; s < lib->symbol_count; ++s) {
            const dex_symbol_t *sym = &lib->symbol_table[s];
            const char *nm_rel = lib->strtab ? (lib->strtab + sym->name_offset) : NULL;
            const char *nm_abs = NULL;
            if (fh) {
                const char *cand = (const char *)((const uint8_t*)fh + sym->name_offset);
                uintptr_t base = (uintptr_t)fh + fh->strtab_offset;
                uintptr_t end  = base + fh->strtab_size;
                if ((uintptr_t)cand >= base && (uintptr_t)cand < end) nm_abs = cand;
            }
            const char *nm = nm_rel ? nm_rel : nm_abs;
            if (!nm) continue;
            if (strcmp(nm, symbol) == 0 || symname_eq(nm, symbol))
                return (void*)((uint32_t)lib->image_base + sym->value_offset);
        }
    }
    return NULL;
}

/* --- ersätt hela do_relocate() med denna version --- */
static int do_relocate(
    uint8_t *image, uint32_t total_sz,
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const dex_reloc_t  *rel,
    const char         *strtab,
    const dex_symbol_t *symtab /* optional, för lokala uppslag i DEX */
)
{
    const uint32_t nrel = hdr->reloc_table_count;
    const int is_exl_mode = (hdr->import_table_count == 0);

    /* heuristik: vanlig byggbas för user */
    const uint32_t BUILD_BASE_GUESS = 0x40000000u;

    for (uint32_t i = 0; i < nrel; ++i) {
        const uint32_t off    = rel[i].reloc_offset;
        const uint32_t typ    = rel[i].type;
        const uint32_t symoff = rel[i].symbol_name_offset;

        if (!user_range_ok_w(image, total_sz, off, 4)) {
            printf("[EXL] reloc OOR/W off=0x%08x total=%u\n", off, total_sz);
            return -1;
        }

        uint8_t  *target = image + off;
        uint32_t  P      = (uint32_t)((uintptr_t)image + off) + 4; /* x86 disp32 */
        uint32_t  B      = (uint32_t)(uintptr_t)image;

        uint32_t old = 0;
        if (copy_from_user(&old, target, 4) != 0) return -1;

        if (is_exl_mode) {
            /* EXL: importtabell tom; A′ kan vara offset ELLER redan absolut VA. */
            switch (typ) {
                case DEX_ABS32: {
                    uint32_t W;
                    if (old < total_sz) {
                        /* offset → absolut med aktuell bas */
                        W = B + old;
                    } else if (is_user_addr(old)) {
                        /* redan en giltig user-VA → låt stå */
                        W = old;
                    } else if (old >= BUILD_BASE_GUESS &&
                               old - BUILD_BASE_GUESS < (1u << 22)) { /* ~4 MB “rimlig modulstorlek” */
                        /* absolut VA från byggbas → rebase till B */
                        W = (old - BUILD_BASE_GUESS) + B;
                    } else {
                        /* ser fel ut – rör inte */
                        W = old;
                    }
                    if (copy_to_user(target, &W, 4) != 0) return -1;
#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
                    DDBG("[REL] ABS32 @%08x A'=%08x -> %08x B=%08x\n", P-4, old, W, B);
#endif
                    break;
                }
                case DEX_PC32: {
                    /* PC-relativ: A′ är normalt ett offset från B. Behandla som tidigare. */
                    uint32_t S = B + old;
                    int32_t disp = (int32_t)S - (int32_t)P;
                    if (copy_to_user(target, &disp, 4) != 0) return -1;
#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
                    DDBG("[REL] PC32  @%08x A'=%08x P=%08x -> disp=%08x (S=%08x)\n",
                         P-4, old, P, (uint32_t)disp, S);
#endif
                    break;
                }
                case DEX_RELATIVE: {
                    uint32_t W;
                    if (old < total_sz) {
                        W = old + B;
                    } else {
                        /* lämna orörd om det inte ser ut som offset */
                        W = old;
                    }
                    if (copy_to_user(target, &W, 4) != 0) return -1;
#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
                    DDBG("[REL] REL   @%08x A'=%08x -> %08x B=%08x\n", P-4, old, W, B);
#endif
                    break;
                }
                default:
                    printf("[EXL] UNKNOWN reloc type %u (EXL)\n", typ);
                    return -1;
            }
            continue;
        }

        /* ---------- DEX-läge (med imports) ---------- */
        const char *symname = (symoff ? (strtab + symoff) : NULL);
        void *S_ptr = NULL;

        if (symname && *symname) {
            if (symtab) {
                for (uint32_t s = 0; s < hdr->symbol_table_count && !S_ptr; ++s) {
                    const dex_symbol_t *ds = &symtab[s];
                    const char *nm = strtab + ds->name_offset;
                    if (nm && (strcmp(nm, symname) == 0 || symname_eq(nm, symname)))
                        S_ptr = (void *)((uint32_t)image + ds->value_offset);
                }
            }
            if (!S_ptr) S_ptr = resolve_exl_symbol("diffc.exl", symname);
            if (!S_ptr) S_ptr = resolve_exl_symbol(symname, symname);
        }

        switch (typ) {
            case DEX_ABS32: {
                if (!S_ptr) { printf("[EXL] unresolved ABS32 '%s'\n", symname ? symname : "<null>"); return -1; }
                uint32_t W = (uint32_t)(uintptr_t)S_ptr;
                if (!is_user_addr(W)) { printf("[EXL] ABS32 -> kernel VA for '%s'\n", symname); return -1; }
                if (copy_to_user(target, &W, 4) != 0) return -1;
#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
                DDBG("[REL] ABS32 @%08x old=%08x -> %08x (%s)\n", P-4, old, W, symname);
#endif
                break;
            }
            case DEX_PC32: {
                if (!S_ptr) { printf("[EXL] unresolved PC32 '%s'\n", symname ? symname : "<null>"); return -1; }
                uint32_t S = (uint32_t)(uintptr_t)S_ptr;
                int32_t disp = (int32_t)S - (int32_t)P;
                if (copy_to_user(target, &disp, 4) != 0) return -1;
#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
                DDBG("[REL] PC32  @%08x P=%08x S=%08x -> disp=%08x (%s) old=%08x\n",
                     P-4, P, S, (uint32_t)disp, symname, old);
#endif
                break;
            }
            case DEX_RELATIVE: {
                uint32_t W = old + B;
                if (copy_to_user(target, &W, 4) != 0) return -1;
#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
                DDBG("[REL] REL   @%08x old=%08x -> %08x (B=%08x)\n", P-4, old, W, B);
#endif
                break;
            }
            default:
                printf("[EXL] UNKNOWN reloc type: %u @ off=0x%08x\n", typ, off);
                return -1;
        }
    }

    /* Post-check: behåll endast i DEX-läge (EXL kan medvetet lämna absoluta user-VAs). */
    if (hdr->import_table_count) {
        for (uint32_t i = 0; i < nrel; ++i) {
            if (rel[i].type != DEX_ABS32) continue;
            uint32_t off = rel[i].reloc_offset;
            if (off > total_sz || total_sz - off < 4) return -1;
            uint32_t val = 0;
            if (copy_from_user(&val, image + off, 4) != 0) return -1;
            if (!is_user_addr(val)) {
                printf("[EXL] Post check ABS32 off=0x%08x -> kernel VA %08x\n", off, val);
                return -1;
            }
        }
    }
    return 0;
}

/* ---------------- load_exl ---------------- */

const exl_t* load_exl(const FileTable *ft, const char *exl_name)
{
    if (exl_count >= MAX_EXL_FILES) {
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

    /* redan laddat i denna CR3? */
    for (size_t i = 0; i < exl_count; ++i) {
        if (exl_cr3s[i] != cur_cr3) continue;
        if (exl_name_equals(exl_files[i].name, tmp_name)) {
            const exl_t *lib = &exl_files[i];
            if (lib->image_base && paging_check_user_range((uint32_t)lib->image_base, 4) == 0)
                return lib;
            DDBG("[EXL] stale cache for CR3=%08x, invalidating\n", cur_cr3);
            exl_invalidate_for_cr3(cur_cr3);
            break;
        }
    }

    if (is_loading(tmp_name)) {
        DDBG("[EXL] already loading '%s' – skip\n", tmp_name);
        return NULL;
    }
    push_loading(tmp_name);

    char path[EXL_NAME_LENGTH * 2];
    (void)snprintf(path, sizeof(path), "/system/exls/%s", tmp_name);

    int fidx = find_entry_by_path(ft, path);
    if (fidx < 0) {
        printf("[EXL] not found: %s\n", path);
        pop_loading(tmp_name);
        return NULL;
    }

    const FileEntry *fe = &ft->entries[fidx];
    uint32_t fsize = fe->file_size_bytes;

    /* Läs in i kernelbuffer men markera temporärt som USER för read_file */
    uint8_t *kfile = (uint8_t*)kmalloc(fsize);
    if (!kfile) {
        printf("[EXL] kmalloc(%u) failed\n", fsize);
        pop_loading(tmp_name);
        return NULL;
    }
    paging_update_flags((uint32_t)kfile, (uint32_t)fsize, PAGE_USER, 0);
    int r = read_file(ft, path, kfile);
    paging_update_flags((uint32_t)kfile, (uint32_t)fsize, 0, PAGE_USER);
    if (r < 0) {
        printf("[EXL] read fail: %s\n", path);
        kfree(kfile);
        pop_loading(tmp_name);
        return NULL;
    }
    uint32_t real_fsz = (uint32_t)r;

    /* Validera header och intervall */
    if (!in_file(0, sizeof(dex_header_t), real_fsz)) {
        printf("[EXL] file too small for header\n");
        kfree(kfile);
        pop_loading(tmp_name);
        return NULL;
    }

    const dex_header_t *h = (const dex_header_t *)kfile;
    if (h->magic != DEX_MAGIC ||
        h->version_major != DEX_VERSION_MAJOR ||
        h->version_minor != DEX_VERSION_MINOR) {
        printf("[EXL] bad magic/version: %s\n", tmp_name);
        kfree(kfile);
        pop_loading(tmp_name);
        return NULL;
    }

    debug_print_hdr(h);

    if (!in_file(h->text_offset,   h->text_size,   real_fsz) ||
        !in_file(h->rodata_offset, h->rodata_size, real_fsz) ||
        !in_file(h->data_offset,   h->data_size,   real_fsz)) {
        printf("[EXL] section range OOR (fsz=%u)\n", real_fsz);
        kfree(kfile);
        pop_loading(tmp_name);
        return NULL;
    }

    if ((h->import_table_count &&
         !in_file(h->import_table_offset, h->import_table_count * sizeof(dex_import_t), real_fsz)) ||
        (h->reloc_table_count &&
         !in_file(h->reloc_table_offset,  h->reloc_table_count  * sizeof(dex_reloc_t),  real_fsz)) ||
        (h->symbol_table_count &&
         !in_file(h->symbol_table_offset, h->symbol_table_count * sizeof(dex_symbol_t), real_fsz)) ||
        (h->strtab_size &&
         !in_file(h->strtab_offset,       h->strtab_size,                              real_fsz))) {
        printf("[EXL] table range OOR\n");
        kfree(kfile);
        pop_loading(tmp_name);
        return NULL;
    }

    /* Storlekar & totalsize */
    uint32_t text_sz = h->text_size;
    uint32_t ro_sz   = h->rodata_size;
    uint32_t data_sz = h->data_size;
    uint32_t bss_sz  = h->bss_size;

    uint32_t end_text = h->text_offset   + text_sz;
    uint32_t end_ro   = h->rodata_offset + ro_sz;
    uint32_t end_dat  = h->data_offset   + data_sz + bss_sz;

    uint32_t max_end = end_text;
    if (end_ro  > max_end) max_end = end_ro;
    if (end_dat > max_end) max_end = end_dat;

    uint32_t total_sz = PAGE_ALIGN_UP(max_end);

    /* Allokera user-bilden */
    uint8_t *image = umalloc(total_sz);
    if (!image) {
        printf("[EXL] umalloc(%u) fail\n", total_sz);
        kfree(kfile);
        pop_loading(tmp_name);
        return NULL;
    }
    /* RW under inladdning */
    paging_update_flags((uint32_t)image, total_sz, PAGE_PRESENT|PAGE_USER|PAGE_RW, 0);

    /* Kopiera sektioner */
    if (text_sz &&
        copy_to_user(image + h->text_offset,   kfile + h->text_offset,   text_sz) != 0)
    { ufree(image, total_sz); kfree(kfile); pop_loading(tmp_name); return NULL; }

    if (ro_sz &&
        copy_to_user(image + h->rodata_offset, kfile + h->rodata_offset, ro_sz) != 0)
    { ufree(image, total_sz); kfree(kfile); pop_loading(tmp_name); return NULL; }

    if (data_sz &&
        copy_to_user(image + h->data_offset,   kfile + h->data_offset,   data_sz) != 0)
    { ufree(image, total_sz); kfree(kfile); pop_loading(tmp_name); return NULL; }

    if (bss_sz &&
        zero_user(image + h->data_offset + data_sz, bss_sz) != 0)
    { ufree(image, total_sz); kfree(kfile); pop_loading(tmp_name); return NULL; }

    /* Relocation */
    const dex_import_t *imp    = (const dex_import_t*)(kfile + h->import_table_offset);
    const dex_reloc_t  *rel    = (const dex_reloc_t *)(kfile + h->reloc_table_offset);
    const dex_symbol_t *symtab = (const dex_symbol_t*)(kfile + h->symbol_table_offset);
    const char         *strtab = (const char*)(kfile + h->strtab_offset);

    if (do_relocate(image, total_sz, h, imp, rel, strtab, symtab) != 0) {
        printf("[EXL] relocation failed for %s\n", tmp_name);
        ufree(image, total_sz);
        kfree(kfile);
        pop_loading(tmp_name);
        return NULL;
    }

    /* Sätt rätt skydd: text/ro = RX, data+bss = RW */
    if (text_sz)
        paging_update_flags((uint32_t)(image + h->text_offset),
                            PAGE_ALIGN_UP(text_sz), 0, PAGE_RW);
    if (ro_sz)
        paging_update_flags((uint32_t)(image + h->rodata_offset),
                            PAGE_ALIGN_UP(ro_sz), 0, PAGE_RW);
    if (data_sz || bss_sz)
        paging_update_flags((uint32_t)(image + h->data_offset),
                            PAGE_ALIGN_UP(data_sz + bss_sz),
                            PAGE_PRESENT|PAGE_USER|PAGE_RW, 0);

    paging_set_user((uint32_t)image, total_sz);

    /* Kopiera metadata (kernelpersistens) */
    dex_symbol_t *symtab_copy = NULL;
    char *strtab_copy = NULL;

    if (h->symbol_table_count) {
        size_t sym_bytes = h->symbol_table_count * sizeof(dex_symbol_t);
        symtab_copy = (dex_symbol_t*)kmalloc(sym_bytes);
        if (!symtab_copy) {
            printf("[EXL] symtab alloc fail\n");
            ufree(image, total_sz);
            kfree(kfile);
            pop_loading(tmp_name);
            return NULL;
        }
        memcpy(symtab_copy, (const void*)(kfile + h->symbol_table_offset), sym_bytes);
    }
    if (h->strtab_size) {
        strtab_copy = (char*)kmalloc(h->strtab_size);
        if (!strtab_copy) {
            if (symtab_copy) kfree(symtab_copy);
            printf("[EXL] strtab alloc fail\n");
            ufree(image, total_sz);
            kfree(kfile);
            pop_loading(tmp_name);
            return NULL;
        }
        memcpy(strtab_copy, (const void*)(kfile + h->strtab_offset), h->strtab_size);
    }

    dex_header_t *hdr_copy = (dex_header_t*)kmalloc(sizeof(dex_header_t));
    if (!hdr_copy) {
        if (symtab_copy) kfree(symtab_copy);
        if (strtab_copy) kfree(strtab_copy);
        ufree(image, total_sz);
        kfree(kfile);
        pop_loading(tmp_name);
        return NULL;
    }
    memcpy(hdr_copy, h, sizeof(dex_header_t));

    exl_t *lib = &exl_files[exl_count];
    memset(lib, 0, sizeof(*lib));
    (void)strlcpy(lib->name, tmp_name, sizeof(lib->name));
    lib->image_base   = image;
    lib->image_size   = total_sz;
    lib->header       = hdr_copy;
    lib->symbol_table = symtab_copy;
    lib->symbol_count = h->symbol_table_count;
    lib->strtab       = strtab_copy;

    exl_cr3s[exl_count] = cur_cr3;
    exl_count++;

    kfree(kfile);
    pop_loading(tmp_name);

#ifdef DIFF_DEBUG
    {
        uint32_t entry = (uint32_t)image + h->entry_offset;
        dump_pde_pte(entry);
        DDBG("[EXL] entry VA=%08x (off=0x%x)\n", entry, h->entry_offset);
    }
#endif
    return lib;
}

