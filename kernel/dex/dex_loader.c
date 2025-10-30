#include "dex/dex.h"
#include "dex/exl.h"
#include "system/process.h"
#include "system/syscall.h"
#include "diff.h"
#include "string.h"
#include "stdint.h"
#include "stddef.h"
#include "stdio.h"
#include "console.h"
#include "paging.h"
#include "heap.h"
#include "system/usercopy.h"


// =======================
// Sanity helpers (non-fatal validators)
// =======================

// Print a bounded string safely from user/file area for debug logs only
static void print_str_preview(const char *s, uint32_t max)
{
    if (!s)
    {
        printf("(null)");
        return;
    }

    uint32_t n = 0;

    while (n < max && s[n] && n < 48)
    {
        putch(s[n]);
        n++;
    }

    if (n == 48)
    {
        printf("...");
    }
}

// Safe add: returns 1 on overflow, 0 ok, result in *out
static int u32_add_overflow(uint32_t a, uint32_t b, uint32_t *out)
{
    uint64_t r = (uint64_t)a + (uint64_t)b;
    *out = (uint32_t)r;

    return r > 0xFFFFFFFFull;
}

static int range_in_file(uint32_t off, uint32_t sz, size_t file_size)
{
    uint32_t end;

    if (u32_add_overflow(off, sz, &end))
    {
        return 0;
    }

    return end <= file_size;
}

static void dex_sanity_scan_header(const dex_header_t *h, size_t fsz)
{
    if (!h)
    {
        return;
    }

    if (h->magic != DEX_MAGIC)
    {
        printf("[DEX][SANITY] WARN: bad magic 0x%08x\n", h->magic);
    }

    if (h->version_major != DEX_VERSION_MAJOR || h->version_minor != DEX_VERSION_MINOR)
    {
        printf("[DEX][SANITY] WARN: version %u.%u (expected %u.%u)\n",
               h->version_major, h->version_minor, DEX_VERSION_MAJOR, DEX_VERSION_MINOR);
    }

    struct
    {
        const char *name;
        uint32_t off;
        uint32_t sz;
    } secs[] =
    {
        {".text",  h->text_offset,   h->text_size},
        {".ro",    h->rodata_offset, h->rodata_size},
        {".data",  h->data_offset,   h->data_size},
        {"strtab", h->strtab_offset, h->strtab_size},
    };

    for (unsigned i = 0; i < sizeof(secs) / sizeof(secs[0]); ++i)
    {
        if (!range_in_file(secs[i].off, secs[i].sz, fsz))
        {
            printf("[DEX][SANITY] WARN: %s out of file (off=0x%08x sz=%u fsz=%u)\n",
                   secs[i].name, secs[i].off, secs[i].sz, (unsigned)fsz);
        }
    }

    // Tables
    if (!range_in_file(h->import_table_offset, h->import_table_count * sizeof(dex_import_t), fsz))
    {
        printf("[DEX][SANITY] WARN: import table out of file (off=0x%08x cnt=%u)\n",
               h->import_table_offset, h->import_table_count);
    }

    if (!range_in_file(h->reloc_table_offset, h->reloc_table_count * sizeof(dex_reloc_t), fsz))
    {
        printf("[DEX][SANITY] WARN: reloc table out of file (off=0x%08x cnt=%u)\n",
               h->reloc_table_offset, h->reloc_table_count);
    }

    if (!range_in_file(h->symbol_table_offset, h->symbol_table_count * sizeof(dex_symbol_t), fsz))
    {
        printf("[DEX][SANITY] WARN: symbol table out of file (off=0x%08x cnt=%u)\n",
               h->symbol_table_offset, h->symbol_table_count);
    }

    // Entry inside text?
    uint32_t eo = h->entry_offset ? h->entry_offset : h->text_offset;

    if (!(eo >= h->text_offset && eo < h->text_offset + h->text_size))
    {
        printf("[DEX][SANITY] WARN: entry offset 0x%08x not inside .text [0x%08x..0x%08x)\n",
               eo, h->text_offset, h->text_offset + h->text_size);
    }
}

static void dex_sanity_scan_tables(const dex_header_t *h, const void *file_data, size_t fsz)
{
if (!h || !file_data)
{
    return;
}

const uint8_t *base = (const uint8_t*)file_data;

const char *strtab = NULL;
if (range_in_file(h->strtab_offset, h->strtab_size, fsz))
{
    strtab = (const char*)(base + h->strtab_offset);
}
else
{
    printf("[DEX][SANITY] WARN: cannot scan names, strtab invalid\n");
    return;
}

// Imports
if (range_in_file(h->import_table_offset, h->import_table_count * sizeof(dex_import_t), fsz))
{
    const dex_import_t *imp = (const dex_import_t*)(base + h->import_table_offset);

    for (uint32_t i = 0; i < h->import_table_count; ++i)
    {
        if (imp[i].exl_name_offset >= h->strtab_size)
        {
            printf("[DEX][SANITY] WARN: import[%u] exl_name_offset=%u out of strtab(%u)\n",
                   i, imp[i].exl_name_offset, h->strtab_size);
        }

        if (imp[i].symbol_name_offset >= h->strtab_size)
        {
            printf("[DEX][SANITY] WARN: import[%u] symbol_name_offset=%u out of strtab(%u)\n",
                   i, imp[i].symbol_name_offset, h->strtab_size);
        }

        // Name previews (safe & bounded)
        if (imp[i].exl_name_offset < h->strtab_size)
        {
            const char *exl_name = strtab + imp[i].exl_name_offset;
            printf("[DEX][SANITY] import[%u] exl='", i);
            print_str_preview(exl_name, h->strtab_size - imp[i].exl_name_offset);
            printf("' ");
        }
        if (imp[i].symbol_name_offset < h->strtab_size)
        {
            const char *sym_name = strtab + imp[i].symbol_name_offset;
            printf("sym='");
            print_str_preview(sym_name, h->strtab_size - imp[i].symbol_name_offset);
            printf("'\n");
        }
        else
        {
            printf("\n");
        }
    }
}
else
{
    printf("[DEX][SANITY] WARN: import table invalid, skip scanning\n");
}

// Symbols
if (range_in_file(h->symbol_table_offset, h->symbol_table_count * sizeof(dex_symbol_t), fsz))
{
    const dex_symbol_t *sym = (const dex_symbol_t*)(base + h->symbol_table_offset);

    for (uint32_t i = 0; i < h->symbol_table_count; ++i)
    {
        if (sym[i].name_offset >= h->strtab_size)
        {
            printf("[DEX][SANITY] WARN: symbol[%u] name_offset=%u out of strtab(%u)\n",
                   i, sym[i].name_offset, h->strtab_size);
        }
        else
        {
            const char *nm = strtab + sym[i].name_offset;
            printf("[DEX][SANITY] symbol[%u] name='", i);
            print_str_preview(nm, h->strtab_size - sym[i].name_offset);
            printf("'\n");
        }

        // Value offset rough sanity: should lie within sections (value is section-relative offset)
        uint32_t vo = sym[i].value_offset;
        uint32_t ok = 0;
        if (vo < h->text_size) ok = 1;
        if (vo >= h->rodata_offset && vo < h->rodata_offset + h->rodata_size) ok = 1;
        if (vo >= h->data_offset && vo < h->data_offset + h->data_size) ok = 1;
        if (!ok)
        {
            printf("[DEX][SANITY] WARN: symbol[%u] value_offset=0x%08x looks outside sections\n", i, vo);
        }
    }
}
else
{
    printf("[DEX][SANITY] WARN: symbol table invalid, skip scanning\n");
}

// Relocations
if (range_in_file(h->reloc_table_offset, h->reloc_table_count * sizeof(dex_reloc_t), fsz))
{
    const dex_reloc_t *rel = (const dex_reloc_t*)(base + h->reloc_table_offset);

    for (uint32_t i = 0; i < h->reloc_table_count; ++i)
    {
        if (rel[i].symbol_name_offset >= h->strtab_size)
        {
            printf("[DEX][SANITY] WARN: reloc[%u] symbol_name_offset=%u out of strtab(%u)\n",
                   i, rel[i].symbol_name_offset, h->strtab_size);
        }
        else
        {
            const char *nm = strtab + rel[i].symbol_name_offset;
            printf("[DEX][SANITY] reloc[%u] sym='", i);
            print_str_preview(nm, h->strtab_size - rel[i].symbol_name_offset);
            printf("'\n");
        }

        uint32_t toff = rel[i].reloc_offset;
        uint32_t ok = 0;
        if (toff >= h->text_offset && toff + 4 <= h->text_offset + h->text_size) ok = 1;
        if (toff >= h->rodata_offset && toff + 4 <= h->rodata_offset + h->rodata_size) ok = 1;
        if (toff >= h->data_offset && toff + 4 <= h->data_offset + h->data_size) ok = 1;
        if (!ok)
        {
            printf("[DEX][SANITY] WARN: reloc[%u] reloc_offset=0x%08x outside sections\n", i, toff);
        }

        if (!(rel[i].type == DEX_ABS32 || rel[i].type == DEX_PC32 || rel[i].type == DEX_RELATIVE))
        {
            printf("[DEX][SANITY] WARN: reloc[%u] unknown type=%u\n", i, rel[i].type);
        }
    }
}
else
{
    printf("[DEX][SANITY] WARN: reloc table invalid, skip scanning\n");
}
}


// Returns a sanitized copy of the header; never aborts.
// It clamps sizes/counts so subsequent code has safer bounds.
static dex_header_t dex_header_sanitize(const dex_header_t *h, size_t fsz)
{
dex_header_t sh = *h;

// Clamp sections individually to file size to avoid taking addresses of packed members.
struct Sec { const char *name; uint32_t off; uint32_t sz; } secs[4] =
{
    { ".text",  sh.text_offset,   sh.text_size },
    { ".ro",    sh.rodata_offset, sh.rodata_size },
    { ".data",  sh.data_offset,   sh.data_size },
    { "strtab", sh.strtab_offset, sh.strtab_size },
};

for (int i = 0; i < 4; ++i)
{
    uint32_t off = secs[i].off;
    uint32_t sz  = secs[i].sz;
    uint32_t end = 0;

    if (u32_add_overflow(off, sz, &end) || end > fsz)
    {
        uint32_t new_sz = (off >= fsz) ? 0u : (uint32_t)fsz - off;
        printf("[DEX][SANITY] WARN: clamping section %s at off=0x%08x to sz=%u\n",
               secs[i].name, off, new_sz);

        switch (i)
        {
            case 0: sh.text_size   = new_sz; break;
            case 1: sh.rodata_size = new_sz; break;
            case 2: sh.data_size   = new_sz; break;
            case 3: sh.strtab_size = new_sz; break;
        }
    }
}

// Clamp table counts
#define CLAMP_COUNT(off, count, elem_size, label) do {                               \
    uint32_t need_ = 0;                                                              \
    if (u32_add_overflow((off), (count) * (elem_size), &need_) || need_ > fsz)       \
    {                                                                                \
        uint32_t maxcnt_ = 0;                                                        \
        if ((off) < fsz && (elem_size))                                              \
        {                                                                            \
            maxcnt_ = (uint32_t)((fsz - (off)) / (elem_size));                       \
        }                                                                            \
        printf("[DEX][SANITY] WARN: clamping %s count from %u to %u\n",              \
               (label), (count), maxcnt_);                                           \
        (count) = maxcnt_;                                                           \
    }                                                                                \
} while (0)

CLAMP_COUNT(sh.import_table_offset, sh.import_table_count, sizeof(dex_import_t), "imports");
CLAMP_COUNT(sh.reloc_table_offset,  sh.reloc_table_count,  sizeof(dex_reloc_t),  "relocs");
CLAMP_COUNT(sh.symbol_table_offset, sh.symbol_table_count, sizeof(dex_symbol_t), "symbols");

// Fix entry inside text
{
    uint32_t eo = sh.entry_offset ? sh.entry_offset : sh.text_offset;
    if (!(eo >= sh.text_offset && eo < sh.text_offset + sh.text_size))
    {
        printf("[DEX][SANITY] WARN: fixing entry_off from 0x%08x to .text start 0x%08x\n",
               eo, sh.text_offset);
        sh.entry_offset = sh.text_offset;
    }
}

return sh;
}

// === DEBUG TOGGLES ===
// Slå på/av full dump av DEX-filen + VRAM innan körning:
#define DEX_DUMP_WHOLE_FILE 1
// Slå på mer verbos reloc-debug:
#define DEX_VERBOSE_RELOCS 1
//======================

//#define IGNORE_DEBUG

extern void enter_user_mode(uint32_t entry, uint32_t user_stack_top);
extern FileTable *file_table;

// Paging and process helpers
extern uint32_t paging_new_address_space(void);
extern void paging_switch_address_space(uint32_t cr3);
extern void paging_destroy_address_space(uint32_t cr3);

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

#ifdef DEX_VERBOSE_RELOCS
#define RDBG(...) printf(__VA_ARGS__)
#else
#define RDBG(...) DDBG(__VA_ARGS__)
#endif

// ---------- Helpers ----------

static inline int is_user_va(uint32_t a) {
    return (a >= USER_MIN) && (a < USER_MAX);
}

static inline uint32_t align_up(uint32_t x, uint32_t a) {
    return (x + (a - 1)) & ~(a - 1);
}

static inline void ddbg_dump_range(const char *tag, uint32_t va, uint32_t sz) {
    DDBG("[%s] VA=%08x..%08x (size=%u / 0x%x)\n",
         tag, va, va + (sz ? sz - 1 : 0), sz, sz);
}

#ifdef DEX_DUMP_WHOLE_FILE
static void dump_entire_dex_file(const uint8_t *buf, size_t sz)
{
    printf("[DEX][DUMP] full file size=%u bytes\n", (unsigned)sz);
    size_t off = 0;
    while (off < sz) {
        size_t chunk = (sz - off > 256) ? 256 : (sz - off);
        printf("[DEX][DUMP] +0x%08x (%u bytes)\n", (unsigned)off, (unsigned)chunk);
        hexdump_bytes(buf + off, (uint32_t)chunk);
        off += chunk;
    }
}
#endif

static int dxpp_find_and_setup(uint8_t *image_base,
                               uint32_t image_size,
                               const dex_header_t *file_hdr)
{
    if (!image_base || !file_hdr) return -1;

    uint32_t ro_off = file_hdr->rodata_offset;
    uint32_t ro_sz  = file_hdr->rodata_size;

    if (!ro_sz || (ro_off + ro_sz > image_size)) {
        // .ro saknas eller ligger utanför bilden -> skanna hela bilden (failsafe)
        ro_off = 0;
        ro_sz  = image_size;
    }

    // Först: prova början av .ro
    uint32_t dp_off = ro_off;
    dex_params_t kdp;
    int found = 0;

    if (ro_sz >= sizeof(dex_params_t) &&
        copy_from_user(&kdp, image_base + dp_off, sizeof(kdp)) == 0 &&
        kdp.magic == DEX_PARAMS_MAGIC)
    {
        found = 1;
    }
    else {
        // Skanna .ro (eller hela bilden om vi föll tillbaka)
        for (uint32_t off = ro_off; off + sizeof(dex_params_t) <= ro_off + ro_sz; off += 4) {
            uint32_t magic = 0;
            if (copy_from_user(&magic, image_base + off, sizeof(magic)) != 0)
                continue;
            if (magic == DEX_PARAMS_MAGIC) {
                if (copy_from_user(&kdp, image_base + off, sizeof(kdp)) != 0)
                    continue;
                if (kdp.magic == DEX_PARAMS_MAGIC) {
                    dp_off = off;
                    found = 1;
                    break;
                }
            }
        }
    }

    if (!found) return 1; // inget dp – OK, bara informativt

    printf("[DXPP] found dex_params_t at off=0x%08x (VA=%08x)\n",
           dp_off, (uint32_t)(uintptr_t)(image_base + dp_off));
    printf("[DXPP] BEFORE: stack_limit=%08x stack_top=%08x image_base=%08x image_size=%u\n",
           kdp.stack_limit, kdp.stack_top, kdp.image_base, kdp.image_size);

    // Uppdatera med faktisk bas + storlek (page-aligned)
    kdp.image_base = (uint32_t)(uintptr_t)image_base;
    uint32_t aligned_image_size = (image_size + 0xFFFu) & ~0xFFFu;
    kdp.image_size = aligned_image_size ? aligned_image_size : image_size;

    // Sätt default stack om 0
    if (kdp.stack_top == 0)   kdp.stack_top   = 0x7FFEF000u;
    if (kdp.stack_limit == 0) kdp.stack_limit = 0x7FFDF000u;

    if (copy_to_user(image_base + dp_off, &kdp, sizeof(kdp)) != 0) {
        printf("[DXPP] copy_to_user(dex_params_t) failed\n");
        return -4;
    }

    printf("[DXPP] AFTER: stack_limit=%08x stack_top=%08x image_base=%08x image_size=%u\n",
           kdp.stack_limit, kdp.stack_top, kdp.image_base, kdp.image_size);
    return 0;
}

// ---- VRAM-layout dump (sektioner + tabeller) ----
#ifdef DEX_DUMP_WHOLE_FILE
static void dump_mapped_dex_image(const dex_header_t *hdr,
                                  const uint8_t *image_base,
                                  uint32_t image_sz)
{
    printf("\n[DEX][VRAM] image_base=%08x image_size=%u (0x%x)\n",
           (uint32_t)(uintptr_t)image_base, image_sz, image_sz);

    // Headerfält
    printf("[DEX][VRAM][HDR] magic=%08x ver=%u.%u entry_off=0x%08x\n",
           hdr->magic, hdr->version_major, hdr->version_minor, hdr->entry_offset);
    printf("[DEX][VRAM][HDR] .text off=0x%08x sz=0x%08x | .ro off=0x%08x sz=0x%08x\n",
           hdr->text_offset,   hdr->text_size,
           hdr->rodata_offset, hdr->rodata_size);
    printf("[DEX][VRAM][HDR] .data off=0x%08x sz=0x%08x | .bss sz=0x%08x\n",
           hdr->data_offset, hdr->data_size, hdr->bss_size);
    printf("[DEX][VRAM][HDR] imports off=0x%08x cnt=%u | relocs off=0x%08x cnt=%u\n",
           hdr->import_table_offset, hdr->import_table_count,
           hdr->reloc_table_offset,  hdr->reloc_table_count);
    printf("[DEX][VRAM][HDR] symbols off=0x%08x cnt=%u | strtab off=0x%08x sz=0x%08x\n",
           hdr->symbol_table_offset, hdr->symbol_table_count,
           hdr->strtab_offset, hdr->strtab_size);

    // Sektionernas VA
    uint32_t text_va = (uint32_t)(uintptr_t)(image_base + hdr->text_offset);
    uint32_t ro_va   = (uint32_t)(uintptr_t)(image_base + hdr->rodata_offset);
    uint32_t data_va = (uint32_t)(uintptr_t)(image_base + hdr->data_offset);
    uint32_t bss_va  = data_va + hdr->data_size;

    printf("[DEX][VRAM][SECT] .text  VA=%08x..%08x (sz=0x%x)\n",
           text_va, text_va + (hdr->text_size ? hdr->text_size - 1 : 0), hdr->text_size);
    printf("[DEX][VRAM][SECT] .ro    VA=%08x..%08x (sz=0x%x)\n",
           ro_va,   ro_va   + (hdr->rodata_size ? hdr->rodata_size - 1 : 0), hdr->rodata_size);
    printf("[DEX][VRAM][SECT] .data  VA=%08x..%08x (sz=0x%x)\n",
           data_va, data_va + (hdr->data_size ? hdr->data_size - 1 : 0), hdr->data_size);
    if (hdr->bss_size) {
        printf("[DEX][VRAM][SECT] .bss   VA=%08x..%08x (sz=0x%x)\n",
               bss_va, bss_va + hdr->bss_size - 1, hdr->bss_size);
    }

    // Tabellernas VA
    uint32_t imp_va = (uint32_t)(uintptr_t)(image_base + hdr->import_table_offset);
    uint32_t rel_va = (uint32_t)(uintptr_t)(image_base + hdr->reloc_table_offset);
    uint32_t sym_va = (uint32_t)(uintptr_t)(image_base + hdr->symbol_table_offset);
    uint32_t str_va = (uint32_t)(uintptr_t)(image_base + hdr->strtab_offset);

    printf("[DEX][VRAM][TABS] imports VA=%08x cnt=%u  | relocs  VA=%08x cnt=%u\n",
           imp_va, hdr->import_table_count, rel_va, hdr->reloc_table_count);
    printf("[DEX][VRAM][TABS] symbols VA=%08x cnt=%u  | strtab  VA=%08x sz=0x%08x\n",
           sym_va, hdr->symbol_table_count, str_va, hdr->strtab_size);

    // Hexdump .text/.ro/.data början + entry
    if (hdr->text_size) {
        size_t n = hdr->text_size < 64 ? hdr->text_size : 64;
        printf("[DEX][VRAM][DUMP] .text first %zu bytes @%08x:\n", n, text_va);
        hexdump_bytes((void*)text_va, (uint32_t)n);
    }
    if (hdr->rodata_size) {
        size_t n = hdr->rodata_size < 64 ? hdr->rodata_size : 64;
        printf("[DEX][VRAM][DUMP] .ro   first %zu bytes @%08x:\n", n, ro_va);
        hexdump_bytes((void*)ro_va, (uint32_t)n);
    }
    if (hdr->data_size) {
        size_t n = hdr->data_size < 64 ? hdr->data_size : 64;
        printf("[DEX][VRAM][DUMP] .data first %zu bytes @%08x:\n", n, data_va);
        hexdump_bytes((void*)data_va, (uint32_t)n);
    }

    // Entry
    uint32_t entry_off = hdr->entry_offset ? hdr->entry_offset : hdr->text_offset;
    uint32_t entry_va  = (uint32_t)(uintptr_t)(image_base + entry_off);
    printf("[DEX][VRAM][ENTRY] entry_off=0x%08x entry_va=%08x\n", entry_off, entry_va);
    printf("[DEX][VRAM][DUMP] entry 64 bytes @%08x:\n", entry_va);
    hexdump_bytes((void*)entry_va, 64);

    printf("[DEX][VRAM] SUMMARY: base=%08x size=0x%x .text=%08x .ro=%08x .data=%08x .bss=%08x entry=%08x\n\n",
           (uint32_t)(uintptr_t)image_base, image_sz,
           text_va, ro_va, data_va, hdr->bss_size ? bss_va : 0, entry_va);
}
#endif

// ---------- Reloc helpers ----------

static const char* reloc_type_str(uint32_t t) {
    switch (t) {
        case DEX_ABS32:    return "ABS32";
        case DEX_PC32:     return "PC32";
        case DEX_RELATIVE: return "RELATIVE";
        default:           return "UNKNOWN";
    }
}

static int parse_at_off(const char *name, uint32_t *out_voff)
{
    if (!name || !out_voff) return -1;
    if (!((name[0] == '@') &&
          ((name[1] == 'o' || name[1] == 'O') &&
           (name[2] == 'f' || name[2] == 'F') &&
           (name[3] == 'f' || name[3] == 'F') &&
           name[4] == '_')))
        return -2;

    uint32_t v = 0;
    for (int i = 5; i < 13; ++i) {
        char c = name[i];
        if (c == 0) break;
        v <<= 4;
        if      (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint32_t)(10 + c - 'a');
        else if (c >= 'A' && c <= 'F') v |= (uint32_t)(10 + c - 'A');
        else return -3;
    }
    *out_voff = v;
    return 0;
}

static void* resolve_import_func(const dex_header_t *hdr, const uint8_t *file, uint32_t name_off)
{
    const char *strtab = (const char*)(file + hdr->strtab_offset);
    const char *sym = (name_off < hdr->strtab_size) ? (strtab + name_off) : "";
    const char *exl = "diffc.exl";
    return resolve_exl_symbol(exl, sym);
}

static int resolve_name_field_to_addr(
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const dex_symbol_t *symtab,
    uint32_t symtab_cnt,
    const char *strtab,
    void **import_ptrs,
    uint8_t *image,
    uint32_t sym_field,
    uint32_t *out_S
)
{
    if (!hdr || !strtab || !image || !out_S) return -1;

    if (sym_field < hdr->import_table_count) {              // import-index
        if (!import_ptrs) return -2;
        *out_S = (uint32_t)(uintptr_t)import_ptrs[sym_field];
        return 0;
    }

    if (sym_field < hdr->strtab_size) {                     // strtab-offset
        const char *name = strtab + sym_field;

        if (imp && hdr->import_table_count && import_ptrs) {
            for (uint32_t k = 0; k < hdr->import_table_count; ++k) {
                const char *imp_name = strtab + imp[k].symbol_name_offset;
                if (imp_name && name && strcmp(name, imp_name) == 0) {
                    *out_S = (uint32_t)(uintptr_t)import_ptrs[k];
                    return 0;
                }
            }
        }

        uint32_t voff = 0;
        if (parse_at_off(name, &voff) == 0) {
            *out_S = (uint32_t)(uintptr_t)image + voff;
            return 0;
        }

        if (symtab && symtab_cnt) {
            for (uint32_t s = 0; s < symtab_cnt; ++s) {
                const char *sn = strtab + symtab[s].name_offset;
                if (sn && name && strcmp(name, sn) == 0) {
                    *out_S = (uint32_t)(uintptr_t)image + symtab[s].value_offset;
                    return 0;
                }
            }
        }
        
// Fallback: try resolving via EXL default helper using name_off
{
    const uint8_t *file_base = (const uint8_t*)strtab - hdr->strtab_offset;
    void *fb = resolve_import_func(hdr, file_base, sym_field);
    if (fb) {
        *out_S = (uint32_t)(uintptr_t)fb;
        return 0;
    }
}
return -3;

    }

    *out_S = (uint32_t)(uintptr_t)image + sym_field;        // backcompat
    return 0;
}

static int resolve_imports_user(
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const char *strtab,
    void **out_ptrs,
    uint8_t *image,
    uint32_t image_sz
)
{
    if (!hdr || !imp || !strtab || !out_ptrs) return -1;
    if (hdr->import_table_count > 4096) return -1;

    for (uint32_t i = 0; i < hdr->import_table_count; ++i) {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;

        if (!exl || !*exl || !sym || !*sym) {
            printf("[DEX] bad import strings @%u\n", i);
            return -2;
        }

        DDBG("[DEX][imp] resolving %u: %s:%s\n", i, exl, sym);
        void *addr = resolve_exl_symbol(exl, sym);
        if (!addr) {
            DDBG("[DEX][imp] miss -> trying load_exl(%s)\n", exl);
            const exl_t *mod = load_exl(file_table, exl);
            if (!mod) { printf("[DEX] cannot load dependency: %s\n", exl); return -3; }
            (void)mod;
            addr = resolve_exl_symbol(exl, sym);
        }
        if (!addr) { printf("[DEX] unresolved import %s:%s\n", exl, sym); return -4; }

        uintptr_t a = (uintptr_t)addr;
        if (a >= (uintptr_t)image && a < ((uintptr_t)image + image_sz)) {
            printf("[DEX] Import %s:%s resolves inside image (%p)\n", exl, sym, addr);
            return -5;
        }
        if (!is_user_va((uint32_t)a)) {
            printf("[DEX] Import %s:%s -> kernel VA %p\n", exl, sym, addr);
            return -6;
        }

        out_ptrs[i] = addr;
        printf("[DEX][imp] %u: %s:%s -> %p\n", i, exl, sym, addr);
    }
    return 0;
}

// Relocs: ABS32=S+A, PC32=S+A-P, RELATIVE=image_base + A
static int relocate_image(
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const dex_symbol_t *symtab,
    uint32_t            symtab_cnt,
    const dex_reloc_t  *rel,
    const char         *strtab,
    uint8_t            *image,
    uint32_t            image_sz
)
{
    if (!hdr || !rel || !image || image_sz == 0) { printf("[DEX] relocate_image: bad args\n"); return -1; }
    if (hdr->import_table_count > 4096) { printf("[DEX] Too many imports (%u)\n", hdr->import_table_count); return -2; }

    void **import_ptrs = NULL;
    if (hdr->import_table_count) {
        size_t bytes = (size_t)hdr->import_table_count * sizeof(void *);
        import_ptrs = (void **)kmalloc(bytes);
        if (!import_ptrs) { printf("[DEX] kmalloc import_ptrs=%u failed\n", (unsigned)bytes); return -3; }
        memset(import_ptrs, 0, bytes);

        int r = resolve_imports_user(hdr, imp, strtab, import_ptrs, image, image_sz);
        if (r != 0) { kfree(import_ptrs); return -4; }
    }

    DDBG("[RELOC] Applying %u relocations\n", hdr->reloc_table_count);
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i) {
        uint32_t off = rel[i].reloc_offset;
        uint32_t typ = rel[i].type;

        if (off > image_sz || (image_sz - off) < 4) {
            printf("[DEX] Reloc out of range off=0x%08x image=%u type=%s idx=%u\n",
                   off, image_sz, reloc_type_str(typ), rel[i].symbol_name_offset);
            if (import_ptrs) kfree(import_ptrs);
            return -5;
        }

        uint8_t *target = image + off;

        switch (typ) {
        case DEX_ABS32: {
            uint32_t A = 0, S = 0;
            if (copy_from_user(&A, target, 4) != 0) { if (import_ptrs) kfree(import_ptrs); return -6; }
            int rr = resolve_name_field_to_addr(hdr, imp, symtab, symtab_cnt, strtab,
                                                import_ptrs, image,
                                                rel[i].symbol_name_offset, &S);
            if (rr != 0) {
                printf("[REL] ABS32 unresolved (field=%u rr=%d) @%08x\n",
                       rel[i].symbol_name_offset, rr, (uint32_t)(uintptr_t)target);
                if (import_ptrs) kfree(import_ptrs);
                return -6;
            }
            uint32_t val = S + A;
            RDBG("[REL] ABS32 @%08x : S=%08x A=%08x -> %08x\n",
                 (uint32_t)(uintptr_t)target, S, A, val);
            if (copy_to_user(target, &val, 4) != 0) { if (import_ptrs) kfree(import_ptrs); return -6; }
            break;
        }

        case DEX_PC32: {
            uint32_t A = 0, S = 0;
            if (copy_from_user(&A, target, 4) != 0) { if (import_ptrs) kfree(import_ptrs); return -6; }
            int rr = resolve_name_field_to_addr(hdr, imp, symtab, symtab_cnt, strtab,
                                                import_ptrs, image,
                                                rel[i].symbol_name_offset, &S);
            if (rr != 0) {
                printf("[REL] PC32 unresolved (field=%u rr=%d) @%08x\n",
                       rel[i].symbol_name_offset, rr, (uint32_t)(uintptr_t)target);
                if (import_ptrs) kfree(import_ptrs);
                return -6;
            }
            if (A == (uint32_t)-4) { A = 0; } // normalisera -4 från länkare
            uint32_t P = (uint32_t)(uintptr_t)target + 4;
            int32_t  val = (int32_t)S + (int32_t)A - (int32_t)P;
            RDBG("[REL] PC32  @%08x : S=%08x A=%08x P=%08x -> %08x\n",
                 (uint32_t)(uintptr_t)target, S, A, P, (uint32_t)val);
            if (copy_to_user(target, &val, 4) != 0) { if (import_ptrs) kfree(import_ptrs); return -6; }
            break;
        }

        case DEX_RELATIVE: {
            uint32_t A = 0;
            if (copy_from_user(&A, target, 4) != 0) { if (import_ptrs) kfree(import_ptrs); return -6; }
            uint32_t val = (uint32_t)(uintptr_t)image + A;
            RDBG("[REL] REL   @%08x : B=%08x A=%08x -> %08x\n",
                 (uint32_t)(uintptr_t)target, (uint32_t)(uintptr_t)image, A, val);
            if (copy_to_user(target, &val, 4) != 0) { if (import_ptrs) kfree(import_ptrs); return -6; }
            break;
        }

        default:
            printf("[DEX] Unknown reloc type=%u at #%u (off=0x%08x)\n", typ, i, off);
            if (import_ptrs) kfree(import_ptrs);
            return -7;
        }
    }

    if (import_ptrs) kfree(import_ptrs);
    DDBG("[RELOC] done\n");
    return 0;
}

// ==========================
// DEX load till nuvarande AS
// ==========================
int dex_load(const void *file_data, size_t file_size, dex_executable_t *out)
{
    const dex_header_t *hdr;
    uint32_t text_sz, ro_sz, data_sz, bss_sz, entry_off;
    uint32_t max_end, tmp, total_sz;
    uint8_t *image;
    const dex_import_t *imp;
    const dex_reloc_t *rel;
    const dex_symbol_t *symtab = NULL;
    const char *stab;

    if (!file_data || file_size < sizeof(dex_header_t) || !out) return -1;

    hdr = (const dex_header_t *)file_data;
    if (hdr->magic != DEX_MAGIC) { printf("[DEX] Invalid DEX file\n"); return -2; }

    // Sanity scan (non-fatal)
    dex_sanity_scan_header(hdr, file_size);
    dex_sanity_scan_tables(hdr, file_data, file_size);

    // Create a sanitized working header copy; we only WARN and clamp.
    dex_header_t _san = dex_header_sanitize(hdr, file_size);
    const dex_header_t *vhdr = &_san;

    // Sektioner inom fil
    if (!((vhdr->text_offset   + vhdr->text_size)   <= file_size) ||
        !((vhdr->rodata_offset + vhdr->rodata_size) <= file_size) ||
        !((vhdr->data_offset   + vhdr->data_size)   <= file_size) ||
        !((vhdr->strtab_offset + vhdr->strtab_size) <= file_size)) {
        printf("[DEX] Section offsets or sizes out of file\n");
        return -3;
    }

    uint32_t entry_offset = vhdr->entry_offset ? vhdr->entry_offset : vhdr->text_offset;
    if (!(entry_offset >= vhdr->text_offset && entry_offset < vhdr->text_offset + vhdr->text_size)) {
        printf("[DEX] Entry offset out of .text\n");
        return -3;
    }

    text_sz   = vhdr->text_size;
    ro_sz     = vhdr->rodata_size;
    data_sz   = vhdr->data_size;
    bss_sz    = vhdr->bss_size;
    entry_off = entry_offset;

    max_end = vhdr->data_offset + data_sz + bss_sz;
    tmp = vhdr->rodata_offset + ro_sz;   if (tmp > max_end) max_end = tmp;
    tmp = vhdr->text_offset   + text_sz; if (tmp > max_end) max_end = tmp;
    tmp = entry_off + 16u;              if (tmp > max_end) max_end = tmp;

    total_sz = PAGE_ALIGN_UP(max_end);

#ifdef DIFF_DEBUG
    DDBG("=== DEX HEADER DEBUG ===\n");
    DDBG("magic=0x%08x ver=%u.%u\n", vhdr->magic, vhdr->version_major, vhdr->version_minor);
    DDBG("entry_off=0x%08x\n", vhdr->entry_offset);
    DDBG(".text off=0x%08x sz=%u\n", vhdr->text_offset, vhdr->text_size);
    DDBG(".ro   off=0x%08x sz=%u\n", vhdr->rodata_offset, vhdr->rodata_size);
    DDBG(".data off=0x%08x sz=%u\n", vhdr->data_offset, vhdr->data_size);
    DDBG(".bss  sz=%u\n", vhdr->bss_size);
    DDBG("import off=0x%08x cnt=%u\n", vhdr->import_table_offset, vhdr->import_table_count);
    DDBG("reloc  off=0x%08x cnt=%u\n", vhdr->reloc_table_offset,  vhdr->reloc_table_count);
    DDBG("symtab off=0x%08x cnt=%u\n", vhdr->symbol_table_offset, vhdr->symbol_table_count);
    DDBG("strtab off=0x%08x sz =%u\n", vhdr->strtab_offset, vhdr->strtab_size);
    DDBG("TOTAL user image sz (page-aligned) = %u (0x%x)\n", total_sz, total_sz);
    DDBG("========================\n");
#endif

    image = (uint8_t *)umalloc(total_sz);
    if (!image) { printf("[DEX] Unable to allocate %u bytes for program\n", total_sz); return -4; }

    DDBG("[DEX] image base(user)=%08x size=%u\n", (uint32_t)(uintptr_t)image, total_sz);

    // Reservera och gör hela bilden P|U|RW för skrivfasen
    if (paging_reserve_range((uintptr_t)image, total_sz) != 0) { printf("[DEX] reserve_range fail\n"); ufree(image, total_sz); return -4; }
    paging_update_flags((uint32_t)image, total_sz, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    paging_flush_tlb();

    // Kopiera sektioner
    if (text_sz && copy_to_user(image + vhdr->text_offset,  (const uint8_t *)file_data + vhdr->text_offset,  text_sz) != 0) { printf("[DEX] copy .text fail\n");  ufree(image, total_sz); return -20; }
    if (ro_sz   && copy_to_user(image + vhdr->rodata_offset,(const uint8_t *)file_data + vhdr->rodata_offset,ro_sz)   != 0) { printf("[DEX] copy .ro fail\n");    ufree(image, total_sz); return -21; }
    if (data_sz && copy_to_user(image + vhdr->data_offset,  (const uint8_t *)file_data + vhdr->data_offset,  data_sz) != 0) { printf("[DEX] copy .data fail\n");  ufree(image, total_sz); return -22; }
    if (bss_sz  && zero_user(image + vhdr->data_offset + data_sz, bss_sz) != 0)                                           { printf("[DEX] zero .bss fail\n");   ufree(image, total_sz); return -23; }

    // Tabeller inom fil?
    if ((vhdr->import_table_count &&
         (vhdr->import_table_offset + vhdr->import_table_count * sizeof(dex_import_t) > file_size)) ||
        (vhdr->reloc_table_count  &&
         (vhdr->reloc_table_offset  + vhdr->reloc_table_count  * sizeof(dex_reloc_t)   > file_size)) ||
        (vhdr->symbol_table_count &&
         (vhdr->symbol_table_offset + vhdr->symbol_table_count * sizeof(dex_symbol_t)  > file_size)) ||
        (vhdr->strtab_size &&
         (vhdr->strtab_offset       + vhdr->strtab_size                                 > file_size)))
    {
        printf("[DEX] table out of file\n");
        ufree(image, total_sz);
        return -5;
    }

    imp    = (const dex_import_t *)((const uint8_t *)file_data + vhdr->import_table_offset);
    rel    = (const dex_reloc_t  *)((const uint8_t *)file_data + vhdr->reloc_table_offset);
    symtab = (const dex_symbol_t *)((const uint8_t *)file_data + vhdr->symbol_table_offset);
    stab   = (const char         *)((const uint8_t *)file_data + vhdr->strtab_offset);

    ddbg_dump_range("DEX.text",   (uint32_t)(uintptr_t)(image + vhdr->text_offset),   vhdr->text_size);
    ddbg_dump_range("DEX.rodata", (uint32_t)(uintptr_t)(image + vhdr->rodata_offset), vhdr->rodata_size);
    ddbg_dump_range("DEX.data",   (uint32_t)(uintptr_t)(image + vhdr->data_offset),   vhdr->data_size);
    if (bss_sz) ddbg_dump_range("DEX.bss", (uint32_t)(uintptr_t)(image + vhdr->data_offset + data_sz), bss_sz);

    // Relocs sker medan allt är RW
    if (relocate_image(hdr, imp, symtab, vhdr->symbol_table_count, rel, stab, image, total_sz) != 0) {
        ufree(image, total_sz);
        return -6;
    }

    // Skärp rättigheter
    if (text_sz) {
        paging_update_flags((uint32_t)(image + vhdr->text_offset), PAGE_ALIGN_UP(text_sz), 0, PAGE_RW); // RX
    }
    if (ro_sz) {
        paging_update_flags((uint32_t)(image + vhdr->rodata_offset), PAGE_ALIGN_UP(ro_sz), 0, PAGE_RW); // R
    }
    if (data_sz || bss_sz) {
        paging_update_flags((uint32_t)(image + vhdr->data_offset), PAGE_ALIGN_UP(data_sz + bss_sz),
                            PAGE_PRESENT | PAGE_USER | PAGE_RW, 0); // RW
    }
    paging_flush_tlb();

#ifdef DEX_DUMP_WHOLE_FILE
    dump_mapped_dex_image(hdr, image, total_sz);
#endif

    // DPAR/stack-setup (mappar stack med P|U|RW)
    (void)dxpp_find_and_setup(image, total_sz, hdr);

    out->image_base = image;
    out->header     = (dex_header_t *)hdr;
    out->dex_entry  = (void (*)(void))((uint32_t)image + entry_off);
    out->image_size = total_sz;

#ifdef DIFF_DEBUG
    DDBG("[DEX] entry bytes (64 bytes):\n");
    hexdump_bytes((void *)((uint32_t)image + entry_off), 64);
    DDBG("[DEX] entry VA=%08x off=0x%x\n", (uint32_t)image + entry_off, entry_off);
#endif
    return 0;
}

// ==========================
// DEX körning i nuvarande AS
// ==========================

static int build_user_stack_with_args_ex(uint32_t stk_top,
                                         const char *prog_name,
                                         int argc_in, char **argv_in,
                                         uint32_t *out_user_sp,
                                         uint32_t *out_argv_vec_u,
                                         uint32_t *out_argc_u,
                                         uint32_t *out_cmdline_u)
{
    DDBG("[USTACK] top=%08x prog='%s' argc=%d argv_in=%p\n",
         stk_top, prog_name ? prog_name : "(null)", argc_in, (void*)argv_in);

    if (!is_user_va(stk_top)) return -1;

    uint32_t sp = stk_top;
    const uint32_t scratch_bytes = 8 * 1024;
    uint32_t scratch_lo = (sp - scratch_bytes) & ~0xF;
    if (!is_user_va(scratch_lo)) return -2;

    ddbg_dump_range("USTACK map", scratch_lo, PAGE_ALIGN_UP(sp - scratch_lo));
    paging_reserve_range(scratch_lo, PAGE_ALIGN_UP(sp - scratch_lo));
    paging_update_flags(scratch_lo, PAGE_ALIGN_UP(sp - scratch_lo), PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    uint32_t str_sp = sp;
    uint32_t argv_count = (argc_in > 0 ? (uint32_t)argc_in : 0);
    if (!prog_name) prog_name = "program";

    size_t pn_len = strlen(prog_name) + 1;
    str_sp -= (uint32_t)pn_len;
    uint32_t prog_name_u = str_sp;
    if (copy_to_user((void*)prog_name_u, prog_name, pn_len) != 0) return -3;
    DDBG("[USTACK] prog_name_u=%08x '%s' (len=%u)\n",
         prog_name_u, prog_name, (unsigned)pn_len);

    uint32_t cmdline_u = prog_name_u;

    uint32_t *argv_ptrs = (uint32_t *)kmalloc(sizeof(uint32_t) * (argv_count + 2));
    if (!argv_ptrs) return -4;
    memset(argv_ptrs, 0, sizeof(uint32_t) * (argv_count + 2));

    argv_ptrs[0] = prog_name_u;
    for (uint32_t i = 0; i < argv_count; ++i) {
        const char *s = argv_in ? argv_in[i] : "";
        size_t sl = strlen(s) + 1;
        str_sp -= (uint32_t)sl;
        uint32_t u = str_sp;
        if (copy_to_user((void*)u, s, sl) != 0) { kfree(argv_ptrs); return -5; }
        argv_ptrs[i + 1] = u;
        DDBG("[USTACK] argv[%u] \"%s\" -> %08x (len=%u)\n", i+1, s, u, (unsigned)sl);
    }
    uint32_t argv_items = argv_count + 1;

    uint32_t argv_vec_bytes = sizeof(uint32_t) * (argv_items + 1);
    str_sp -= argv_vec_bytes;
    uint32_t argv_vec_u = str_sp;
    if (copy_to_user((void*)argv_vec_u, argv_ptrs, argv_vec_bytes) != 0) { kfree(argv_ptrs); return -6; }

    kfree(argv_ptrs);

    uint32_t dummy_ret = 0;
    uint32_t argc_u = argv_items;
    uint32_t envp_u = 0;
    str_sp -= 4; if (copy_to_user((void*)str_sp, &envp_u, 4) != 0) return -7; // envp=NULL
    str_sp -= 4; if (copy_to_user((void*)str_sp, &argv_vec_u, 4) != 0) return -7; // argv
    str_sp -= 4; if (copy_to_user((void*)str_sp, &argc_u, 4) != 0) return -7;   // argc
    str_sp -= 4; if (copy_to_user((void*)str_sp, &dummy_ret, 4) != 0) return -7;// ret

    DDBG("[USTACK] final sp=%08x\n", (str_sp & ~0xFu));
    str_sp &= ~0xFu;

    if (out_user_sp)    *out_user_sp    = str_sp;
    if (out_argv_vec_u) *out_argv_vec_u = argv_vec_u;
    if (out_argc_u)     *out_argc_u     = argc_u;
    if (out_cmdline_u)  *out_cmdline_u  = cmdline_u;
    return 0;
}

static int install_entry_thunk(uint32_t near_sp,
                               uint32_t argv_vec_u,
                               uint32_t argc_u,
                               uint32_t real_entry,
                               uint32_t exit_eip,
                               uint32_t *out_thunk_eip)
{
    if (!is_user_va(near_sp) || !is_user_va(real_entry)) return -1;

    const uint32_t curr_page = near_sp & ~0xFFFu;
    uint32_t thunk_page = curr_page + 0x1000u;
    if (!is_user_va(thunk_page) || (thunk_page + 0x1000u) > USER_MAX) {
        thunk_page = (USER_MAX & ~0xFFFu) - 0x2000u;
    }

    if (paging_reserve_range(thunk_page, 0x1000u) != 0) return -1;
    paging_update_flags(thunk_page, 0x1000u, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    uint32_t thunk_va = (thunk_page + 0x20u + 15u) & ~0xFu;

    uint8_t stub[64];
    uint8_t *p = stub;

    // cld
    *p++ = 0xFC;
    // DS/ES/FS/GS = 0x23
    *p++ = 0x6A; *p++ = 0x23; *p++ = 0x1F;               // push 0x23 ; pop ds
    *p++ = 0x6A; *p++ = 0x23; *p++ = 0x07;               // push 0x23 ; pop es
    *p++ = 0x6A; *p++ = 0x23; *p++ = 0x0F; *p++ = 0xA1;  // push 0x23 ; pop fs
    *p++ = 0x6A; *p++ = 0x23; *p++ = 0x0F; *p++ = 0xA9;  // push 0x23 ; pop gs

    // push argv ; push argc ; call entry
    *p++ = 0x68; memcpy(p, &argv_vec_u, 4); p += 4;
    *p++ = 0x68; memcpy(p, &argc_u,     4); p += 4;
    *p++ = 0xB8; memcpy(p, &real_entry, 4); p += 4; // mov eax, entry
    *p++ = 0xFF; *p++ = 0xD0;                        // call eax

    // exit(ret) om tillgänglig
    *p++ = 0x50;                                     // push eax
    *p++ = 0xB8; memcpy(p, &exit_eip, 4); p += 4;    // mov eax, exit
    *p++ = 0x85; *p++ = 0xC0;                        // test eax,eax
    *p++ = 0x74; *p++ = 0x02;                        // jz +2
    *p++ = 0xFF; *p++ = 0xD0;                        // call eax

    // jmp $
    *p++ = 0xEB; *p++ = 0xFE;

    const uint32_t stub_len = (uint32_t)(p - stub);
    if (copy_to_user((void*)thunk_va, stub, stub_len) != 0) {
        paging_update_flags(thunk_page, 0x1000u, 0, PAGE_PRESENT);
        return -3;
    }

    paging_update_flags(thunk_page, 0x1000u, PAGE_PRESENT | PAGE_USER, PAGE_RW); // RX
    if (out_thunk_eip) *out_thunk_eip = thunk_va;
    return 0;
}

static int install_safe_return_thunk(uint32_t user_sp, uint32_t *out_va)
{
    uint8_t thunk_code[] = { 0xEB, 0xFE }; // jmp $
    uint32_t thunk_len = sizeof(thunk_code);

    uint32_t va = (user_sp - 0x40) & ~0xF;
    if (paging_reserve_range(va & ~0xFFFu, 0x1000u) != 0) return -1;
    paging_update_flags(va & ~0xFFFu, 0x1000u, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    if (copy_to_user((void*)(uintptr_t)va, thunk_code, thunk_len) != 0) return -1;

    paging_update_flags(va & ~0xFFFu, 0x1000u, PAGE_PRESENT | PAGE_USER, PAGE_RW); // RX
    *out_va = va;
    DDBG("[DEX] installed safe-return thunk @%08x\n", va);
    return 0;
}

// [Hjälp] hitta exit() i exl
static uint32_t find_exit_runtime_addr(uint8_t *image_base, const dex_header_t *hdr)
{
    (void)image_base;
    if (!hdr || !hdr->import_table_count || !hdr->strtab_size) return 0;
    const dex_import_t *imp = (const dex_import_t*)((uintptr_t)image_base + hdr->import_table_offset);
    const char *strtab      = (const char*)((uintptr_t)image_base + hdr->strtab_offset);
    for (uint32_t i=0;i<hdr->import_table_count;i++){
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;
        if (exl && sym && strcmp(sym,"exit")==0) {
            void *p = resolve_exl_symbol(exl, "exit");
            if (p) return (uint32_t)(uintptr_t)p;
        }
    }
    return 0;
}

// ==========================
// dex_run (nuvarande process)
// ==========================
int dex_run(const FileTable *ft, const char *path, int argc, char **argv)
{
    int file_index;
    const FileEntry *fe;
    uint8_t *buffer;
    dex_executable_t dex;
    int rc;

    if (!ft || !path || !path[0]) return -1;

    file_index = find_entry_by_path(ft, path);
    if (file_index < 0) { printf("[DEX] ERROR: File not found: %s\n", path); return -1; }

    fe = &ft->entries[file_index];
    if (!fe->file_size_bytes) { printf("[DEX] ERROR: Empty file: %s\n", path); return -2; }

    buffer = (uint8_t *)kmalloc(fe->file_size_bytes);
    if (!buffer) { printf("[DEX] ERROR: Unable to allocate %u bytes\n", fe->file_size_bytes); return -3; }

    if (read_file(ft, path, buffer) < 0) { printf("[DEX] ERROR: Failed to read file: %s\n", path); kfree(buffer); return -4; }

#ifdef DEX_DUMP_WHOLE_FILE
    dump_entire_dex_file(buffer, fe->file_size_bytes);
#endif

    DDBG("[DEX] dex_run path='%s' size=%u\n", path, fe->file_size_bytes);
    rc = dex_load(buffer, fe->file_size_bytes, &dex);
    if (rc != 0) { kfree(buffer); return rc; }

    // DPAR/stack
    uint32_t user_sp = 0, argv_vec_u = 0, argc_u = 0, cmdline_u = 0;
    const uint32_t stk_sz  = 64 * 1024;
    const uint32_t stk_top = (USER_MAX & ~0xFFFu) - 0x1000;
    const uint32_t stk_lo  = (stk_top - stk_sz) & ~0xFFFu;
    const uint32_t map_sz  = PAGE_ALIGN_UP(stk_top - stk_lo);

    ddbg_dump_range("USTACK default map", stk_lo, map_sz);
    paging_reserve_range(stk_lo, map_sz);
    paging_update_flags(stk_lo, map_sz, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    if (build_user_stack_with_args_ex(stk_top, path, argc, argv, &user_sp, &argv_vec_u, &argc_u, &cmdline_u) != 0)
        user_sp = stk_top;

    uint32_t entry_eip = (uint32_t)(uintptr_t)dex.dex_entry;
    uint32_t exit_eip  = find_exit_runtime_addr(dex.image_base, dex.header);
    uint32_t thunk_eip = entry_eip;
    if (install_entry_thunk(user_sp, argv_vec_u, argc_u, entry_eip, exit_eip, &thunk_eip) == 0) {
        entry_eip = thunk_eip;
    }
    DDBG("[DEX] final entry_eip(thunk)=%08x\n", entry_eip);

    // patch dummy ret
    uint32_t safe_ret = exit_eip;
    if (!safe_ret) {
        if (install_safe_return_thunk(user_sp, &safe_ret) != 0) { safe_ret = 0xFFFFFFFFu; }
    }
    (void)copy_to_user((void*)(uintptr_t)user_sp, &safe_ret, sizeof(uint32_t));
    DDBG("[DEX] patched dummy_ret on user stack -> %08x\n", safe_ret);

    // Heap window ovanför image
    uintptr_t heap_base = PAGE_ALIGN_UP((uint32_t)(uintptr_t)dex.image_base + dex.image_size);
    uintptr_t heap_size = 64u << 20;
    DDBG("[DEX] heap window base=%08x size=%uMB\n", (uint32_t)heap_base, (unsigned)(heap_size >> 20));
    system_brk_init_window(heap_base, heap_size);
    paging_reserve_range(heap_base, heap_size);
    // Lås upp 8MB initialt:
    system_brk_set((void *)(heap_base + (8u<<20)));

    DDBG("[DEX] jumping to user: eip=%08x esp=%08x\n", entry_eip, user_sp);
    enter_user_mode(entry_eip, user_sp);

    kfree(buffer);
    return 0;
}

// ==========================
// dex_spawn_process (ny process/CR3)
// ==========================
int dex_spawn_process(const FileTable *ft, const char *path, int argc, char **argv)
{
    int file_index;
    const FileEntry *fe;
    uint8_t *buffer;
    uint32_t cr3_parent;
    uint32_t cr3_child;
    dex_executable_t dex;
    int load_rc;
    process_t *p;

#ifdef DIFF_DEBUG
    printf("dex_spawn_process heap_dump:\n");
    heap_dump();
#endif

    if (!ft || !path || !path[0]) return -1;

    file_index = find_entry_by_path(ft, path);
    if (file_index < 0) { printf("[DEX] ERROR: File not found: %s\n", path); return -2; }

    fe = &ft->entries[file_index];
    if (!fe->file_size_bytes) { printf("[DEX] ERROR: Empty file: %s\n", path); return -3; }

    buffer = (uint8_t *)kmalloc(fe->file_size_bytes);
    if (!buffer) { printf("[DEX] ERROR: Unable to allocate %u bytes\n", fe->file_size_bytes); return -4; }

#ifdef DIFF_DEBUG
    printf("Trying to read_file(%p, %s, buffer)\n", ft, path);
    printf("Buffer attempted to allocate: %d bytes\n", fe->file_size_bytes);
#endif

    if (read_file(ft, path, buffer) < 0) {
        printf("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buffer);
        return -5;
    }

#ifdef DEX_DUMP_WHOLE_FILE
    dump_entire_dex_file(buffer, fe->file_size_bytes);
#endif

    cr3_parent = read_cr3_local();
    cr3_child  = paging_new_address_space();
    if (!cr3_child) {
        printf("[DEX] ERROR: paging_new_address_space failed");
        kfree(buffer);
        return -6;
    }
    DDBG("[DEX] CR3 parent=%08x new child=%08x\n", cr3_parent, cr3_child);

    paging_switch_address_space(cr3_child);
    DDBG("[DEX] switched to child AS\n");

    // Nollställ ev. modulcacher för det här CR3:et
    exl_invalidate_for_cr3(read_cr3_local());

    // Rensa användarkartor och heap
    paging_free_all_user();
    paging_user_heap_reset();
    DDBG("[DEX] child AS: cleared user mappings & heap window\n");

    load_rc = dex_load(buffer, fe->file_size_bytes, &dex);
    if (load_rc != 0)
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: dex_load rc=%d\n", load_rc);
        return -7;
    }

    // Bygg stack i child
    uint32_t user_sp = 0, argv_vec_u = 0, argc_u = 0, cmdline_u = 0;
    const uint32_t stk_sz  = 64 * 1024;
    const uint32_t stk_top = (USER_MAX & ~0xFFFu) - 0x1000;
    const uint32_t stk_lo  = (stk_top - stk_sz) & ~0xFFFu;
    const uint32_t map_sz  = PAGE_ALIGN_UP(stk_top - stk_lo);

    ddbg_dump_range("USTACK default map (child)", stk_lo, map_sz);
    paging_reserve_range(stk_lo, map_sz);
    paging_update_flags(stk_lo, map_sz, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    if (build_user_stack_with_args_ex(stk_top, path, argc, argv,
                                      &user_sp, &argv_vec_u, &argc_u, &cmdline_u) != 0)
        user_sp = stk_top;

    uint32_t entry_eip = (uint32_t)(uintptr_t)dex.dex_entry;
    uint32_t exit_eip  = find_exit_runtime_addr(dex.image_base, dex.header);
    uint32_t thunk_eip = entry_eip;
    if (install_entry_thunk(user_sp, argv_vec_u, argc_u, entry_eip, exit_eip, &thunk_eip) == 0) {
        entry_eip = thunk_eip;
    }
    DDBG("[DEX] child entry_eip(thunk)=%08x user_sp=%08x\n", entry_eip, user_sp);

    uint32_t safe_ret = exit_eip;
    if (!safe_ret) {
        if (install_safe_return_thunk(user_sp, &safe_ret) != 0) { safe_ret = 0xFFFFFFFFu; }
    }
    (void)copy_to_user((void*)(uintptr_t)user_sp, &safe_ret, sizeof(uint32_t));
    DDBG("[DEX] child patched dummy_ret -> %08x\n", safe_ret);

    // Heap window above the image
    uintptr_t heap_base = PAGE_ALIGN_UP((uint32_t)(uintptr_t)dex.image_base + dex.image_size);
    uintptr_t heap_size = 64u << 20;

    DDBG("[DEX] child heap window base=%08x size=%uMB\n", (uint32_t)heap_base, (unsigned)(heap_size >> 20));
    system_brk_init_window(heap_base, heap_size);
    paging_reserve_range(heap_base, heap_size);
    system_brk_set((void *)(heap_base + (8u<<20)));

    p = process_create_user_with_cr3(entry_eip, user_sp, cr3_child, 16384);
    if (!p)
    {
        paging_switch_address_space(cr3_child);
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: process_create_user_with_as failed");
        return -12;
    }

    paging_switch_address_space(cr3_parent);
    DDBG("[DEX] switched back to parent AS\n");

#ifdef DIFF_DEBUG
    int tid_dbg = (p && p->main_thread) ? p->main_thread->thread_id : -1;
#else
    int tid_dbg = -1;
#endif

    int pid = process_pid(p);
    DDBG("[DEX] spawn: pid=%d (main tid=%d) parent_cr3=%08x child_cr3=%08x\n",
         pid, tid_dbg, cr3_parent, cr3_child);

    kfree(buffer);
    return pid;
}




