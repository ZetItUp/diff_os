#include "drivers/module_loader.h"
#include "drivers/ddf.h"
#include "diff.h"
#include "heap.h"
#include "interfaces.h"
#include "irq.h"
#include "stdio.h"
#include "string.h"
#include "stddef.h"
#include "stdint.h"

#define IGNORE_DEBUG

#ifndef NULL
#define NULL ((void*)0)
#endif

#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
    #define DDBG(...) printf(__VA_ARGS__)
#else
    #define DDBG(...) do {} while (0)
#endif

extern FileTable *file_table;
extern kernel_exports_t g_exports;

// NOTE: Addend is an extra value added to the symbol address during relocation

// Basic helpers

static inline uint32_t max_u32(uint32_t a, uint32_t b)
{
    return (a > b) ? a : b;
}

// Check if pointer is inside the loaded module image
int ptr_in_module(const ddf_module_t *m, const void *ptr)
{
    if (!m || !m->module_base || m->size_bytes == 0 || !ptr)
    {
        return 0;
    }

    const uint8_t *lo = (const uint8_t *)m->module_base;
    const uint8_t *hi = lo + m->size_bytes;
    const uint8_t *p  = (const uint8_t *)ptr;

    return (p >= lo) && (p < hi);
}

// Print header of the exports block
void dump_exports_header(const kernel_exports_t *e)
{
#ifdef DIFF_DEBUG
    // Copy to aligned scratch
    uint32_t scratch[8] = {0};
    size_t avail = sizeof(*e);
    size_t want  = sizeof(scratch);
    size_t ncopy = (avail < want) ? avail : want;

    memcpy((void *)scratch, (const void *)e, ncopy);

    printf("[KEXP] head: %08x %08x %08x %08x  %08x %08x %08x %08x\n",
           scratch[0], scratch[1], scratch[2], scratch[3],
           scratch[4], scratch[5], scratch[6], scratch[7]);
#else
    (void)e;
#endif
}

// Check that a sub range fits inside a buffer
static int range_ok(uint32_t off, uint32_t size, uint32_t total)
{
    if (off > total)
    {
        return 0;
    }

    if (size == 0)
    {
        return 1;
    }

    if (size > 0xFFFFFFFFu - off)
    {
        return 0;
    }

    return (off + size) <= total;
}

// Write and read helpers for 32 bit words
static inline void wr32(void *p, uint32_t v)
{
    *(uint32_t *)p = v;
}

static inline uint32_t rd32(const void *p)
{
    return *(const uint32_t *)p;
}

// Validate DDF header
static int validate_header(const ddf_header_t *h, uint32_t file_bytes, uint32_t *out_min_total)
{
    uint32_t need_total;

    if (!h || !out_min_total)
    {
        return -1;
    }

    if (h->magic != DDF_MAGIC)
    {
        DDBG("[MODULE] ERROR: Bad DDF magic: 0x%08x\n", (unsigned)h->magic);

        return -1;
    }

    if (h->version_major != 1)
    {
        DDBG("[MODULE] ERROR: Unsupported DDF major version: %u\n", (unsigned)h->version_major);

        return -1;
    }

#ifdef DIFF_DEBUG
    if (h->version_minor != 0)
    {
        printf("[MODULE] WARN: DDF minor version %u (expected 0)\n", (unsigned)h->version_minor);
    }
#endif

    // Sections must be inside the disk image
    if (!range_ok(h->text_offset,   h->text_size,   file_bytes))
    {
        DDBG("[MODULE] ERROR: .text OOB\n");

        return -1;
    }

    if (!range_ok(h->rodata_offset, h->rodata_size, file_bytes))
    {
        DDBG("[MODULE] ERROR: .rodata OOB\n");

        return -1;
    }

    if (!range_ok(h->data_offset,   h->data_size,   file_bytes))
    {
        DDBG("[MODULE] ERROR: .data OOB\n");

        return -1;
    }

    // Tables must fit in file
    {
        uint32_t sym_bytes = h->symbol_table_count * (uint32_t)sizeof(ddf_symbol_t);

        if (!range_ok(h->symbol_table_offset, sym_bytes, file_bytes))
        {
            DDBG("[MODULE] ERROR: symtab OOB\n");

            return -1;
        }
    }

    if (!range_ok(h->strtab_offset, 1, file_bytes))
    {
        DDBG("[MODULE] ERROR: strtab OOB\n");

        return -1;
    }

    {
        uint32_t rel_bytes = h->reloc_table_count * (uint32_t)sizeof(ddf_reloc_t);

        if (!range_ok(h->reloc_table_offset, rel_bytes, file_bytes))
        {
            DDBG("[MODULE] ERROR: reloc OOB\n");

            return -1;
        }
    }

    need_total = file_bytes;

    if (h->bss_size != 0)
    {
        uint32_t bss_end;

        if (h->bss_offset > 0xFFFFFFFFu - h->bss_size)
        {
            DDBG("[MODULE] ERROR: BSS overflow\n");

            return -1;
        }

        bss_end = h->bss_offset + h->bss_size;

        if (bss_end > need_total)
        {
            need_total = bss_end;
        }
    }

    *out_min_total = need_total;

    return 0;
}

// Print key header fields in debug mode
static void debug_dump_header(const ddf_header_t *h, uint32_t file_bytes)
{
#ifndef DIFF_DEBUG
    (void)h; (void)file_bytes;
#else
    if (!h)
    {
        return;
    }

    printf("[DDF] magic=%08x ver=%u.%u file=%u bytes\n",
           (unsigned)h->magic, (unsigned)h->version_major, (unsigned)h->version_minor, (unsigned)file_bytes);

    printf("[DDF] entry init@+%08x exit@+%08x irq@+%08x irq_num=%u\n",
           (unsigned)h->init_offset, (unsigned)h->exit_offset, (unsigned)h->irq_offset, (unsigned)h->irq_number);

    printf("[DDF] text  off=%08x size=%08x\n", (unsigned)h->text_offset,   (unsigned)h->text_size);
    printf("[DDF] rodat off=%08x size=%08x\n", (unsigned)h->rodata_offset, (unsigned)h->rodata_size);
    printf("[DDF] data  off=%08x size=%08x\n", (unsigned)h->data_offset,   (unsigned)h->data_size);
    printf("[DDF] bss   off=%08x size=%08x\n", (unsigned)h->bss_offset,    (unsigned)h->bss_size);

    printf("[DDF] syms  off=%08x count=%u (size=%u)\n",
           (unsigned)h->symbol_table_offset, (unsigned)h->symbol_table_count,
           (unsigned)(h->symbol_table_count * (uint32_t)sizeof(ddf_symbol_t)));

    printf("[DDF] str   off=%08x\n", (unsigned)h->strtab_offset);
    printf("[DDF] rel   off=%08x count=%u (size=%u)\n",
           (unsigned)h->reloc_table_offset, (unsigned)h->reloc_table_count,
           (unsigned)(h->reloc_table_count * (uint32_t)sizeof(ddf_reloc_t)));

    const ddf_symbol_t *sy = (const ddf_symbol_t *)((const uint8_t*)h + h->symbol_table_offset);
    const char *st = (const char *)((const uint8_t*)h + h->strtab_offset);

    printf("[DDF] symbols (%u):\n", (unsigned)h->symbol_table_count);

    for (uint32_t i = 0; i < h->symbol_table_count; i++)
    {
        const char *nm = st + sy[i].name_offset;

        printf("  [%u] name='%s' value_off=0x%08x type=%u\n",
               (unsigned)i, nm ? nm : "", (unsigned)sy[i].value_offset, (unsigned)sy[i].type);
    }
#endif
}

// Relocations

static int apply_relocations(void *base, const ddf_header_t *h, uint32_t total_bytes)
{
    if (!h || !base)
    {
        return -1;
    }

    const ddf_reloc_t *rels = (const ddf_reloc_t *)((const uint8_t*)base + h->reloc_table_offset);
    const ddf_symbol_t *syms = (const ddf_symbol_t *)((const uint8_t*)base + h->symbol_table_offset);

    DDBG("[RELOC] Applying %u relocations\n", (unsigned)h->reloc_table_count);

    for (uint32_t i = 0; i < h->reloc_table_count; i++)
    {
        const ddf_reloc_t *r = &rels[i];
        uint32_t where_off = r->r_offset;

        if (!range_ok(where_off, 4, total_bytes))
        {
            DDBG("[RELOC] ERROR: r[%u] target OOB off=%u\n", (unsigned)i, (unsigned)where_off);

            return -1;
        }

        uint8_t *loc = (uint8_t*)base + where_off;

        uint32_t S = 0;
        uint32_t A = (uint32_t)r->r_addend;
        int have_sym = (r->r_sym_index != 0xFFFFFFFFu);

        if (have_sym)
        {
            if (r->r_sym_index >= h->symbol_table_count)
            {
                DDBG("[RELOC] ERROR: r[%u] bad sym index %u\n", (unsigned)i, (unsigned)r->r_sym_index);

                return -1;
            }

            const ddf_symbol_t *sym = &syms[r->r_sym_index];
            uint32_t voff = sym->value_offset;

            if (!range_ok(voff, 1, total_bytes))
            {
                DDBG("[RELOC] ERROR: r[%u] sym value OOB off=%u\n", (unsigned)i, (unsigned)voff);

                return -1;
            }

            S = (uint32_t)((uintptr_t)base + voff);
        }
        else
        {
            // In this format the addend holds a module relative target offset
            uint32_t t_off = A;

            if (!range_ok(t_off, 1, total_bytes))
            {
                DDBG("[RELOC] ERROR: r[%u] addend target OOB %u\n", (unsigned)i, (unsigned)t_off);

                return -1;
            }

            S = (uint32_t)((uintptr_t)base + t_off);
            A = 0; // Prevent double add
        }

        switch (r->r_type)
        {
            case DDF_RELOC_ABS32:
            {
                uint32_t V = S + A;

                wr32(loc, V);

                if (have_sym)
                {
                    DDBG("[RELOC] #%u ABS32 off=%08x -> %08x sym=%u A=%d\n",
                           (unsigned)i, (unsigned)where_off, (unsigned)V,
                           (unsigned)r->r_sym_index, (int)r->r_addend);
                }
                else
                {
                    DDBG("[RELOC] #%u ABS32 off=%08x -> %08x sym=none A=0\n",
                           (unsigned)i, (unsigned)where_off, (unsigned)V);
                }
                break;
            }

            case DDF_RELOC_REL32:
            {
                // i386 style PC relative displacement
                uint32_t Pp4 = (uint32_t)((uintptr_t)loc + 4u);
                int32_t disp = (int32_t)((int64_t)S + (int32_t)A - (int64_t)Pp4);

                wr32(loc, (uint32_t)disp);

                if (have_sym)
                {
                    DDBG("[RELOC] #%u REL32 off=%08x P+4=%08x S=%08x A=%d disp=%08x sym=%u\n",
                           (unsigned)i, (unsigned)where_off, (unsigned)Pp4, (unsigned)S,
                           (int)r->r_addend, (unsigned)disp, (unsigned)r->r_sym_index);
                }
                else
                {
                    DDBG("[RELOC] #%u REL32 off=%08x P+4=%08x S=%08x A=0 disp=%08x sym=none\n",
                           (unsigned)i, (unsigned)where_off, (unsigned)Pp4, (unsigned)S, (unsigned)disp);
                }

#ifdef DIFF_DEBUG
                // Show resolved destination for sanity
                {
                    uint32_t disp_written = rd32(loc);
                    uint32_t dest = (uint32_t)((uintptr_t)loc + 4u + disp_written);
                    DDBG("[RELOC] dest=%08x\n", (unsigned)dest);
                }
#endif
                break;
            }

            case DDF_RELOC_RELATIVE:
            {
                // If addend is inside module treat as module relative else keep raw
                uint32_t add = (uint32_t)r->r_addend;
                uint32_t val = range_ok(add, 1, total_bytes)
                               ? (uint32_t)((uintptr_t)base + add)
                               : add;

                if (range_ok(add, 1, total_bytes))
                {
                    DDBG("[RELOC] #%u RELATIVE off=%08x -> %08x\n",
                           (unsigned)i, (unsigned)where_off, (unsigned)val);
                }
                else
                {
                    DDBG("[RELOC] #%u RELATIVE off=%08x addend outside %u -> %08x\n",
                           (unsigned)i, (unsigned)where_off, (unsigned)add, (unsigned)val);
                }
                wr32(loc, val);

                break;
            }

            default:
            {
                DDBG("[RELOC] ERROR: r[%u] unknown type %u\n", (unsigned)i, (unsigned)r->r_type);

                return -1;
            }
        }

        // Guard against writes into a null page
        if ((uintptr_t)loc < 0x1000u)
        {
            DDBG("[RELOC] ERROR: wrote into NULL page loc=%p\n", (void *)loc);

            return -1;
        }
    }

    return 0;
}

// Symbol lookup inside a module
void *ddf_find_symbol(void *module_base, ddf_header_t *header, const char *name)
{
    if (!module_base || !header || !name)
    {
        return NULL;
    }

    if (header->symbol_table_count == 0)
    {
        return NULL;
    }

    const ddf_symbol_t *syms = (const ddf_symbol_t *)((const uint8_t*)module_base + header->symbol_table_offset);
    const char *strtab = (const char *)((const uint8_t*)module_base + header->strtab_offset);

    for (uint32_t i = 0; i < header->symbol_table_count; i++)
    {
        const ddf_symbol_t *s = &syms[i];
        const char *nm = strtab + s->name_offset;

        if (!nm || *nm == '\0')
        {
            continue;
        }

        if (strcmp(nm, name) == 0)
        {
            return (void *)((uint8_t*)module_base + s->value_offset);
        }
    }

    return NULL;
}

// Module loader

void *load_ddf_module(const char *path, ddf_header_t **out_header, uint32_t *out_header_off, uint32_t *out_size)
{
    int idx;
    const FileEntry *fe;
    void *file_img;
    int bytes_read;
    ddf_header_t *hdr;
    uint32_t need_total;

    if (out_header)
    {
        *out_header = NULL;
    }

    if (out_header_off)
    {
        *out_header_off = 0;
    }

    if (out_size)
    {
        *out_size = 0;
    }

    if (!path || !file_table)
    {
        DDBG("[MODULE] ERROR: path or file_table is NULL\n");

        return NULL;
    }

    idx = find_entry_by_path(file_table, path);

    if (idx < 0)
    {
        DDBG("[MODULE] ERROR: '%s' not found in DiffFS\n", path);

        return NULL;
    }

    fe = &file_table->entries[idx];

    if (fe->type != ENTRY_TYPE_FILE || fe->file_size_bytes == 0)
    {
        DDBG("[MODULE] ERROR: '%s' is not a regular file\n", path);

        return NULL;
    }

    file_img = kmalloc(fe->file_size_bytes);

    if (!file_img)
    {
        DDBG("[MODULE] ERROR: OOM for module file image (%u bytes)\n", (unsigned)fe->file_size_bytes);

        return NULL;
    }

    bytes_read = read_file(file_table, path, file_img);

    if (bytes_read <= 0)
    {
        DDBG("[MODULE] ERROR: failed to read '%s'\n", path);
        kfree(file_img);

        return NULL;
    }

    hdr = (ddf_header_t *)file_img;

    if (validate_header(hdr, (uint32_t)bytes_read, &need_total) != 0)
    {
        kfree(file_img);

        return NULL;
    }

    debug_dump_header(hdr, (uint32_t)bytes_read);

    // Grow allocation to cover bss if needed
    if (need_total > (uint32_t)bytes_read)
    {
        void *bigger = kmalloc(need_total);

        if (!bigger)
        {
            DDBG("[MODULE] ERROR: OOM for module total (%u bytes)\n", (unsigned)need_total);
            kfree(file_img);

            return NULL;
        }

        memcpy(bigger, file_img, (size_t)bytes_read);
        memset((uint8_t*)bigger + bytes_read, 0, (size_t)(need_total - (uint32_t)bytes_read));
        kfree(file_img);
        file_img = bigger;
        hdr = (ddf_header_t *)file_img;
    }

    // Zero bss in case the buffer is too large
    if (hdr->bss_size)
    {
        if (!range_ok(hdr->bss_offset, hdr->bss_size, need_total))
        {
            DDBG("[MODULE] ERROR: BSS out of bounds after alloc\n");
            kfree(file_img);

            return NULL;
        }

        memset((uint8_t*)file_img + hdr->bss_offset, 0, hdr->bss_size);
    }

    // Apply relocations
    if (apply_relocations(file_img, hdr, need_total) != 0)
    {
        kfree(file_img);

        return NULL;
    }

    if (out_header)
    {
        *out_header = hdr;
    }

    if (out_header_off)
    {
        *out_header_off = 0;
    }

    if (out_size)
    {
        *out_size = need_total;
    }

    DDBG("[MODULE] Loaded '%s' at %p total=%u bytes\n", path, file_img, (unsigned)need_total);

    return file_img;
}

// Fill function pointers from header offsets
static void fill_entrypoints(ddf_module_t *m)
{
    if (!m || !m->module_base || !m->header)
    {
        return;
    }

    uint8_t *base = (uint8_t*)m->module_base;
    ddf_header_t *h = m->header;

    m->driver_init = NULL;
    m->driver_exit = NULL;
    m->driver_irq  = NULL;

    if (h->init_offset)
    {
        m->driver_init = (void (*)(kernel_exports_t*))(void *)(base + h->init_offset);
    }

    if (h->exit_offset)
    {
        m->driver_exit = (void (*)(void))(void *)(base + h->exit_offset);
    }

    if (h->irq_offset)
    {
        m->driver_irq = (void (*)(unsigned, void*))(void *)(base + h->irq_offset);
    }
}

// Pick a IRQ number from header
static uint32_t detect_irq_number(void *base, ddf_header_t *h)
{
    uint32_t chosen = IRQ_INVALID;

    if (h->irq_number != IRQ_INVALID && h->irq_number < 16 && h->irq_number != 0)
    {
        chosen = h->irq_number;
    }
    else
    {
        volatile unsigned int *p = (volatile unsigned int *)ddf_find_symbol(base, h, "ddf_irq_number");

        if (p)
        {
            uint32_t v = *p;

            if (v < 16 && v != 0)
            {
                chosen = v;
            }
        }
    }

    DDBG("[MODULE] IRQ resolve header=%u using=%u\n", (unsigned)h->irq_number, (unsigned)chosen);

    return chosen;
}

// Load a driver module
ddf_module_t *load_driver(const char *path)
{
    if (!path)
    {
        return NULL;
    }

    ddf_header_t *h = NULL;
    uint32_t header_off = 0;
    uint32_t size_bytes = 0;

    void *base = load_ddf_module(path, &h, &header_off, &size_bytes);

    if (!base)
    {
        return NULL;
    }

    ddf_module_t *m = (ddf_module_t *)kmalloc(sizeof(ddf_module_t));

    if (!m)
    {
        DDBG("[MODULE] ERROR: OOM for ddf_module_t\n");
        kfree(base);

        return NULL;
    }

    memset(m, 0, sizeof(*m));
    m->module_base = base;
    m->header = h;
    m->size_bytes = size_bytes;

    fill_entrypoints(m);

    // Resolve IRQ line 
    m->irq_number = detect_irq_number(base, h);

    DDBG("[MODULE] Entry init=%p exit=%p irq=%p irq_num=%u\n",
           (void*)m->driver_init, (void*)m->driver_exit, (void*)m->driver_irq, (unsigned)m->irq_number);

    return m;
}

