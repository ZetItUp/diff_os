// All comments are written in English.
// Allman brace style is used consistently.

#include "stdio.h"
#include "string.h"
#include "drivers/ata.h"
#include "drivers/config.h"
#include "drivers/module_loader.h"
#include "drivers/ddf.h"
#include "diff.h"
#include "heap.h"
#include "irq.h"

#define MAX_DRIVERS   32

typedef struct driver_record
{
    ddf_module_t *module;
    char          name[64];
    char          path[256];
} driver_record_t;

static driver_record_t g_drivers[MAX_DRIVERS];
static unsigned g_driver_count = 0;

/* ---------------- path helpers ---------------- */

static const char *basename_ptr(const char *path)
{
    const char *p;
    const char *slash;

    if (!path)
    {
        return "";
    }

    p = path;
    slash = p;

    while (*p)
    {
        if (*p == '/' || *p == '\\')
        {
            slash = p + 1;
        }
        p++;
    }

    return slash;
}

static void basename_no_ext(const char *path, char *out, size_t out_sz)
{
    const char *base;
    size_t n;

    if (!out || out_sz == 0)
    {
        return;
    }

    base = basename_ptr(path);
    n = 0;

    while (base[n] && base[n] != '.' && n + 1 < out_sz)
    {
        out[n] = base[n];
        n++;
    }

    out[n] = '\0';
}

/* ---------------- driver registry helpers ---------------- */

static int find_driver_index_by_name(const char *name)
{
    unsigned i;

    for (i = 0; i < g_driver_count; i++)
    {
        if (strcmp(g_drivers[i].name, name) == 0)
        {
            return (int)i;
        }
    }

    return -1;
}

static int find_driver_index_by_irq(uint32_t irq_num)
{
    unsigned i;

    if (irq_num >= 16u)
    {
        return -1;
    }

    for (i = 0; i < g_driver_count; i++)
    {
        ddf_module_t *m;

        m = g_drivers[i].module;
        if (m && m->irq_number == irq_num)
        {
            return (int)i;
        }
    }

    return -1;
}

static void unload_at_index(unsigned idx)
{
    ddf_module_t *mod;
    unsigned j;

    if (idx >= g_driver_count)
    {
        return;
    }

    mod = g_drivers[idx].module;

    if (mod)
    {
        if (mod->irq_number != IRQ_INVALID && mod->irq_number < 16u && mod->driver_irq)
        {
            irq_uninstall_handler((uint8_t)mod->irq_number);
        }

        if (mod->driver_exit)
        {
            mod->driver_exit();
        }

        if (mod->module_base)
        {
            kfree(mod->module_base);
        }

        kfree(mod);
    }

    for (j = idx + 1; j < g_driver_count; j++)
    {
        g_drivers[j - 1] = g_drivers[j];
    }

    g_driver_count--;
    memset(&g_drivers[g_driver_count], 0, sizeof(g_drivers[g_driver_count]));
}

void remove_driver(uint32_t irq_num)
{
    int idx;

    idx = find_driver_index_by_irq(irq_num);
    if (idx >= 0)
    {
        unload_at_index((unsigned)idx);
    }
}

void remove_driver_by_name(const char *name)
{
    int idx;

    if (!name)
    {
        return;
    }

    idx = find_driver_index_by_name(name);
    if (idx >= 0)
    {
        unload_at_index((unsigned)idx);
    }
}

void remove_all_drivers(void)
{
    while (g_driver_count > 0)
    {
        unload_at_index(g_driver_count - 1);
    }
}

/* ---------------- config parsing (safe) ----------------
 * Same external behavior as your original version:
 *  - Only reads [DRIVERS] (uppercase).
 *  - Requires a preceding "path=" inside [DRIVERS].
 *  - Lines listing driver file names are taken verbatim.
 * Differences:
 *  - No strtok_r/strcpy/strcat/strncpy.
 *  - Lines are split manually; we copy line text to temp buffers
 *    before building paths to avoid aliasing and overruns.
 */

void load_drivers(const FileTable* table, const char* cfg_path)
{
    int idx;
    const FileEntry* fe;
    char* syscfg_data;
    int bytes_read;
    char *cursor;
    int in_drivers;
    int done_drivers;
    char driver_path[128];

    remove_all_drivers();
    memset(g_drivers, 0, sizeof(g_drivers));
    g_driver_count = 0;

    idx = find_entry_by_path(table, cfg_path);
    if (idx == -1)
    {
        printf("ERROR: File '%s' was not found!\n", cfg_path);
        return;
    }

    fe = &table->entries[idx];

    syscfg_data = (char *)kmalloc(fe->sector_count * 512 + 1);
    if (!syscfg_data)
    {
        printf("ERROR: OOM reading '%s'\n", cfg_path);
        return;
    }

    bytes_read = read_file(table, cfg_path, syscfg_data);
    if (bytes_read <= 0)
    {
        printf("ERROR: File '%s' was empty!\n", cfg_path);
        kfree(syscfg_data);
        return;
    }

    syscfg_data[bytes_read] = '\0';

    in_drivers = 0;
    done_drivers = 0;
    driver_path[0] = '\0';

    cursor = syscfg_data;
    while (*cursor && !done_drivers)
    {
        char *line;
        char *end;

        /* Slice current line [cursor, end) */
        line = cursor;
        end = line;
        while (*end && *end != '\r' && *end != '\n')
        {
            end++;
        }

        /* Terminate line in-place and advance cursor past CR/LF block */
        if (*end)
        {
            *end = '\0';
            end++;
            while (*end == '\r' || *end == '\n')
            {
                end++;
            }
            cursor = end;
        }
        else
        {
            cursor = end;
        }

        /* Left-trim spaces/tabs */
        while (*line == ' ' || *line == '\t')
        {
            line++;
        }

        if (*line == '\0' || *line == '#')
        {
            continue;
        }

        if (*line == '[')
        {
            char *r;
            size_t n;

            r = line;
            while (*r && *r != ']')
            {
                r++;
            }

            if (*r == ']')
            {
                n = (size_t)(r - (line + 1));
                if (n == 7 && strncmp(line + 1, "DRIVERS", 7) == 0)
                {
                    in_drivers = 1;
                    driver_path[0] = '\0';
                }
                else
                {
                    if (in_drivers)
                    {
                        done_drivers = 1;
                    }
                    in_drivers = 0;
                }

                continue;
            }

            continue;
        }

        if (!in_drivers)
        {
            continue;
        }

        if (strncmp(line, "path=", 5) == 0)
        {
            /* Safe copy of path value (as-is; no trimming to keep behavior identical) */
            (void)strlcpy(driver_path, line + 5, sizeof(driver_path));
            continue;
        }

        if (driver_path[0] == '\0')
        {
            printf("[DRIVER] WARNING: 'path=' missing before '%s' in [DRIVERS]\n", line);
            continue;
        }

        /* Build absolute path safely:
           - copy 'line' (filename) to a temp buffer
           - compose into abs_path with snprintf to avoid intermediate overflows */
        {
            char name_tmp[128];
            char abs_path[256];
            size_t plen;
            int need_slash;
            int written;
            char drv_name[64];
            int existing;
            ddf_module_t *module;
            driver_record_t *slot;

            /* Decouple from syscfg_data buffer */
            (void)strlcpy(name_tmp, line, sizeof(name_tmp));

            plen = strlen(driver_path);
            need_slash = (plen == 0 || driver_path[plen - 1] != '/') ? 1 : 0;

            if (need_slash)
            {
                written = snprintf(abs_path, sizeof(abs_path), "%s/%s", driver_path, name_tmp);
            }
            else
            {
                written = snprintf(abs_path, sizeof(abs_path), "%s%s", driver_path, name_tmp);
            }

            if (written < 0 || (size_t)written >= sizeof(abs_path))
            {
                printf("[DRIVER] ERROR: driver path+name too long: %s + %s\n", driver_path, name_tmp);
                continue;
            }

            basename_no_ext(name_tmp, drv_name, sizeof(drv_name));
            if (drv_name[0] == '\0')
            {
                printf("[DRIVER] ERROR: invalid driver name from '%s'\n", name_tmp);
                continue;
            }

            existing = find_driver_index_by_name(drv_name);
            if (existing >= 0)
            {
                unload_at_index((unsigned)existing);
            }

            if (g_driver_count >= MAX_DRIVERS)
            {
                printf("[DRIVER] ERROR: driver registry full, skipping %s\n", abs_path);
                continue;
            }

            module = load_driver(abs_path);
            if (!module)
            {
                printf("[DRIVER] ERROR: Failed to load driver %s\n", abs_path);
                continue;
            }

            if (module->irq_number != IRQ_INVALID && module->irq_number < 16u && module->driver_irq)
            {
                irq_install_handler((uint8_t)module->irq_number, module->driver_irq);
            }

            slot = &g_drivers[g_driver_count++];
            memset(slot, 0, sizeof(*slot));
            slot->module = module;
            (void)strlcpy(slot->name, drv_name, sizeof(slot->name));
            (void)strlcpy(slot->path, abs_path, sizeof(slot->path));

            if (module && module->driver_init) 
            {
#ifdef DIFF_DEBUG
                printf("[KEXP] sizeof(kernel_exports_t)=%u\n", (unsigned)sizeof(kernel_exports_t));
                printf("[KEXP] inb=%p outb=%p inw=%p outw=%p outl=%p inl=%p io_wait=%p\n",
                       g_exports.inb, g_exports.outb, g_exports.inw, g_exports.outw,
                       g_exports.outl, g_exports.inl, g_exports.io_wait);
                printf("[KEXP] printf=%p vprintf=%p pic_clr=%p pic_set=%p map_phys=%p kbd_reg=%p vbe_reg=%p\n",
                       g_exports.printf, g_exports.vprintf, g_exports.pic_clear_mask, g_exports.pic_set_mask,
                       g_exports.map_physical, g_exports.keyboard_register, g_exports.vbe_register);
#endif
                /*printf("[CFG] calling driver_init... init=%p  module=[%p..%p)  arg=%p\n",
       (void *)module->driver_init,
       module->module_base,
       (uint8_t *)module->module_base + module->size_bytes,
       (void *)&g_exports);

dump_exports_header(&g_exports);
*/
/* Refuse to call if the pointer does not point inside the module image */
if (!ptr_in_module(module, (const void *)module->driver_init))
{
    printf("[CFG] ABORT: driver_init pointer is outside module range\n");
}
else
{
    /* One more lightweight sanity: read the first dword of code */
#ifdef DIFF_DEBUG
    uint32_t first = *(const uint32_t *)((const uint8_t *)module->driver_init);
    printf("[CFG] init@%p first dword=%08x\n", (void *)module->driver_init, (unsigned)first);
#endif

    module->driver_init(&g_exports);
}

            }
            /* Optional log kept commented:
             * printf("[MODULE] Loaded %s (name=%s)%s\n",
             *        abs_path, slot->name,
             *        (module->irq_number != IRQ_INVALID && module->driver_irq) ? " [IRQ registered]" : "");
             */
        }
    }

    kfree(syscfg_data);
}

