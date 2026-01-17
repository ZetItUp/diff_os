// Sampling profiler for DiffOS
// Samples user EIP on timer interrupts and outputs CSV via serial

#include "system/profiler.h"
#include "system/process.h"
#include "serial.h"
#include "string.h"
#include "stdio.h"
#include "heap.h"
#include "dex/dex.h"

static profiler_state_t s_profiler;
static int s_initialized = 0;

void profiler_init(void)
{
    memset(&s_profiler, 0, sizeof(s_profiler));
    s_profiler.active = 0;
    s_profiler.target_pid = -1;
    s_initialized = 1;
}

int profiler_start(int pid)
{
    if (!s_initialized)
    {
        profiler_init();
    }

    // If already profiling, stop first
    if (s_profiler.active)
    {
        profiler_stop();
    }

    // Get target process
    process_t *target = NULL;
    if (pid < 0)
    {
        target = process_current();
    }
    else
    {
        target = process_find_by_pid(pid);
    }

    if (!target)
    {
        return -1;
    }

    // Clear sample data but preserve loaded symbols
    s_profiler.target_pid = target->pid;
    // image_base will be set by profiler_load_symbols when symbols are loaded
    s_profiler.active = 1;
    s_profiler.total_samples = 0;
    s_profiler.sample_count = 0;
    memset(s_profiler.samples, 0, sizeof(s_profiler.samples));

    serial_write("[PROFILER] Started profiling PID ");
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%d", s_profiler.target_pid);
    serial_write(buffer);
    snprintf(buffer, sizeof(buffer), " (image_base=0x%08x, symbols=%d)\n",
             s_profiler.image_base, s_profiler.symbol_count);
    serial_write(buffer);

    return 0;
}

int profiler_stop(void)
{
    if (!s_profiler.active)
    {
        return -1;
    }

    s_profiler.active = 0;

    serial_write("[PROFILER] Stopped. Total samples: ");
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%u", s_profiler.total_samples);
    serial_write(buffer);
    serial_write(", unique addresses: ");
    snprintf(buffer, sizeof(buffer), "%d", s_profiler.sample_count);
    serial_write(buffer);
    serial_write("\n");

    return 0;
}

void profiler_record_sample(uint32_t eip, int pid)
{
    if (!s_profiler.active)
    {
        return;
    }

    // Only sample target process
    if (pid != s_profiler.target_pid)
    {
        return;
    }

    // Only sample user-space addresses
    if (eip < 0x40000000 || eip >= 0x80000000)
    {
        return;
    }

    s_profiler.total_samples++;

    // Find existing entry or add new one
    for (int i = 0; i < s_profiler.sample_count; i++)
    {
        if (s_profiler.samples[i].address == eip)
        {
            s_profiler.samples[i].count++;

            return;
        }
    }

    // Add new entry if space available
    if (s_profiler.sample_count < PROFILER_MAX_SAMPLES)
    {
        s_profiler.samples[s_profiler.sample_count].address = eip;
        s_profiler.samples[s_profiler.sample_count].count = 1;
        s_profiler.sample_count++;
    }
}

// Find symbol info for an absolute address
static const char *find_symbol_name(uint32_t address, const char **out_library)
{
    const char *best_match = NULL;
    const char *best_library = NULL;
    uint32_t best_address = 0;

    for (int i = 0; i < s_profiler.symbol_count; i++)
    {
        if (s_profiler.symbols[i].address <= address &&
            s_profiler.symbols[i].address >= best_address)
        {
            best_address = s_profiler.symbols[i].address;
            best_match = s_profiler.symbols[i].name;
            best_library = s_profiler.symbols[i].library;
        }
    }

    // If sample is too far beyond the matched symbol, it's likely unmapped
    // Use 64KB as a reasonable max function size
    if (best_match && (address - best_address) < 0x10000)
    {
        if (out_library)
        {
            *out_library = best_library;
        }

        return best_match;
    }

    if (out_library)
    {
        *out_library = NULL;
    }

    return "unknown";
}

// Sort samples by count (descending) using simple bubble sort
static void sort_samples(void)
{
    for (int i = 0; i < s_profiler.sample_count - 1; i++)
    {
        for (int j = 0; j < s_profiler.sample_count - i - 1; j++)
        {
            if (s_profiler.samples[j].count < s_profiler.samples[j + 1].count)
            {
                profiler_sample_t tmp = s_profiler.samples[j];
                s_profiler.samples[j] = s_profiler.samples[j + 1];
                s_profiler.samples[j + 1] = tmp;
            }
        }
    }
}

int profiler_dump_csv(void)
{
    if (s_profiler.total_samples == 0)
    {
        serial_write("[PROFILER] No samples collected\n");

        return -1;
    }

    // Sort by sample count
    sort_samples();

    // Output CSV header
    serial_write("\n===PROFILE_CSV_START===\n");
    serial_write("address,count,percent,library,function\n");

    char line[256];

    for (int i = 0; i < s_profiler.sample_count; i++)
    {
        uint32_t addr = s_profiler.samples[i].address;
        uint32_t count = s_profiler.samples[i].count;
        uint32_t percent_x100 = (count * 10000) / s_profiler.total_samples;

        const char *lib_name = NULL;
        const char *func_name = find_symbol_name(addr, &lib_name);

        snprintf(line, sizeof(line), "0x%08x,%u,%u.%02u,%s,%s\n",
                 addr, count,
                 percent_x100 / 100, percent_x100 % 100,
                 lib_name ? lib_name : "-",
                 func_name);

        serial_write(line);
    }

    serial_write("===PROFILE_CSV_END===\n\n");

    // Also output a summary grouped by library:function
    serial_write("===PROFILE_SUMMARY_START===\n");
    serial_write("library,function,total_count,percent\n");

    // Aggregate by library:function
    typedef struct
    {
        const char *library;
        const char *name;
        uint32_t count;
    } func_summary_t;

    func_summary_t summaries[256];
    int summary_count = 0;

    for (int i = 0; i < s_profiler.sample_count; i++)
    {
        const char *lib_name = NULL;
        const char *func_name = find_symbol_name(s_profiler.samples[i].address, &lib_name);

        // Find or add to summaries (match both library and function)
        int found = 0;
        for (int j = 0; j < summary_count; j++)
        {
            int lib_match = (summaries[j].library == lib_name) ||
                           (summaries[j].library && lib_name && strcmp(summaries[j].library, lib_name) == 0);
            if (lib_match && strcmp(summaries[j].name, func_name) == 0)
            {
                summaries[j].count += s_profiler.samples[i].count;
                found = 1;

                break;
            }
        }

        if (!found && summary_count < 256)
        {
            summaries[summary_count].library = lib_name;
            summaries[summary_count].name = func_name;
            summaries[summary_count].count = s_profiler.samples[i].count;
            summary_count++;
        }
    }

    // Sort summaries by count
    for (int i = 0; i < summary_count - 1; i++)
    {
        for (int j = 0; j < summary_count - i - 1; j++)
        {
            if (summaries[j].count < summaries[j + 1].count)
            {
                func_summary_t tmp = summaries[j];
                summaries[j] = summaries[j + 1];
                summaries[j + 1] = tmp;
            }
        }
    }

    // Output summaries
    for (int i = 0; i < summary_count; i++)
    {
        uint32_t percent_x100 = (summaries[i].count * 10000) / s_profiler.total_samples;

        snprintf(line, sizeof(line), "%s,%s,%u,%u.%02u\n",
                 summaries[i].library ? summaries[i].library : "-",
                 summaries[i].name, summaries[i].count,
                 percent_x100 / 100, percent_x100 % 100);

        serial_write(line);
    }

    serial_write("===PROFILE_SUMMARY_END===\n");

    return 0;
}

int profiler_is_active(void)
{
    return s_profiler.active;
}

int profiler_target_pid(void)
{
    return s_profiler.target_pid;
}

void profiler_clear_symbols(void)
{
    s_profiler.symbol_count = 0;
}

int profiler_load_symbols(const void *dex_data, size_t dex_size, uint32_t image_base, const char *library_name)
{
    if (!dex_data || dex_size < sizeof(dex_header_t))
    {
        return -1;
    }

    const dex_header_t *header = (const dex_header_t *)dex_data;

    // Verify magic
    if (header->magic != DEX_MAGIC)
    {
        return -1;
    }

    // Check symbol table bounds
    if (header->symbol_table_offset == 0 || header->symbol_table_count == 0)
    {
        return 0;
    }

    uint32_t symbol_end = header->symbol_table_offset + header->symbol_table_count * sizeof(dex_symbol_t);

    if (symbol_end > dex_size)
    {
        return -1;
    }

    // Check string table bounds
    if (header->strtab_offset == 0)
    {
        return -1;
    }

    const uint8_t *data = (const uint8_t *)dex_data;
    const dex_symbol_t *symbols = (const dex_symbol_t *)(data + header->symbol_table_offset);
    const char *string_table = (const char *)(data + header->strtab_offset);

    // Mark as initialized so profiler_start won't call profiler_init and clear symbols
    s_initialized = 1;

    // Store image base for the main executable
    if (!library_name || library_name[0] == '\0')
    {
        s_profiler.image_base = image_base;
    }

    // Count symbols added in this call
    int added = 0;

    // Load symbols (only functions, type 0), appending to existing
    for (uint32_t i = 0; i < header->symbol_table_count; i++)
    {
        if (s_profiler.symbol_count >= PROFILER_MAX_SYMBOLS)
        {
            break;
        }

        // Only include function symbols (type 0)
        if (symbols[i].type != 0)
        {
            continue;
        }

        // Get symbol name
        uint32_t name_offset = symbols[i].name_offset;
        if (name_offset >= header->strtab_size)
        {
            continue;
        }

        const char *name = string_table + name_offset;

        // Store absolute address
        s_profiler.symbols[s_profiler.symbol_count].address = image_base + symbols[i].value_offset;
        strlcpy(s_profiler.symbols[s_profiler.symbol_count].name,
                name, PROFILER_MAX_SYMBOL_NAME);
        strlcpy(s_profiler.symbols[s_profiler.symbol_count].library,
                library_name ? library_name : "main",
                PROFILER_MAX_LIB_NAME);
        s_profiler.symbol_count++;
        added++;
    }

    serial_write("[PROFILER] Loaded ");
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%d symbols from %s (total: %d)\n",
             added, library_name ? library_name : "main", s_profiler.symbol_count);
    serial_write(buffer);

    return 0;
}
