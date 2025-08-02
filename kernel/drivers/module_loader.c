#include "drivrs/ddf.h"
#include "stdint.h"
#include "string.h"

// TODO: Implement reading
void *load_ddf_module(const char *path);

void load_driver(const char *path)
{
    void *module_base = load_ddf_module(path);

    if(!module_base)
    {
        return;
    }

    ddf_header_t *header = (ddf_header_t*)module_base;

    if(header->magic != DDF_MAGIC)
    {
        return;
    }

    // Relative offsets from module base
    void (*init_fn)(kernel_exports_t*) = (void(*)(kernel_exports_t*))((uint8_t*)module_base + header->init_offset);
    void (*exit_fn)(void) = (void(*)(void))((uint8_t*)module_base + header->exit_offset);
    void (*irq_fn)(void) = (void(*)(void))((uint8_t*)module_base + header->irq_offset);

    // Save exit_fn and irq_fn in a suitable place
    
    // Run driver-init and give it the kernel table
    init_fn(&g_exports);
}

void *ddf_find_symbol(void *module, const char *name)
{
    ddf_header_t *header = (ddf_header_t*)module;
    ddf_symbol_t *sym_table = (ddf_symbol_t*)((uint8_t*)module + header->symbol_table_offset);
    const char *str_table = (const char *)(sym_table + header->symbol_table_count);

    for(uint32_t i = 0; i < header->symbol_table_count; ++i)
    {
        if(!strcmp(str_table + sym_table[i].name_offset, name))
        {
            return (uint8_t)module + sym_table[i].value_offset;
        }
    }

    return NULL;
}

void *load_ddf_module(const char *path)
{
    extern uint8_t _binary_drivers_obj_keyboard_ddf_start[];

    return (void*)_binary_drivers_obj_keyboard_dd_start;
}
