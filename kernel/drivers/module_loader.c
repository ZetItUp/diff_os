#include "drivers/ddf.h"
#include "drivers/module_loader.h"
#include "diff.h"
#include "string.h"
#include "stdint.h"
#include "stdio.h"
#include "heap.h"

kernel_exports_t g_exports = 
{
    .inb = inb,
    .outb = outb,
    .printf = printf,
    .pic_clear_mask = pic_clear_mask,
    .pic_set_mask = pic_set_mask
};

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
printf("DDF HEADER:\n");
printf("  magic: %x\n", header->magic);
printf("  init_offset: %d\n", header->init_offset);
printf("  exit_offset: %d\n", header->exit_offset);
printf("  irq_offset: %d\n", header->irq_offset);
printf("  symbol_table_offset: %d\n", header->symbol_table_offset);
printf("  symbol_table_count: %d\n", header->symbol_table_count);
printf("  version_major: %d\n", header->version_major);
printf("  version_minor: %d\n", header->version_minor);

    // Relative offsets from module base
    void (*init_fn)(kernel_exports_t*) = (void(*)(kernel_exports_t*))((uint8_t*)module_base + header->init_offset);
    void (*exit_fn)(void) = (void(*)(void))((uint8_t*)module_base + header->exit_offset);
    void (*irq_fn)(void) = (void(*)(void))((uint8_t*)module_base + header->irq_offset);

    // Save exit_fn and irq_fn in a suitable place
    
    // Run driver-init and give it the kernel table

    init_fn(&g_exports);
}

void *ddf_find_symbol(void *module, uint32_t module_size, const char *name)
{
    (void)module_size;
    ddf_header_t *header = (ddf_header_t*)module;
    uint8_t *base = (uint8_t*)module;
    ddf_symbol_t *sym_table = (ddf_symbol_t*)(base + header->symbol_table_offset);
    const char *str_table = (const char*)(base + header->symbol_table_offset + header->symbol_table_count * sizeof(ddf_symbol_t));

    // Debug: skriv ut symboltabellen
    printf("[DEBUG] Symbol table count = %d\n", header->symbol_table_count);
    for(uint32_t i = 0; i < header->symbol_table_count; ++i)
    {
        const char *sym_name = str_table + sym_table[i].name_offset;
        int sym_type = sym_table[i].type;
        uint32_t val_off = sym_table[i].value_offset;

        printf("Symbol %d: name='%s', type=%d, value_offset=0x%x\n", i, sym_name, sym_type, val_off);
    }

    // Sök efter symbolen
    for(uint32_t i = 0; i < header->symbol_table_count; ++i)
    {
        const char *sym_name = str_table + sym_table[i].name_offset;
        if(!strcmp(sym_name, name))
        {
            return (void*)(base + sym_table[i].value_offset);
        }
    }
    return NULL;
}


void *load_ddf_module(const char *path)
{
    extern SuperBlock superblock;
    extern FileTable *file_table;

    // Find the file in FileTable
    int index = find_entry_by_path(file_table, path);
    if(index == -1)
    {
        printf("[MODULE ERROR] Could not find driver %s!\n", path);

        return NULL;
    }

    const FileEntry *fe = &file_table->entries[index];
    if(fe->type != ENTRY_TYPE_FILE || fe->file_size_bytes == 0)
    {
        printf("[MODULE ERROR] Invalid module: %s!\n", path);

        return NULL;
    }
    
    uint32_t size = fe->sector_count * 512;
    uint8_t *module_base = kmalloc(size);
    if(!module_base)
    {
        printf("[MODULE ERROR] Unable to allocate memory for module: %s\n", path);

        return NULL;
    }

    // Read module into RAM
    if(read_file(&superblock, file_table, path, module_base) != 0)
    {
        printf("[MODULE ERROR] Unable to read module from disk: %s\n", path);
        kfree(module_base);

        return NULL;
    }

    if(fe->file_size_bytes < size)
    {
        module_base[fe->file_size_bytes] = 0;
    }

    ddf_header_t *header = (ddf_header_t*)module_base;
    printf("init_offset=%d exit_offset=%d irq_offset=%d size=%d\n",
        header->init_offset, header->exit_offset, header->irq_offset, fe->file_size_bytes);

    uint32_t *magic = ddf_find_symbol(module_base, size, "my_kernel_addr");
    if (magic)
        printf("driver's my_kernel_addr = %x\n", *magic);
    else
        printf("Symbol 'my_kernel_addr' not found!\n");


    return (void*)module_base;
}
