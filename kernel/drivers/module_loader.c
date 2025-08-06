#include "drivers/ddf.h"
#include "drivers/module_loader.h"
#include "paging.h"
#include "diff.h"
#include "stdint.h"
#include "string.h"
#include "heap.h"
#include "irq.h"

#define DDF_MAGIC 0x00464444

kernel_exports_t g_exports = {
    .marker = 0xCAFEBABE,
    .inb = inb,
    .outb = outb,
    .printf = printf,
    .vprintf = vprintf,
    .pic_clear_mask = pic_clear_mask,
    .pic_set_mask = pic_set_mask
};

static ddf_header_t *find_ddf_header(uint8_t *module_base, uint32_t size, uint32_t *out_offset)
{
    static const uint32_t common_header_offsets[] = 
    {
        0x0000, 
        0x0800, 
        0x1000, 
        0x2000
    };

    for (unsigned i = 0; i < sizeof(common_header_offsets)/sizeof(common_header_offsets[0]); i++)
    {
        uint32_t off = common_header_offsets[i];
        
        if (off + sizeof(ddf_header_t) > size)
        {
            continue;
        }

        ddf_header_t *hdr = (ddf_header_t*)(module_base + off);
        
        if (hdr->magic == DDF_MAGIC) 
        {
            if (out_offset) 
            {
                *out_offset = off;
            }
            
            return hdr;
        }
    }

    for (uint32_t off = 0; off + sizeof(ddf_header_t) < size; off += 4)
    {
        ddf_header_t *hdr = (ddf_header_t*)(module_base + off);
        
        if (hdr->magic == DDF_MAGIC) 
        {
            if (out_offset)
            {
                *out_offset = off;
            }

            return hdr;
        }
    }

    return 0;
}

void *load_ddf_module(const char *path, ddf_header_t **out_header, uint32_t *out_header_offset, uint32_t *out_size)
{
    extern SuperBlock superblock;
    extern FileTable *file_table;

    int index = find_entry_by_path(file_table, path);
    if(index == -1)
    { 
        return 0;
    }

    const FileEntry *fe = &file_table->entries[index];
    if(fe->type != ENTRY_TYPE_FILE || fe->file_size_bytes == 0)
    {
        return 0;
    }

    // Read raw file into temp buffer
    uint32_t size = fe->sector_count * 512;
    uint8_t *raw_buf = kmalloc(size);
    
    if(!raw_buf)
    {
        return 0;
    }
    
    if(read_file(&superblock, file_table, path, raw_buf) != 0) 
    {
        kfree(raw_buf);
    
        return 0;
    }

    uint32_t hdr_off = 0;
    ddf_header_t *header = find_ddf_header(raw_buf, size, &hdr_off);
    if (!header)
    {
        printf("[ERROR] DDF header not found!\n");
        kfree(raw_buf);
   
        return 0;
    }

    uint32_t text_off    = header->text_offset;
    uint32_t text_size   = header->text_size;
    uint32_t rodata_off  = header->rodata_offset;
    uint32_t rodata_size = header->rodata_size;
    uint32_t data_off    = header->data_offset;
    uint32_t data_size   = header->data_size;
    uint32_t bss_off     = header->bss_offset;
    uint32_t bss_size    = header->bss_size;

    uint32_t module_total = bss_off + bss_size;
    uint8_t *module_base = kmalloc(module_total);
    
    if (!module_base) 
    {
        printf("[ERROR] Could not allocate memory for module\n");
        kfree(raw_buf);
        return 0;
    }

    memcpy(module_base + text_off,    raw_buf + text_off,    text_size);
    memcpy(module_base + rodata_off,  raw_buf + rodata_off,  rodata_size);
    memcpy(module_base + data_off,    raw_buf + data_off,    data_size);
    memset(module_base + bss_off, 0, bss_size);

    memcpy(module_base + hdr_off, raw_buf + hdr_off, sizeof(ddf_header_t));
    kfree(raw_buf);

    if(out_header)
    {
        *out_header = (ddf_header_t*)(module_base + hdr_off);
    }

    if(out_header_offset)
    {
        *out_header_offset = hdr_off;
    }

    if(out_size) 
    {
        *out_size = module_total;
    }

    return module_base;
}

ddf_module_t *load_driver(const char *path)
{
    ddf_header_t *header = 0;
    uint32_t header_offset = 0;
    uint32_t module_size = 0;
    
    void *module_base = load_ddf_module(path, &header, &header_offset, &module_size);
    
    if (!module_base) 
    {
        printf("[ERROR] Module Base is NULL\n");
    
        return NULL;
    }

    if(!header)
    {
        printf("ERROR] Header is NULL\n");
    
        return NULL;
    }

    // Get ddf_driver_init function
    void (*init_fn)(kernel_exports_t*) = (void(*)(kernel_exports_t*))((uint8_t*)module_base + header->init_offset);
    
    // Get ddf_driver_irq function
    void (*irq_fn)(unsigned, void *) = (void (*)(unsigned, void *))((uint8_t*)module_base + header->irq_offset);
    
    // Get ddf_driver_exit function
    void (*exit_fn)(void) = (void(*)(void))((uint8_t*)module_base + header->exit_offset);
    
    ddf_module_t *module = kmalloc(sizeof(ddf_module_t));
    module->module_base = module_base;
    module->header = header;
    module->driver_init = init_fn;
    module->driver_irq = irq_fn;
    module->driver_exit = exit_fn;
    module->irq_number = header->irq_number;

    if(module->driver_init)
    {
        module->driver_init(&g_exports);
    }

    return module;
}


