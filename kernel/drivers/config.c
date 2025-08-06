#include "stdio.h"
#include "string.h"
#include "drivers/ata.h"
#include "drivers/config.h"
#include "drivers/module_loader.h"
#include "drivers/ddf.h"
#include "diff.h"
#include "heap.h"
#include "irq.h"

#define MAX_MODULES     16          // 16 for now

static ddf_module_t *installed_modules[MAX_MODULES];

void remove_driver(uint32_t irq_num)
{
    if(irq_num >= MAX_MODULES)
    {
        return;
    }

    if(installed_modules[irq_num]->driver_exit)
    {
        installed_modules[irq_num]->driver_exit();
        kfree(installed_modules[irq_num]->module_base);
        kfree(installed_modules[irq_num]);
        installed_modules[irq_num] = NULL;
        irq_uninstall_handler(irq_num);
    }
}

void load_drivers(const FileTable *table, const char *cfg_path)
{
    memset(installed_modules, 0, sizeof(installed_modules));

    int idx = find_entry_by_path(table, cfg_path);
    if (idx == -1)
    {
        printf("ERROR: File '%s' was not found!\n", cfg_path);
        
        return;
    }

    const FileEntry *fe = &table->entries[idx];
    uint32_t syscfg_size = fe->file_size_bytes;
    
    if (syscfg_size == 0 || syscfg_size > 4096)
    {
        printf("File is empty or too big!\n");
        
        return;
    }

    uint32_t sector_bytes = fe->sector_count * 512;
    char *syscfg_data = kmalloc(sector_bytes + 1);      // Null termination, +1
    if (disk_read(fe->start_sector, fe->sector_count, syscfg_data) != 0)
    {
        printf("Failed to read sys.cfg!\n");
        kfree(syscfg_data);
        
        return;
    }

    syscfg_data[syscfg_size] = 0;

    char driver_path[128] = "";
    char *lines = syscfg_data;
    char *saveptr;

    for (char *line = strtok_r(lines, "\r\n", &saveptr); line; line = strtok_r(NULL, "\r\n", &saveptr))
    {
        while (*line == ' ' || *line == '\t') 
        { 
            line++; 
        }

        if (*line == '#' || *line == 0) 
        { 
            continue; 
        }

        if (strncmp(line, "path=", 5) == 0)
        {
            strncpy(driver_path, line + 5, sizeof(driver_path)-1);
            driver_path[sizeof(driver_path)-1] = 0;
            
            continue;
        }

        if (driver_path[0] && strlen(line) > 0)
        {
            char abs_path[256];
            abs_path[0] = 0;

            strcpy(abs_path, driver_path);

            size_t plen = strlen(driver_path);
            if (plen > 0 && driver_path[plen-1] != '/')
            {
                strcat(abs_path, "/");
            }

            strcat(abs_path, line);

            ddf_module_t *module = load_driver(abs_path);

            if(!module)
            {
                printf("[DRIVER] ERROR: Failed to load driver %s\n", abs_path);
                continue;
            }

            if(installed_modules[module->irq_number])
            {
                printf("[DRIVER] ERROR: Another driver is already installed for that IRQ!\n");
                continue;
            }
            
            if(!module->driver_irq)
            {
                printf("[DRIVER] WARNING: No handler specified, ignoring!\n");
                continue;
            }
            
            installed_modules[module->irq_number] = module;
            irq_install_handler(module->irq_number, module->driver_irq);

            /*
            printf("[MODULE DEBUG] driver_irq=%x irq_number=%x\n", (uint32_t)module->driver_irq, module->irq_number);
            printf("[MODULE DEBUG] irq_handlers[%d]=%x\n", module->irq_number, (uint32_t)irq_handlers[module->irq_number]);
            */
        }
    }

    kfree(syscfg_data);
}
