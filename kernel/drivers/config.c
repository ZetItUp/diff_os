#include "stdio.h"
#include "string.h"
#include "drivers/ata.h"
#include "drivers/config.h"
#include "drivers/module_loader.h"
#include "drivers/ddf.h"
#include "diff.h"
#include "heap.h"
#include "irq.h"

#define MAX_MODULES 16

static ddf_module_t* installed_modules[MAX_MODULES];

void remove_driver(uint32_t irq_num)
{
    if (irq_num >= MAX_MODULES)
    {
        return;
    }

    if (installed_modules[irq_num] && installed_modules[irq_num]->driver_exit)
    {
        installed_modules[irq_num]->driver_exit();
        kfree(installed_modules[irq_num]->module_base);
        kfree(installed_modules[irq_num]);
        installed_modules[irq_num] = NULL;
        irq_uninstall_handler(irq_num);
    }
}

void load_drivers(const FileTable* table, const char* cfg_path)
{
    memset(installed_modules, 0, sizeof(installed_modules));

    int idx = find_entry_by_path(table, cfg_path);
    if (idx == -1)
    {
        printf("ERROR: File '%s' was not found!\n", cfg_path);

        return;
    }

    const FileEntry* fe = &table->entries[idx];
    char* syscfg_data = kmalloc(fe->sector_count * 512 + 1);

    int bytes_read = read_file(table, cfg_path, syscfg_data);
    if (bytes_read <= 0)
    {
        printf("ERROR: File '%s' was empty!\n", cfg_path);
        kfree(syscfg_data);

        return;
    }

    syscfg_data[bytes_read] = 0;

    char* saveptr = NULL;
    char* line = NULL;

    int in_drivers = 0;
    int done_drivers = 0;

    char driver_path[128];
    driver_path[0] = 0;

    for (line = strtok_r(syscfg_data, "\r\n", &saveptr);
         line && !done_drivers;
         line = strtok_r(NULL, "\r\n", &saveptr))
    {
        while (*line == ' ' || *line == '\t')
        {
            line++;
        }

        if (*line == 0 || *line == '#')
        {
            continue;
        }

        if (*line == '[')
        {
            char* r = line;
            while (*r && *r != ']')
            {
                r++;
            }

            if (*r == ']')
            {
                size_t n = (size_t)(r - (line + 1));

                if (n == 7 && strncmp(line + 1, "DRIVERS", 7) == 0)
                {
                    in_drivers = 1;
                    driver_path[0] = 0;
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
            strncpy(driver_path, line + 5, sizeof(driver_path) - 1);
            driver_path[sizeof(driver_path) - 1] = 0;

            continue;
        }

        if (!driver_path[0])
        {
            printf("[DRIVER] WARNING: 'path=' missing before '%s' in [DRIVERS]\n", line);

            continue;
        }

        char abs_path[256];

        size_t plen = strlen(driver_path);
        if (plen >= sizeof(abs_path) - 2)
        {
            printf("[DRIVER] ERROR: drivers path too long\n");

            continue;
        }

        strcpy(abs_path, driver_path);
        if (plen == 0 || abs_path[plen - 1] != '/')
        {
            strcat(abs_path, "/");
        }

        if (strlen(abs_path) + strlen(line) >= sizeof(abs_path))
        {
            printf("[DRIVER] ERROR: driver path+name too long: %s + %s\n", abs_path, line);

            continue;
        }

        strcat(abs_path, line);

        ddf_module_t* module = load_driver(abs_path);
        if (!module)
        {
            printf("[DRIVER] ERROR: Failed to load driver %s\n", abs_path);

            continue;
        }

        if (module->irq_number >= MAX_MODULES)
        {
            printf("[DRIVER] ERROR: IRQ %u out of range for %s\n", module->irq_number, abs_path);
            kfree(module->module_base);
            kfree(module);

            continue;
        }

        if (installed_modules[module->irq_number])
        {
            printf("[DRIVER] ERROR: IRQ %u already has a driver\n", module->irq_number);
            kfree(module->module_base);
            kfree(module);

            continue;
        }

        if (!module->driver_irq)
        {
            printf("[DRIVER] WARNING: %s has no IRQ handler, ignoring\n", abs_path);
            kfree(module->module_base);
            kfree(module);

            continue;
        }

        installed_modules[module->irq_number] = module;
        irq_install_handler(module->irq_number, module->driver_irq);
        // printf("[MODULE] Loaded %s on IRQ %u\n", abs_path, module->irq_number);
    }

    kfree(syscfg_data);
}

