#include "stdio.h"
#include "string.h"
#include "drivers/ata.h"
#include "drivers/config.h"
#include "drivers/module_loader.h"
#include "diff.h"
#include "heap.h"

void load_drivers(const FileTable *table, const char *cfg_path)
{
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
    char *syscfg_data = kmalloc(sector_bytes + 1); // +1 för null-terminering
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
        // Hoppa över kommentarer eller tom rad
        while (*line == ' ' || *line == '\t') 
        { 
            line++; 
        }

        if (*line == '#' || *line == 0) 
        { 
            continue; 
        }

        // path=... ?
        if (strncmp(line, "path=", 5) == 0)
        {
            strncpy(driver_path, line + 5, sizeof(driver_path)-1);
            driver_path[sizeof(driver_path)-1] = 0;
            
            continue;
        }

        // Allt annat på rad = filnamn
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
            
            load_driver(abs_path);
        }
    }

    kfree(syscfg_data);
}
