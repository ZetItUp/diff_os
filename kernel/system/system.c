#include "string.h"
#include "diff.h"
#include "heap.h"
#include "stdio.h"

char* find_shell_path(const FileTable *table, const char *cfg_path)
{
    int idx = find_entry_by_path(table, cfg_path);

    if (idx == -1)
    {
        printf("[SHELL] Config file '%s' not found\n", cfg_path);

        return NULL;
    }

    const FileEntry *fe = &table->entries[idx];
    char *cfg_data = kmalloc(fe->sector_count * 512 + 1);
    int bytes_read = read_file(table, cfg_path, cfg_data);

    if (bytes_read <= 0)
    {
        printf("[SHELL] Config file '%s' is empty\n", cfg_path);
        kfree(cfg_data);

        return NULL;
    }

    cfg_data[bytes_read] = 0;

    char *saveptr = NULL;
    char *line = NULL;
    int in_shell = 0;
    char *result = NULL;

    for (line = strtok_r(cfg_data, "\r\n", &saveptr);
         line;
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
            char *r = strchr(line, ']');

            if (r)
            {
                size_t len = (size_t)(r - (line + 1));

                if (len == 5 && strncmp(line + 1, "SHELL", 5) == 0)
                {
                    in_shell = 1;
                }
                else
                {
                    if (in_shell)
                    {
                        break;
                    }

                    in_shell = 0;
                }
            }

            continue;
        }

        if (!in_shell)
        {
            continue;
        }

        if (strncmp(line, "path=", 5) == 0)
        {
            const char *p = line + 5;
            size_t plen = strlen(p);
            result = kmalloc(plen + 1);
            strcpy(result, p);

            break;
        }
    }

    kfree(cfg_data);

    return result;
}

