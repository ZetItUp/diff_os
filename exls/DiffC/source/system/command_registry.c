#include <system/command_registry.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <syscall.h>

#define CMDREG_MAX_ENTRIES          256
#define MAX_LINE_LEN                512

static cmd_slot_t *g_table;
static size_t g_capacity = CMDREG_MAX_ENTRIES;
static size_t g_count = 0;

// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
static uint32_t hash_str(const char *str)
{
    if (!str)
    {
        return 0;
    }

    uint32_t hash = 2166136261u;

    for(; *str; ++str)
    {
        hash ^= (uint8_t)*str;
        hash *= 16777619u;
    }

    return hash;
}

static inline char *lskip(char *s)
{
    while (*s && isspace((unsigned char)*s))
    {
        s++;
    }

    return s;
}

static inline char *rstrip(char *s)
{
    size_t n = strlen(s);

    while (n && isspace((unsigned char)s[n-1]))
    {
        s[--n] = '\0';
    }
    
    return s;
}

static bool parse_keyvalue(char *line, char **out_key, char **out_val)
{
    char *p = lskip(line);

    if(p == 0 || *p == '#')
    {
        return false;
    }

    char *eql = strchr(p, '=');

    if(!eql)
    {
        return false;
    }

    *eql = 0;
    char *key = p;
    char *val = eql + 1;

    rstrip(key);
    val = lskip(val);

    rstrip(val);

    if(*key == 0 || *val == 0)
    {
        return false;
    }

    *out_key = key;
    *out_val = val;

    return true;
}

static bool validate_table(void)
{
    if(g_table)
    {
        return true;
    }

    g_table = (cmd_slot_t*)calloc(g_capacity, sizeof(cmd_slot_t));

    return g_table != NULL;
}

static size_t find_slot(const char *name, bool *found)
{
    if (!g_table || !name || !*name)
    {
        if (found) *found = false;
        return (size_t)-1;
    }

    uint32_t hash = hash_str(name);
    size_t i = hash % g_capacity;

    for(size_t probe = 0; probe < g_capacity; ++probe)
    {
        size_t idx = (i + probe) % g_capacity;

        if(!g_table[idx].used)
        {
            *found = false;

            return idx;
        }

        if(strncmp(g_table[idx].name, name, MAX_NAME_LEN) == 0)
        {
            *found = true;

            return idx;
        }
    }

    *found = false;

    // We're full
    return (size_t)-1;
}

bool cmdreg_add(const char *name, const char *path)
{
    if(!name || !path || !*name || !*path)
    {
        return false;
    }

    if(!validate_table())
    {
        return false;
    }

    bool found = false;
    size_t idx = find_slot(name, &found);

    if(idx == (size_t)-1)
    {
        // Table is full
        return false;
    }

    if(!found && g_count + 1 >= g_capacity - 1)
    {
        // Avoid making the table full
        return false;
    }

    // This may overwrite the post
    g_table[idx].used = 1;
    strncpy(g_table[idx].name, name, MAX_NAME_LEN - 1); 
    g_table[idx].name[MAX_NAME_LEN - 1] = 0;
    strncpy(g_table[idx].path, path, MAX_PATH_LEN - 1);
    g_table[idx].path[MAX_PATH_LEN - 1] = 0;

    if(!found)
    {
        g_count++;
    }

    return true;
}

const char *cmdreg_lookup(const char *name)
{
    if(!g_table || !name || !*name)
    {
        return NULL;
    }

    bool found = false;
    size_t idx = find_slot(name, &found);

    if(idx == (size_t)-1 || !found)
    {
        return NULL;
    }

    return g_table[idx].path;
}

void cmdreg_reset(void)
{   
    if(g_table)
    {
        free(g_table);

        g_table = NULL;
    }

    g_capacity = CMDREG_MAX_ENTRIES;
    g_count = 0;
}

int cmdreg_init(const char *map_path)
{
    cmdreg_reset();

    if(!validate_table())
    {
        return false;
    }

    FILE *file = fopen(map_path, "r");
    
    if(!file)
    {
        return false;
    }

    char line[MAX_LINE_LEN];

    while(fgets(line, sizeof(line), file))
    {
        char *key;
        char *value;

        if(parse_keyvalue(line, &key, &value))
        {
            if(!cmdreg_add(key, value))
            {
                // TODO: Error output
            }
            else
            {
            }
        }
    }

    fclose(file);
    return true;
}
