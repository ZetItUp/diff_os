/*
 * DiffRuntime - Program Execution Implementation
 */

#include <runtime/exec.h>
#include <system/command_registry.h>
#include <system/process.h>
#include <syscall.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

/* Internal PATH storage */
static char g_path_dirs[RT_MAX_PATHS][RT_MAX_PATH];
static int g_path_count = 0;
static bool g_initialized = false;

/* Default PATH */
static const char *DEFAULT_PATH = "/programs:/system/bin";

/* Default commands.map location */
static const char *DEFAULT_CMDMAP = "/system/commands.map";

/*
 * Parse a colon-separated PATH string into individual directories.
 */
static int parse_path_string(const char *path_str)
{
    if (!path_str || !*path_str)
    {
        return 0;
    }

    g_path_count = 0;

    const char *start = path_str;
    const char *end;

    while (*start && g_path_count < RT_MAX_PATHS)
    {
        /* Find next colon or end of string */
        end = start;
        while (*end && *end != ':')
        {
            end++;
        }

        size_t len = (size_t)(end - start);
        if (len > 0 && len < RT_MAX_PATH)
        {
            strncpy(g_path_dirs[g_path_count], start, len);
            g_path_dirs[g_path_count][len] = '\0';

            /* Remove trailing slash if present */
            if (len > 1 && g_path_dirs[g_path_count][len - 1] == '/')
            {
                g_path_dirs[g_path_count][len - 1] = '\0';
            }

            g_path_count++;
        }

        if (*end == ':')
        {
            start = end + 1;
        }
        else
        {
            break;
        }
    }

    return g_path_count;
}

/*
 * Build a PATH string from the internal directory list.
 */
static int build_path_string(char *out, size_t out_size)
{
    if (!out || out_size == 0)
    {
        return RT_ERR_INVALID;
    }

    out[0] = '\0';
    size_t pos = 0;

    for (int i = 0; i < g_path_count; i++)
    {
        size_t dir_len = strlen(g_path_dirs[i]);
        size_t needed = dir_len + (i > 0 ? 1 : 0);

        if (pos + needed >= out_size)
        {
            break;
        }

        if (i > 0)
        {
            out[pos++] = ':';
        }

        strcpy(out + pos, g_path_dirs[i]);
        pos += dir_len;
    }

    out[pos] = '\0';
    return RT_OK;
}

bool rt_file_exists(const char *path)
{
    if (!path || !*path)
    {
        return false;
    }

    DIR *dir = opendir(path);
    if (dir)
    {
        closedir(dir);

        return false;
    }

    int fd = system_open(path, O_RDONLY, 0);
    if (fd < 0)
    {
        return false;
    }

    system_close(fd);

    return true;
}

int rt_init(const char *commands_map_path)
{
    if (g_initialized)
    {
        return RT_OK;
    }

    /* Initialize command registry */
    const char *map_path = commands_map_path ? commands_map_path : DEFAULT_CMDMAP;
    if (!cmdreg_init(map_path))
    {
        /* Non-fatal: commands.map might not exist */
    }

    /* Initialize default PATH */
    parse_path_string(DEFAULT_PATH);

    g_initialized = true;
    return RT_OK;
}

void rt_shutdown(void)
{
    if (!g_initialized)
    {
        return;
    }

    cmdreg_reset();
    g_path_count = 0;
    g_initialized = false;
}

int rt_resolve(const char *name, char *out_path, size_t out_size, int flags)
{
    if (!name || !*name || !out_path || out_size == 0)
    {
        return RT_ERR_INVALID;
    }

    /* Use default flags if none specified */
    if (flags == 0)
    {
        flags = RT_RESOLVE_ALL;
    }

    /* If name contains a path separator, treat it as a direct path */
    if (strchr(name, '/') != NULL)
    {
        /* Check if it's an absolute path */
        if (name[0] == '/')
        {
            if (rt_file_exists(name))
            {
                strncpy(out_path, name, out_size - 1);
                out_path[out_size - 1] = '\0';
                return RT_OK;
            }
        }
        else
        {
            /* Relative path - resolve against cwd */
            char cwd[RT_MAX_PATH];
            if (getcwd(cwd, sizeof(cwd)))
            {
                char full_path[RT_MAX_PATH];
                snprintf(full_path, sizeof(full_path), "%s/%s", cwd, name);

                if (rt_file_exists(full_path))
                {
                    strncpy(out_path, full_path, out_size - 1);
                    out_path[out_size - 1] = '\0';
                    return RT_OK;
                }
            }
        }

        return RT_ERR_NOT_FOUND;
    }

    /* 1. Search current working directory */
    if (flags & RT_RESOLVE_CWD)
    {
        char cwd[RT_MAX_PATH];
        if (getcwd(cwd, sizeof(cwd)))
        {
            char test_path[RT_MAX_PATH];

            /* Try name.dex */
            snprintf(test_path, sizeof(test_path), "%s/%s.dex", cwd, name);
            if (rt_file_exists(test_path))
            {
                strncpy(out_path, test_path, out_size - 1);
                out_path[out_size - 1] = '\0';
                return RT_OK;
            }

            /* Try name directly */
            snprintf(test_path, sizeof(test_path), "%s/%s", cwd, name);
            if (rt_file_exists(test_path))
            {
                strncpy(out_path, test_path, out_size - 1);
                out_path[out_size - 1] = '\0';
                return RT_OK;
            }
        }
    }

    /* 2. Search commands.map */
    if (flags & RT_RESOLVE_CMDMAP)
    {
        const char *mapped = cmdreg_lookup(name);
        if (mapped && rt_file_exists(mapped))
        {
            strncpy(out_path, mapped, out_size - 1);
            out_path[out_size - 1] = '\0';
            return RT_OK;
        }
    }

    /* 3. Search PATH directories */
    if (flags & RT_RESOLVE_PATH)
    {
        for (int i = 0; i < g_path_count; i++)
        {
            char test_path[RT_MAX_PATH];

            /* Try dir/name/name.dex (standard program layout) */
            snprintf(test_path, sizeof(test_path), "%s/%s/%s.dex",
                     g_path_dirs[i], name, name);
            if (rt_file_exists(test_path))
            {
                strncpy(out_path, test_path, out_size - 1);
                out_path[out_size - 1] = '\0';
                return RT_OK;
            }

            /* Try dir/name.dex */
            snprintf(test_path, sizeof(test_path), "%s/%s.dex",
                     g_path_dirs[i], name);
            if (rt_file_exists(test_path))
            {
                strncpy(out_path, test_path, out_size - 1);
                out_path[out_size - 1] = '\0';
                return RT_OK;
            }

            /* Try dir/name (without .dex) */
            snprintf(test_path, sizeof(test_path), "%s/%s",
                     g_path_dirs[i], name);
            if (rt_file_exists(test_path))
            {
                strncpy(out_path, test_path, out_size - 1);
                out_path[out_size - 1] = '\0';
                return RT_OK;
            }
        }
    }

    return RT_ERR_NOT_FOUND;
}

int rt_exec(const char *name, int argc, char **argv, int flags)
{
    if (!name || !*name)
    {
        return RT_ERR_INVALID;
    }

    /* Ensure runtime is initialized */
    if (!g_initialized)
    {
        rt_init(NULL);
    }

    /* Resolve the program path */
    char resolved_path[RT_MAX_PATH];
    int rc = rt_resolve(name, resolved_path, sizeof(resolved_path), 0);
    if (rc != RT_OK)
    {
        return RT_ERR_NOT_FOUND;
    }

    /* Spawn the process */
    int pid = process_spawn(resolved_path, argc, argv);
    if (pid < 0)
    {
        return RT_ERR_SPAWN_FAIL;
    }

    /* If RT_SPAWN_WAIT is set, wait for completion */
    if (flags & RT_SPAWN_WAIT)
    {
        int status = 0;
        process_wait(pid, &status);
        return status;
    }

    return pid;
}

int rt_exec_wait(const char *name, int argc, char **argv, int *status)
{
    int rc = rt_exec(name, argc, argv, RT_SPAWN_WAIT);

    if (rc < 0)
    {
        return rc;
    }

    if (status)
    {
        *status = rc;
    }

    return RT_OK;
}

int rt_get_path(char *out_path, size_t out_size)
{
    return build_path_string(out_path, out_size);
}

int rt_set_path(const char *path)
{
    if (!path)
    {
        g_path_count = 0;
        return RT_OK;
    }

    parse_path_string(path);
    return RT_OK;
}

int rt_append_path(const char *dir)
{
    if (!dir || !*dir)
    {
        return RT_ERR_INVALID;
    }

    if (g_path_count >= RT_MAX_PATHS)
    {
        return RT_ERR_NO_MEMORY;
    }

    strncpy(g_path_dirs[g_path_count], dir, RT_MAX_PATH - 1);
    g_path_dirs[g_path_count][RT_MAX_PATH - 1] = '\0';
    g_path_count++;

    return RT_OK;
}

int rt_prepend_path(const char *dir)
{
    if (!dir || !*dir)
    {
        return RT_ERR_INVALID;
    }

    if (g_path_count >= RT_MAX_PATHS)
    {
        return RT_ERR_NO_MEMORY;
    }

    /* Shift existing entries */
    for (int i = g_path_count; i > 0; i--)
    {
        strcpy(g_path_dirs[i], g_path_dirs[i - 1]);
    }

    strncpy(g_path_dirs[0], dir, RT_MAX_PATH - 1);
    g_path_dirs[0][RT_MAX_PATH - 1] = '\0';
    g_path_count++;

    return RT_OK;
}
