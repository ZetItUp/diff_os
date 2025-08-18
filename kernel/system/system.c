#include "string.h"
#include "diff.h"
#include "heap.h"
#include "stdio.h"

/*
 * System config (strict SHELL section)
 * - Only reads keys inside [SHELL] (case-insensitive).
 * - Handles BOM, CR/LF, whitespace, inline comments (# or ;), quoted values.
 * - Normalizes cfg_path (trim + ensure leading '/'), collapses '//' in result.
 * - Returns kmalloc'ed path on success (caller frees), else NULL.
 * - Allman brace style; declarations at block start; English comments.
 */

static void collapse_slashes(char *s)
{
    char *r;
    char *w;

    if (!s)
    {
        return;
    }

    r = s;
    w = s;

    while (*r)
    {
        *w++ = *r;
        if (*r == '/')
        {
            r++;
            while (*r == '/')
            {
                r++;
            }
            continue;
        }
        r++;
    }

    *w = '\0';
}

static int ascii_tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return c - 'A' + 'a';
    }
    return c;
}

/* Trims trailing CR/LF/spaces and strips inline comments (# or ;) */
static void rstrip_and_decomment(char *s)
{
    size_t n;
    size_t i;

    if (!s)
    {
        return;
    }

    n = 0;
    while (s[n] != '\0')
    {
        if (s[n] == '#' || s[n] == ';')
        {
            s[n] = '\0';
            break;
        }
        n++;
    }

    i = 0;
    while (s[i] != '\0')
    {
        i++;
    }

    while (i > 0 && (s[i - 1] == '\r' || s[i - 1] == '\n' || s[i - 1] == ' ' || s[i - 1] == '\t'))
    {
        s[--i] = '\0';
    }
}

/* Left-trim spaces/tabs in-place. */
static void ltrim_inplace(char *s)
{
    char *p;
    char *dst;

    if (!s)
    {
        return;
    }

    p = s;
    while (*p == ' ' || *p == '\t')
    {
        p++;
    }

    if (p != s)
    {
        dst = s;
        while (*p)
        {
            *dst++ = *p++;
        }
        *dst = '\0';
    }
}

/* Return next NUL-terminated line from *it (in-place), trimming and decommenting. */
static char* next_line(char **it)
{
    char *s;
    char *p;
    char *line;

    if (!it || !*it)
    {
        return NULL;
    }

    s = *it;

    while (*s == '\r' || *s == '\n')
    {
        s++;
    }

    if (*s == '\0')
    {
        *it = s;
        return NULL;
    }

    p = s;
    while (*p && *p != '\r' && *p != '\n')
    {
        p++;
    }

    if (*p != '\0')
    {
        *p = '\0';
        p++;
    }

    line = s;
    rstrip_and_decomment(line);

    while (*p == '\r' || *p == '\n')
    {
        p++;
    }

    *it = p;
    return line;
}

static char* dup_unquoted_slice(const char *p, size_t len)
{
    char *out;

    out = (char *)kmalloc(len + 1);
    if (!out)
    {
        return NULL;
    }

    if (len > 0)
    {
        memcpy(out, p, len);
    }
    out[len] = '\0';
    return out;
}

/* Parse a value (quoted or plain) to a heap string; make absolute and collapse slashes. */
static char* parse_value_to_heap(const char *val_start)
{
    const char *p;
    const char *q;
    size_t len;
    char quote;
    char *res;

    p = val_start;
    while (*p == ' ' || *p == '\t')
    {
        p++;
    }

    if (*p == '\"' || *p == '\'')
    {
        quote = *p++;
        q = p;
        while (*q && *q != quote)
        {
            q++;
        }
        len = (size_t)(q - p);
        res = dup_unquoted_slice(p, len);
    }
    else
    {
        len = 0;
        while (p[len] != '\0' && p[len] != '#' && p[len] != ';')
        {
            len++;
        }
        while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t'))
        {
            len--;
        }
        res = dup_unquoted_slice(p, len);
    }

    if (!res)
    {
        return NULL;
    }

    ltrim_inplace(res);
    rstrip_and_decomment(res);

    if (res[0] != '/')
    {
        char *out;
        size_t L;

        L = strlen(res);
        out = (char *)kmalloc(L + 2);
        if (!out)
        {
            kfree(res);
            return NULL;
        }
        out[0] = '/';
        memcpy(out + 1, res, L + 1);
        kfree(res);
        res = out;
    }

    collapse_slashes(res);
    return res;
}

/* Case-insensitive check if line starts with key= ; returns pointer to value in *val_out */
static int key_equals_ci(const char *line, const char *key, const char **val_out)
{
    const char *p;
    const char *k;

    p = line;
    k = key;

    while (*p == ' ' || *p == '\t')
    {
        p++;
    }

    while (*k && ascii_tolower((unsigned char)*p) == ascii_tolower((unsigned char)*k))
    {
        p++;
        k++;
    }

    if (*k != '\0')
    {
        return 0;
    }

    while (*p == ' ' || *p == '\t')
    {
        p++;
    }

    if (*p != '=')
    {
        return 0;
    }

    p++;
    while (*p == ' ' || *p == '\t')
    {
        p++;
    }

    if (val_out)
    {
        *val_out = p;
    }

    return 1;
}

char* find_shell_path(const FileTable *table, const char *cfg_path)
{
    char norm_cfg[256];
    int idx;
    const FileEntry *fe;
    char *cfg_data;
    int bytes_read;
    char *it;
    char *line;
    int in_shell;
    char *result;

    /* Normalize cfg_path: trim + ensure leading slash */
    (void)strlcpy(norm_cfg, cfg_path, sizeof(norm_cfg));
    ltrim_inplace(norm_cfg);
    rstrip_and_decomment(norm_cfg);

    if (norm_cfg[0] != '/')
    {
        char tmp[256];

        (void)snprintf(tmp, sizeof(tmp), "/%s", norm_cfg);
        (void)strlcpy(norm_cfg, tmp, sizeof(norm_cfg));
    }

    idx = find_entry_by_path(table, norm_cfg);
    if (idx == -1)
    {
        printf("[SHELL] Config file '%s' not found\n", norm_cfg);
        return NULL;
    }

    fe = &table->entries[idx];

    cfg_data = (char *)kmalloc(fe->sector_count * 512 + 1);
    if (!cfg_data)
    {
        printf("[SHELL] Out of memory reading '%s'\n", norm_cfg);
        return NULL;
    }

    bytes_read = read_file(table, norm_cfg, cfg_data);
    if (bytes_read <= 0)
    {
        printf("[SHELL] Config file '%s' is empty\n", norm_cfg);
        kfree(cfg_data);
        return NULL;
    }

    cfg_data[bytes_read] = '\0';

    /* Strip UTF-8 BOM if present */
    if ((unsigned char)cfg_data[0] == 0xEF &&
        (unsigned char)cfg_data[1] == 0xBB &&
        (unsigned char)cfg_data[2] == 0xBF)
    {
        memmove(cfg_data, cfg_data + 3, (size_t)bytes_read - 2);
    }

    in_shell = 0;
    result = NULL;

    it = cfg_data;
    for (line = next_line(&it); line; line = next_line(&it))
    {
        const char *val;

        ltrim_inplace(line);

        if (*line == '\0')
        {
            continue;
        }

        /* Section header */
        if (*line == '[')
        {
            char *r;
            const char *sec;
            size_t len;

            r = line;
            while (*r && *r != ']')
            {
                r++;
            }

            if (*r == ']')
            {
                sec = line + 1;
                len = (size_t)(r - sec);

                if (len == 5 &&
                    ascii_tolower((unsigned char)sec[0]) == 's' &&
                    ascii_tolower((unsigned char)sec[1]) == 'h' &&
                    ascii_tolower((unsigned char)sec[2]) == 'e' &&
                    ascii_tolower((unsigned char)sec[3]) == 'l' &&
                    ascii_tolower((unsigned char)sec[4]) == 'l')
                {
                    in_shell = 1;
                }
                else
                {
                    in_shell = 0;
                }
            }

            continue;
        }

        /* Only accept keys while inside [SHELL] */
        if (in_shell)
        {
            if (key_equals_ci(line, "path", &val) ||
                key_equals_ci(line, "shell", &val) ||
                key_equals_ci(line, "exec", &val))
            {
                result = parse_value_to_heap(val);
                if (!result)
                {
                    printf("[SHELL] OOM parsing path value\n");
                }
                break;
            }
        }
    }

    kfree(cfg_data);
    return result;
}

