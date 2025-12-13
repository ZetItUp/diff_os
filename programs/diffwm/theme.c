#include "theme.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Cursor type names for parsing
static const char *cursor_names[CURSOR_COUNT] = {
    "normal",
    "resize_h",
    "resize_v",
    "resize_diag_l",
    "resize_diag_r",
    "move",
    "text",
    "hand",
    "wait",
    "crosshair"
};

// Find cursor type by name, returns -1 if not found
static int find_cursor_type(const char *name)
{
    for (int i = 0; i < CURSOR_COUNT; i++)
    {
        if (strcmp(name, cursor_names[i]) == 0)
        {
            return i;
        }
    }
    return -1;
}

// Skip whitespace
static const char *skip_ws(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

// Trim trailing whitespace and newline
static void trim_end(char *s)
{
    int len = strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r' ||
                       s[len-1] == ' ' || s[len-1] == '\t'))
    {
        s[--len] = '\0';
    }
}

int theme_load(cursor_theme_t *theme, const char *theme_path)
{
    if (!theme || !theme_path) return -1;

    // Initialize theme
    memset(theme, 0, sizeof(*theme));
    strncpy(theme->name, "default", sizeof(theme->name) - 1);

    FILE *fp = fopen(theme_path, "r");
    if (!fp)
    {
        return -1;
    }

    char line[256];
    int current_cursor = -1;
    char current_path[128] = {0};
    int current_hotspot_x = 0;
    int current_hotspot_y = 0;

    while (fgets(line, sizeof(line), fp))
    {
        trim_end(line);
        const char *p = skip_ws(line);

        // Skip empty lines and comments
        if (*p == '\0' || *p == '#' || *p == ';')
        {
            continue;
        }

        // Section header: [cursor.type]
        if (*p == '[')
        {
            // Load previous cursor if we had one
            if (current_cursor >= 0 && current_path[0] != '\0')
            {
                theme->cursors[current_cursor].image = tga_load(current_path);
                theme->cursors[current_cursor].hotspot_x = current_hotspot_x;
                theme->cursors[current_cursor].hotspot_y = current_hotspot_y;
            }

            // Reset for new section
            current_cursor = -1;
            current_path[0] = '\0';
            current_hotspot_x = 0;
            current_hotspot_y = 0;

            // Parse section name
            p++;
            const char *end = strchr(p, ']');
            if (!end) continue;

            char section[64];
            int len = end - p;
            if (len >= (int)sizeof(section)) len = sizeof(section) - 1;
            strncpy(section, p, len);
            section[len] = '\0';

            // Check for cursor.X format
            if (strncmp(section, "cursor.", 7) == 0)
            {
                current_cursor = find_cursor_type(section + 7);
            }
            else if (strcmp(section, "theme") == 0)
            {
                // Theme metadata section
                current_cursor = -2; // Special marker
            }
        }
        // Key=value pairs
        else if (current_cursor >= 0 || current_cursor == -2)
        {
            const char *eq = strchr(p, '=');
            if (!eq) continue;

            char key[32];
            int klen = eq - p;
            if (klen >= (int)sizeof(key)) klen = sizeof(key) - 1;
            strncpy(key, p, klen);
            key[klen] = '\0';
            trim_end(key);

            const char *val = skip_ws(eq + 1);

            if (current_cursor == -2)
            {
                // Theme metadata
                if (strcmp(key, "name") == 0)
                {
                    strncpy(theme->name, val, sizeof(theme->name) - 1);
                }
            }
            else
            {
                // Cursor properties
                if (strcmp(key, "path") == 0)
                {
                    strncpy(current_path, val, sizeof(current_path) - 1);
                }
                else if (strcmp(key, "hotspot_x") == 0)
                {
                    current_hotspot_x = atoi(val);
                }
                else if (strcmp(key, "hotspot_y") == 0)
                {
                    current_hotspot_y = atoi(val);
                }
            }
        }
    }

    // Load last cursor if we had one
    if (current_cursor >= 0 && current_path[0] != '\0')
    {
        theme->cursors[current_cursor].image = tga_load(current_path);
        theme->cursors[current_cursor].hotspot_x = current_hotspot_x;
        theme->cursors[current_cursor].hotspot_y = current_hotspot_y;
    }

    fclose(fp);
    return 0;
}

void theme_free(cursor_theme_t *theme)
{
    if (!theme) return;

    for (int i = 0; i < CURSOR_COUNT; i++)
    {
        if (theme->cursors[i].image)
        {
            tga_free(theme->cursors[i].image);
            theme->cursors[i].image = NULL;
        }
    }
}

const cursor_t *theme_get_cursor(const cursor_theme_t *theme, cursor_type_t type)
{
    if (!theme || type < 0 || type >= CURSOR_COUNT)
    {
        return NULL;
    }

    const cursor_t *c = &theme->cursors[type];
    if (!c->image)
    {
        return NULL;
    }

    return c;
}
