#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <console.h>
#include <unistd.h>

enum
{
    TYPE_W = 12,
    SIZE_W = 10,
    NAME_W = 20
};

static void hr(char ch)
{
    int width = 1 + TYPE_W + 1 + SIZE_W + 2 + NAME_W + 4;
    for (int i = 0; i < width; i++)
    {
        putchar(ch);
    }
    putchar('\n');
}

static int is_dir(const struct dirent *e)
{
#ifdef DT_DIR
    if (e->d_type == DT_DIR) return 1;
#endif
    if (e->d_name[0] == '.' && (e->d_name[1] == '\0' || (e->d_name[1] == '.' && e->d_name[2] == '\0'))) return 1;
    return e->d_size == 0;
}

static unsigned char to_lower_char(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
    return c;
}

static int icmp(const char *a, const char *b)
{
    while (*a && *b)
    {
        unsigned char ca = to_lower_char((unsigned char)*a);
        unsigned char cb = to_lower_char((unsigned char)*b);
        if (ca != cb) return (ca < cb) ? -1 : 1;
        a++;
        b++;
    }
    if (*a) return 1;
    if (*b) return -1;
    return 0;
}

static void sort_by_name(struct dirent *arr, size_t n)
{
    for (size_t i = 1; i < n; i++)
    {
        struct dirent key = arr[i];
        size_t j = i;
        while (j > 0 && icmp(arr[j - 1].d_name, key.d_name) > 0)
        {
            arr[j] = arr[j - 1];
            j--;
        }
        arr[j] = key;
    }
}

int main(int argc, char *argv[])
{
    const char *target = (argc > 1 && argv[1] && argv[1][0]) ? argv[1] : ".";
    DIR *d = opendir(target);
    if (!d)
    {
        printf("ls: There is no directory %s!\n", target);
        return 1;
    }

    size_t cap = 64;
    size_t n = 0;
    struct dirent *entries = malloc(cap * sizeof(*entries));
    if (!entries)
    {
        closedir(d);
        return 1;
    }

    while (1)
    {
        struct dirent ent;
        int r = readdir(d, &ent);
        if (r > 0) break;
        if (r < 0)
        {
            free(entries);
            closedir(d);
            return 1;
        }
        if (n == cap)
        {
            cap *= 2;
            struct dirent *tmp = realloc(entries, cap * sizeof(*tmp));
            if (!tmp)
            {
                free(entries);
                closedir(d);
                return 1;
            }
            entries = tmp;
        }
        entries[n++] = ent;
    }

    closedir(d);

    struct dirent *dirs = malloc(n * sizeof(*dirs));
    struct dirent *files = malloc(n * sizeof(*files));
    if (!dirs || !files)
    {
        free(entries);
        free(dirs);
        free(files);
        return 1;
    }

    size_t nd = 0, nf = 0;
    for (size_t i = 0; i < n; i++)
    {
        if (is_dir(&entries[i])) dirs[nd++] = entries[i];
        else files[nf++] = entries[i];
    }

    if (nd > 1) sort_by_name(dirs, nd);
    if (nf > 1) sort_by_name(files, nf);

    char display_path[256];

    if (strcmp(target, ".") == 0)
    {
        if (!getcwd(display_path, sizeof(display_path)))
        {
            snprintf(display_path, sizeof(display_path), ".");
        }
    }
    else
    {
        snprintf(display_path, sizeof(display_path), "%s", target);
    }

    size_t disp_len = strlen(display_path);
    if (disp_len == 0)
    {
        snprintf(display_path, sizeof(display_path), ".");
        disp_len = strlen(display_path);
    }

    if (display_path[disp_len - 1] != '/' && disp_len + 1 < sizeof(display_path))
    {
        display_path[disp_len] = '/';
        display_path[disp_len + 1] = '\0';
    }

    printf("Content of %s\n", display_path);
    hr('=');
    printf(" %-12s %10s  %s\n", "Type", "Size (bytes)", "Name");
    hr('-');

    for (size_t i = 0; i < nd; i++)
    {
        uint8_t c;
        console_get_fgcolor(&c);
        console_set_fgcolor(CONSOLE_COLOR_YELLOW);
        printf(" %-12s ", "DIRECTORY");
        console_set_fgcolor(c);
        printf(" %10u  %s/\n", (unsigned)dirs[i].d_size, dirs[i].d_name);
    }

    for (size_t i = 0; i < nf; i++)
    {
        uint8_t c;
        console_get_fgcolor(&c);
        console_set_fgcolor(CONSOLE_COLOR_CYAN);
        printf(" %-12s ", "FILE");
        console_set_fgcolor(c);
        printf(" %10u  %s\n", (unsigned)files[i].d_size, files[i].d_name);
    }

    hr('-');

    free(entries);
    free(dirs);
    free(files);
    return 0;
}
