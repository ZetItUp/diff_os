#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <syscall.h>
#include <diffwm/diffwm.h>
#include <diffgfx/draw.h>
#include <difffonts/fonts.h>
#include <system/threads.h>
#include <system/command_registry.h>
#include <system/process.h>
#include <stdbool.h>
#include <dirent.h>

#define WIN_W 640
#define WIN_H 400

#define MAX_LINES 128
#define MAX_COLS  80

// VGA color to RGB mapping
static uint32_t vga_to_rgb(uint8_t vga_color)
{
    switch (vga_color & 0xF)
    {
        case 0x0: return color_rgb(0, 0, 0);         // Black
        case 0x1: return color_rgb(0, 0, 170);       // Blue
        case 0x2: return color_rgb(0, 170, 0);       // Green
        case 0x3: return color_rgb(0, 170, 170);     // Cyan
        case 0x4: return color_rgb(170, 0, 0);       // Red
        case 0x5: return color_rgb(170, 0, 170);     // Magenta
        case 0x6: return color_rgb(170, 85, 0);      // Brown
        case 0x7: return color_rgb(170, 170, 170);   // Gray
        case 0x8: return color_rgb(85, 85, 85);      // Dark Gray
        case 0x9: return color_rgb(85, 85, 255);     // Light Blue
        case 0xA: return color_rgb(85, 255, 85);     // Light Green
        case 0xB: return color_rgb(85, 255, 255);    // Light Cyan
        case 0xC: return color_rgb(255, 85, 85);     // Light Red
        case 0xD: return color_rgb(255, 85, 255);    // Pink
        case 0xE: return color_rgb(255, 255, 85);    // Yellow
        case 0xF: return color_rgb(255, 255, 255);   // White
        default:  return color_rgb(170, 170, 170);   // Default to gray
    }
}

typedef struct
{
    char text[MAX_COLS];
    uint8_t colors[MAX_COLS];
    int len;
} line_t;

static line_t g_lines[MAX_LINES];
static int g_line_count = 0;
static int g_cursor_x = 0;
static int g_cursor_y = 0;
static uint8_t g_current_color = 0x07; // Gray on black

static const char *g_shell_name = "Different Terminal";
static const unsigned g_ver_major = 1;
static const unsigned g_ver_minor = 0;

static int g_last_status = 0;
static char g_cwd[256] = "/";

static void ensure_line(int y)
{
    while (g_line_count <= y)
    {
        if (g_line_count >= MAX_LINES)
        {
            // Scroll up
            for (int i = 0; i < MAX_LINES - 1; i++)
            {
                g_lines[i] = g_lines[i + 1];
            }
            g_line_count = MAX_LINES - 1;
        }
        g_lines[g_line_count].len = 0;
        g_lines[g_line_count].text[0] = '\0';
        g_line_count++;
    }
}

static void putc_at(int x, int y, char c, uint8_t color)
{
    if (y < 0 || y >= MAX_LINES || x < 0 || x >= MAX_COLS)
        return;

    ensure_line(y);

    if (x >= g_lines[y].len)
    {
        // Extend line
        for (int i = g_lines[y].len; i < x; i++)
        {
            g_lines[y].text[i] = ' ';
            g_lines[y].colors[i] = color;
        }
        g_lines[y].len = x + 1;
    }

    g_lines[y].text[x] = c;
    g_lines[y].colors[x] = color;
    g_lines[y].text[g_lines[y].len] = '\0';
}

static void term_putchar(char c)
{
    if (c == '\n')
    {
        g_cursor_y++;
        g_cursor_x = 0;
        return;
    }
    if (c == '\r')
    {
        g_cursor_x = 0;
        return;
    }

    putc_at(g_cursor_x, g_cursor_y, c, g_current_color);
    g_cursor_x++;

    if (g_cursor_x >= MAX_COLS)
    {
        g_cursor_x = 0;
        g_cursor_y++;
    }
}

static void term_puts(const char *s)
{
    while (*s)
    {
        term_putchar(*s++);
    }
}

static void term_puts_colored(const char *s, uint8_t color)
{
    uint8_t old = g_current_color;
    g_current_color = color;
    term_puts(s);
    g_current_color = old;
}

static void display_banner(void)
{
    term_puts_colored(" D", 0x0B);        // Light Cyan
    term_puts_colored("ifferent ", 0x03);  // Cyan
    term_puts_colored("OS\n\n", 0x0B);     // Light Cyan
}

static void render(uint32_t *pix, int pitch_pixels, font_t *font)
{
    // Clear to black
    size_t total = (size_t)WIN_W * WIN_H;
    for (size_t i = 0; i < total; i++)
    {
        pix[i] = color_rgb(0, 0, 0);
    }

    if (!font)
        return;

    int fh = font_height(font);
    int fw = font_width(font);
    int y = 8;

    for (int i = 0; i < g_line_count && i < MAX_LINES; i++)
    {
        int x = 8;
        for (int j = 0; j < g_lines[i].len && j < MAX_COLS; j++)
        {
            uint32_t fg = vga_to_rgb(g_lines[i].colors[j]);
            char buf[2] = {g_lines[i].text[j], '\0'};
            font_draw_text(font, pix, pitch_pixels, x, y, buf, fg);
            x += fw;
        }
        y += fh;
        if (y >= WIN_H - fh)
            break;
    }

    // Draw cursor
    if (g_cursor_y >= 0 && g_cursor_y < g_line_count)
    {
        int cursor_screen_y = 8 + g_cursor_y * fh;
        int cursor_screen_x = 8 + g_cursor_x * fw;

        if (cursor_screen_y < WIN_H - fh)
        {
            // Draw cursor as an underscore
            for (int x = 0; x < fw - 1; x++)
            {
                int px = cursor_screen_x + x;
                int py = cursor_screen_y + fh - 2;
                if (px < WIN_W && py < WIN_H)
                {
                    pix[py * pitch_pixels + px] = color_rgb(170, 170, 170);
                }
            }
        }
    }
}

// Built-in commands
static int bi_help(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    term_puts(" Available commands:\n");
    term_puts("--------------------------------------------\n");
    term_puts(" cd    \t- Change current directory\n");
    term_puts(" help  \t- List built-in commands\n");
    term_puts(" echo  \t- Print its arguments\n");
    term_puts(" ver   \t- Show shell version\n");
    term_puts(" exit  \t- Exit the shell\n");
    term_puts("\n");

    return 0;
}

static int bi_echo(int argc, char **argv)
{
    g_current_color = 0x03; // Cyan
    for (int i = 1; i < argc; i++)
    {
        if (i > 1)
            term_putchar(' ');
        term_puts(argv[i]);
    }
    g_current_color = 0x07; // Gray
    term_putchar('\n');

    return 0;
}

static int bi_ver(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    char buf[256];
    snprintf(buf, sizeof(buf), "%s (Version %u.%u)\n", g_shell_name, g_ver_major, g_ver_minor);
    term_puts(buf);

    return 0;
}

static int bi_exit(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    exit(0);
    return 0;
}

static int bi_cd(int argc, char **argv)
{
    const char *arg = (argc < 2 || !argv[1] || !argv[1][0]) ? "/" : argv[1];

    if (chdir(arg) != 0)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "Directory %s does not exist.\n", arg);
        term_puts(buf);
        return -1;
    }

    if (!getcwd(g_cwd, sizeof(g_cwd)))
    {
        strncpy(g_cwd, "/", sizeof(g_cwd) - 1);
        g_cwd[sizeof(g_cwd) - 1] = '\0';
    }

    return 0;
}

static int tokenize(char *line, char **argv, int maxv)
{
    int argc = 0;
    char *s = line;

    size_t n = strlen(s);

    if (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
    {
        s[--n] = 0;
    }

    while (*s && argc < maxv)
    {
        while (*s == ' ' || *s == '\t')
            s++;

        if (!*s)
            break;

        argv[argc++] = s;

        while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n')
            s++;

        if (!*s)
            break;

        *s++ = 0;
    }

    return argc;
}

static int run_builtin(int argc, char **argv)
{
    if (argc == 0)
        return 0;

    if (strcmp(argv[0], "cd") == 0)
        return bi_cd(argc, argv);

    if (strcmp(argv[0], "help") == 0)
        return bi_help(argc, argv);

    if (strcmp(argv[0], "echo") == 0)
        return bi_echo(argc, argv);

    if (strcmp(argv[0], "ver") == 0)
        return bi_ver(argc, argv);

    if (strcmp(argv[0], "exit") == 0)
        return bi_exit(argc, argv);

    return 1; // Not a builtin
}

static int run_external(int argc, char **argv)
{
    if (argc == 0)
        return 0;

    const char *path = cmdreg_lookup(argv[0]);
    if (!path)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "Unknown command: %s\n", argv[0]);
        term_puts(buf);
        return -1;
    }

    int user_argc = argc - 1;

    int pid;
    if (user_argc <= 0)
    {
        pid = process_spawn(path, 0, NULL);
    }
    else
    {
        char *user_argv[16];
        for (int i = 0; i < user_argc; i++)
        {
            user_argv[i] = argv[i + 1];
        }
        pid = process_spawn(path, user_argc, user_argv);
    }

    if (pid < 0)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "[SYSTEM] Could not start %s\n", path);
        term_puts(buf);
        return -1;
    }

    int status = 0;
    int w = process_wait(pid, &status);
    if (w < 0)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "[SYSTEM] Failed to wait for process %d\n", pid);
        term_puts(buf);
        return -1;
    }

    g_last_status = status;
    if (status != 0)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s exited with %d\n", argv[0], status);
        term_puts(buf);
    }
    return status;
}

int main(void)
{
    window_t *win = window_create(80, 80, WIN_W, WIN_H, 0);
    if (!win)
        return -1;

    uint32_t *back = (uint32_t *)malloc((size_t)WIN_W * WIN_H * sizeof(uint32_t));
    if (!back)
    {
        window_destroy(win);
        return -2;
    }

    font_t *font = font_load_bdf("/system/fonts/spleen-8x16.bdf");
    if (!font)
    {
        free(back);
        window_destroy(win);
        return -3;
    }

    // Initialize terminal state
    g_line_count = 0;
    g_cursor_x = 0;
    g_cursor_y = 0;
    g_current_color = 0x07;

    // Initialize command registry
    if (!cmdreg_init("/system/commands.map"))
    {
        term_puts("[CRITICAL ERROR] Unable to initialize command registry!\n");
        font_destroy(font);
        free(back);
        window_destroy(win);
        return 127;
    }

    if (!getcwd(g_cwd, sizeof(g_cwd)))
    {
        strncpy(g_cwd, "/", sizeof(g_cwd) - 1);
        g_cwd[sizeof(g_cwd) - 1] = '\0';
    }

    // Display banner
    display_banner();

    char verline[256];
    snprintf(verline, sizeof(verline), "%s (Version %u.%u)\n\n", g_shell_name, g_ver_major, g_ver_minor);
    term_puts(verline);

    char *line = NULL;
    size_t cap = 0;
    int dirty = 1;

    // Display initial prompt
    char prompt[256];
    snprintf(prompt, sizeof(prompt), "%s> ", g_cwd);
    term_puts(prompt);

    char tty_buf[256];
    int input_pos = 0;
    char input_line[512] = {0};

    while (1)
    {
        // Read from tty
        int n = system_tty_read(tty_buf, (uint32_t)sizeof(tty_buf));
        if (n > 0)
        {
            for (int i = 0; i < n; i++)
            {
                char c = tty_buf[i];

                if (c == '\n' || c == '\r')
                {
                    // Execute command
                    term_putchar('\n');
                    input_line[input_pos] = '\0';

                    if (input_pos > 0)
                    {
                        char *argv[16];
                        int argc = tokenize(input_line, argv, 16);

                        if (argc > 0)
                        {
                            int rc = run_builtin(argc, argv);
                            if (rc == 1)
                            {
                                run_external(argc, argv);
                            }
                        }
                    }

                    // Reset input
                    input_pos = 0;
                    input_line[0] = '\0';

                    // Display new prompt
                    term_putchar('\n');
                    snprintf(prompt, sizeof(prompt), "%s> ", g_cwd);
                    term_puts(prompt);
                    dirty = 1;
                }
                else if (c == '\b' || c == 127) // Backspace
                {
                    if (input_pos > 0)
                    {
                        input_pos--;
                        input_line[input_pos] = '\0';

                        // Move cursor back
                        if (g_cursor_x > 0)
                        {
                            g_cursor_x--;
                            putc_at(g_cursor_x, g_cursor_y, ' ', g_current_color);
                        }
                        dirty = 1;
                    }
                }
                else if (c >= 32 && c < 127) // Printable character
                {
                    if (input_pos < (int)sizeof(input_line) - 1)
                    {
                        input_line[input_pos++] = c;
                        term_putchar(c);
                        dirty = 1;
                    }
                }
            }
        }

        if (dirty)
        {
            render(back, WIN_W, font);
            window_draw(win, back);
            dirty = 0;
        }
        else
        {
            thread_sleep_ms(10);
        }
    }

    font_destroy(font);
    free(back);
    window_destroy(win);
    return 0;
}
