#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <syscall.h>
#include <diffwm/diffwm.h>
#include <diffwm/terminal_component.h>
#include <diffgfx/draw.h>
#include <difffonts/fonts.h>
#include <system/threads.h>
#include <system/command_registry.h>
#include <system/process.h>
#include <stdbool.h>
#include <dirent.h>

#define WIN_W 640
#define WIN_H 600

// VGA color to RGB mapping
static term_color_t vga_to_color(uint8_t vga_color)
{
    term_color_t c = {0, 0, 0, 0xFF};

    switch (vga_color & 0xF)
    {
        case 0x0: c.r = 0;   c.g = 0;   c.b = 0;   break; // Black
        case 0x1: c.r = 0;   c.g = 0;   c.b = 170; break; // Blue
        case 0x2: c.r = 0;   c.g = 170; c.b = 0;   break; // Green
        case 0x3: c.r = 0;   c.g = 170; c.b = 170; break; // Cyan
        case 0x4: c.r = 170; c.g = 0;   c.b = 0;   break; // Red
        case 0x5: c.r = 170; c.g = 0;   c.b = 170; break; // Magenta
        case 0x6: c.r = 170; c.g = 85;  c.b = 0;   break; // Brown
        case 0x7: c.r = 170; c.g = 170; c.b = 170; break; // Gray
        case 0x8: c.r = 85;  c.g = 85;  c.b = 85;  break; // Dark Gray
        case 0x9: c.r = 85;  c.g = 85;  c.b = 255; break; // Light Blue
        case 0xA: c.r = 85;  c.g = 255; c.b = 85;  break; // Light Green
        case 0xB: c.r = 85;  c.g = 255; c.b = 255; break; // Light Cyan
        case 0xC: c.r = 255; c.g = 85;  c.b = 85;  break; // Light Red
        case 0xD: c.r = 255; c.g = 85;  c.b = 255; break; // Pink
        case 0xE: c.r = 255; c.g = 255; c.b = 85;  break; // Yellow
        case 0xF: c.r = 255; c.g = 255; c.b = 255; break; // White
        default:  c.r = 170; c.g = 170; c.b = 170; break; // Default to gray
    }

    return c;
}

static term_color_t vga_attr_to_color(uint8_t attr)
{
    return vga_to_color(attr & 0x0F);
}

// Terminal component
static terminal_component_t g_terminal;

static const char *g_shell_name = "Different Terminal";
static const unsigned g_ver_major = 1;
static const unsigned g_ver_minor = 0;

static const term_color_t default_color = {203, 219, 252, 0xFF};
static int g_last_status = 0;
static char g_cwd[256] = "/";

#define MAX_CHILDREN 32
static int g_children[MAX_CHILDREN];
static int g_child_count = 0;
static bool g_prompt_blocked = false;
static bool g_need_prompt = false;

static void term_puts_colored(const char *s, term_color_t color)
{
    term_color_t old = g_terminal.current_color;
    terminal_set_color(&g_terminal, color);
    terminal_puts(&g_terminal, s);
    terminal_set_color(&g_terminal, old);
}

static void display_banner(void)
{
    term_puts_colored(" D", vga_to_color(0x0B));        // Light Cyan
    term_puts_colored("ifferent ", vga_to_color(0x03));  // Cyan
    term_puts_colored("OS\n\n", vga_to_color(0x0B));     // Light Cyan
}


// Built-in commands
static int bi_help(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    terminal_puts(&g_terminal, " Available commands:\n");
    terminal_puts(&g_terminal, "--------------------------------------------\n");
    terminal_puts(&g_terminal, " cd    \t- Change current directory\n");
    terminal_puts(&g_terminal, " help  \t- List built-in commands\n");
    terminal_puts(&g_terminal, " echo  \t- Print its arguments\n");
    terminal_puts(&g_terminal, " ver   \t- Show shell version\n");
    terminal_puts(&g_terminal, " exit  \t- Exit the shell\n");
    terminal_puts(&g_terminal, "\n");

    return 0;
}

static int bi_echo(int argc, char **argv)
{
    terminal_set_color(&g_terminal, vga_to_color(0x03)); // Cyan
    for (int i = 1; i < argc; i++)
    {
        if (i > 1)
            terminal_putchar(&g_terminal, ' ');
        terminal_puts(&g_terminal, argv[i]);
    }
    terminal_putchar(&g_terminal, '\n');
    terminal_set_color(&g_terminal, default_color);

    return 0;
}

static int bi_ver(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    char buf[256];
    snprintf(buf, sizeof(buf), "%s (Version %u.%u)\n", g_shell_name, g_ver_major, g_ver_minor);
    terminal_puts(&g_terminal, buf);

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
        terminal_puts(&g_terminal, buf);
        return -1;
    }

    if (!getcwd(g_cwd, sizeof(g_cwd)))
    {
        strncpy(g_cwd, "/", sizeof(g_cwd) - 1);
        g_cwd[sizeof(g_cwd) - 1] = '\0';
    }

    /* Ensure initial color is the desired default (not the inherited tty attr). */
    g_terminal.current_color = default_color;
    g_terminal.bg_color = (term_color_t){0, 0, 0, 0xFF};

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

static bool drain_tty_output(void)
{
    char buf[256];
    uint8_t attrs[256];
    bool seen = false;
    term_color_t saved_color = g_terminal.current_color;

    while (1)
    {
        int n = system_tty_read(buf, sizeof(buf), TTY_READ_MODE_OUTPUT, attrs);
        if (n <= 0)
            break;

        seen = true;
        for (int i = 0; i < n; i++)
        {
            term_color_t c = (attrs[i] == 0x07) ? default_color : vga_attr_to_color(attrs[i]);
            terminal_set_color(&g_terminal, c);
            terminal_putchar(&g_terminal, buf[i]);
        }
    }

    terminal_set_color(&g_terminal, saved_color);
    return seen;
}

static void remember_child(int pid)
{
    if (pid <= 0 || g_child_count >= MAX_CHILDREN)
    {
        return;
    }

    g_children[g_child_count++] = pid;
}

static void reap_children(int *dirty_flag)
{
    for (int i = 0; i < g_child_count; )
    {
        int status = 0;
        int rc = system_wait_pid_nohang(g_children[i], &status);

        if (rc > 0)
        {
            g_last_status = status;

            g_children[i] = g_children[g_child_count - 1];
            g_child_count--;

            if (dirty_flag)
            {
                *dirty_flag = 1;
            }

            if (g_child_count == 0)
            {
                g_prompt_blocked = false;
                // Insert a blank line after process completion before the next prompt
                terminal_putchar(&g_terminal, '\n');
                g_need_prompt = true;
            }
            continue;
        }
        else if (rc < 0)
        {
            // Child is gone or invalid; drop it to avoid leaking the slot.
            g_children[i] = g_children[g_child_count - 1];
            g_child_count--;
            continue;
        }

        ++i;
    }
}

static int run_external(int argc, char **argv, int *dirty_flag)
{
    if (argc == 0)
        return 0;

    const char *path = cmdreg_lookup(argv[0]);
    if (!path)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "Unknown command: %s\n", argv[0]);
        terminal_puts(&g_terminal, buf);
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
        terminal_puts(&g_terminal, buf);
        return -1;
    }

    remember_child(pid);
    g_prompt_blocked = true;
    g_need_prompt = false;

    // Mark dirty so the prompt repaints after launching.
    if (dirty_flag)
    {
        *dirty_flag = 1;
    }

    return 0;
}

int main(void)
{
    window_t *win = window_create(80, 80, WIN_W, WIN_H, 0, "Different Terminal");
    if (!win)
        return -1;

    font_t *font = font_load_bdf("/system/fonts/spleen-6x12.bdf");
    if (!font)
    {
        window_destroy(win);
        return -2;
    }

    // Initialize terminal component
    terminal_component_init(&g_terminal, 0, 0, WIN_W, WIN_H, font);
    terminal_set_color(&g_terminal, default_color);

    // Add terminal to window
    window_add_component(win, &g_terminal.base);

    // Initialize command registry
    if (!cmdreg_init("/system/commands.map"))
    {
        terminal_puts(&g_terminal, "[CRITICAL ERROR] Unable to initialize command registry!\n");
        font_destroy(font);
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
    terminal_puts(&g_terminal, verline);

    int dirty = 1;

    // Display initial prompt
    char prompt[256];
    snprintf(prompt, sizeof(prompt), "%s> ", g_cwd);
    terminal_puts(&g_terminal, prompt);

    if (drain_tty_output())
    {
        dirty = 1;
    }

    int input_pos = 0;
    char input_line[512] = {0};

    while (1)
    {
        if (drain_tty_output())
        {
            dirty = 1;
        }

        reap_children(&dirty);
        if (!g_prompt_blocked && g_need_prompt)
        {
            snprintf(prompt, sizeof(prompt), "%s> ", g_cwd);
            terminal_puts(&g_terminal, prompt);
            dirty = 1;
            g_need_prompt = false;
        }

        diff_event_t ev;
        while (window_poll_event(win, &ev))
        {
            if (ev.type != DIFF_EVENT_KEY || !ev.key_pressed)
            {
                continue;
            }

            char c = (char)ev.key;

            if (c == '\n' || c == '\r')
            {
                // Execute command
                terminal_putchar(&g_terminal, '\n');
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
                            run_external(argc, argv, &dirty);
                        }
                    }
                }

                // Reset input
                input_pos = 0;
                input_line[0] = '\0';

                // Mark that we need to show the next prompt (after child completion)
                if (!g_prompt_blocked)
                {
                    snprintf(prompt, sizeof(prompt), "%s> ", g_cwd);
                    terminal_puts(&g_terminal, prompt);
                }
                else
                {
                    g_need_prompt = true;
                }
                dirty = 1;
            }
            else if (c == '\b' || c == 127) // Backspace
            {
                if (input_pos > 0)
                {
                    input_pos--;
                    input_line[input_pos] = '\0';
                    terminal_backspace(&g_terminal);
                    dirty = 1;
                }
            }
            else if (c >= 32 && c < 127) // Printable character
            {
                if (input_pos < (int)sizeof(input_line) - 1)
                {
                    input_line[input_pos++] = c;
                    terminal_putchar(&g_terminal, c);
                    dirty = 1;
                }
            }
        }

        if (dirty)
        {
            window_paint(&win->base);
            dirty = 0;
        }
        else
        {
            thread_sleep_ms(10);
        }
    }

    font_destroy(font);
    window_destroy(win);
    return 0;
}
