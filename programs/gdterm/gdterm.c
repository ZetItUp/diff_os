#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <syscall.h>
#include <diffwm/diffwm.h>
#include <diffwm/terminal_component.h>
#include <diffwm/picture_component.h>
#include <diffgfx/draw.h>
#include <difffonts/fonts.h>
#include <difftga.h>
#include <system/threads.h>
#include <runtime/exec.h>
#include <system/process.h>
#include <stdbool.h>
#include <dirent.h>
#include <tty.h>

#define WIN_W 640
#define WIN_H 400
#define TERMINAL_PADDING_LEFT 8
#define TERMINAL_PADDING_TOP 8

// Default terminal color (light blue)
static const term_color_t default_color = {203, 219, 252, 0xFF};

// VGA color to RGB mapping
static term_color_t vga_to_color(uint8_t vga_color)
{
    // Handle CONSOLE_COLOR_DEFAULT (0xFF) - return terminal default
    if (vga_color == 0xFF)
    {
        return default_color;
    }

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
static int g_terminal_font_height = 0;
static int g_terminal_font_ascent = 0;

static const char *g_shell_name = "Different Terminal";
static const unsigned g_ver_major = 0;
static const unsigned g_ver_minor = 1;

static int g_last_status = 0;
static char g_cwd[256] = "/";
static bool g_logo_enabled = true;
static tga_image_t *g_logo_img = NULL;
static picture_component_t g_logo_picture;
static int g_logo_dirty = 0;

static void claim_gdterm_tty(void)
{
    int tty_id = tty_allocate_device();

    if (tty_id >= 0)
    {
        (void)tty_set_device(tty_id);
    }
}

#define MAX_CHILDREN 32
static int g_children[MAX_CHILDREN];
static int g_child_count = 0;
static bool g_prompt_blocked = false;
static bool g_need_prompt = false;
static bool g_should_quit = false;
static bool g_has_focus = false;

// Command history
#define HISTORY_MAX 50
static char g_history[HISTORY_MAX][512];
static int g_history_count = 0;
static int g_history_index = -1;

// Key codes for arrow keys
#define KEY_UP    0xad
#define KEY_DOWN  0xaf

static void history_add(const char *cmd)
{
    if (!cmd || !cmd[0])
    {
        return;
    }

    // Don't add duplicate of the last command
    if (g_history_count > 0 && strcmp(g_history[g_history_count - 1], cmd) == 0)
    {
        return;
    }

    // Shift history if full
    if (g_history_count >= HISTORY_MAX)
    {
        for (int i = 0; i < HISTORY_MAX - 1; i++)
        {
            strcpy(g_history[i], g_history[i + 1]);
        }
        g_history_count = HISTORY_MAX - 1;
    }

    strncpy(g_history[g_history_count], cmd, 511);
    g_history[g_history_count][511] = '\0';
    g_history_count++;
}

static void window_damage_terminal_full(window_t *window);

static int terminal_visible_line_count(int font_height_value)
{
    if (font_height_value <= 0)
    {
        return 1;
    }

    int usable_height = g_terminal.base.height - TERMINAL_PADDING_TOP;
    int max_visible_lines = usable_height / font_height_value;
    if (max_visible_lines < 1) max_visible_lines = 1;
    if (max_visible_lines > TERM_MAX_LINES) max_visible_lines = TERM_MAX_LINES;
    return max_visible_lines;
}

static void window_damage_terminal_full(window_t *window)
{
    if (!window)
    {
        return;
    }

    window_damage(window,
                  g_terminal.base.x,
                  g_terminal.base.y,
                  g_terminal.base.width,
                  g_terminal.base.height);
}

static void window_damage_terminal_line(window_t *window, int line_index)
{
    if (!window || g_terminal_font_height <= 0)
    {
        return;
    }

    int max_visible_lines = terminal_visible_line_count(g_terminal_font_height);
    if (line_index < 0)
    {
        return;
    }

    if (line_index >= max_visible_lines)
    {
        window_damage_terminal_full(window);
        return;
    }

    int x_position = g_terminal.base.x + TERMINAL_PADDING_LEFT;
    int ascent = g_terminal_font_ascent;
    if (ascent < 0) ascent = 0;

    int y_position = g_terminal.base.y + TERMINAL_PADDING_TOP + line_index * g_terminal_font_height - ascent;
    if (y_position < g_terminal.base.y)
    {
        y_position = g_terminal.base.y;
    }

    int width = g_terminal.base.width - TERMINAL_PADDING_LEFT;
    int height = g_terminal_font_height + ascent;
    if (y_position + height > g_terminal.base.y + g_terminal.base.height)
    {
        height = g_terminal.base.y + g_terminal.base.height - y_position;
    }

    window_damage(window, x_position, y_position, width, height);
}

static void window_damage_logo(window_t *window)
{
    if (!window || !g_logo_img || !g_logo_img->pixels)
    {
        return;
    }

    window_damage(window,
                  g_logo_picture.base.x,
                  g_logo_picture.base.y,
                  g_logo_picture.base.width,
                  g_logo_picture.base.height);
}

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
    terminal_puts(&g_terminal, " logo  \t- Toggle logo overlay (logo on|off)\n");
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

    g_should_quit = true;
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

static int bi_logo(int argc, char **argv)
{
    if (!g_logo_img)
    {
        terminal_puts(&g_terminal, "Logo not loaded.\n");
        return 0;
    }

    if (argc < 2)
    {
        terminal_puts(&g_terminal, g_logo_enabled ? "Logo: on\n" : "Logo: off\n");
        return 0;
    }

    if (strcmp(argv[1], "on") == 0)
    {
    g_logo_enabled = true;
    }
    else if (strcmp(argv[1], "off") == 0)
    {
        g_logo_enabled = false;
    }
    else
    {
        terminal_puts(&g_terminal, "Usage: logo on|off\n");
        return 0;
    }

    g_logo_picture.base.visible = g_logo_enabled;
    g_logo_dirty = 1;
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

    if (strcmp(argv[0], "logo") == 0)
        return bi_logo(argc, argv);

    return 1; // Not a builtin
}

static bool drain_tty_output(void)
{
    char buf[256];
    bool had_output = false;

    for (;;)
    {
        int n = system_tty_read_output(buf, sizeof(buf) - 1);
        if (n <= 0)
            break;

        buf[n] = '\0';

        for (int i = 0; i < n; i++)
        {
            terminal_putchar(&g_terminal, buf[i]);
        }

        had_output = true;
    }

    return had_output;
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

    /* Resolve the program using DiffRuntime */
    char resolved_path[RT_MAX_PATH];
    int rc = rt_resolve(argv[0], resolved_path, sizeof(resolved_path), RT_RESOLVE_ALL);
    if (rc != RT_OK)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "Unknown command: %s\n", argv[0]);
        terminal_puts(&g_terminal, buf);
        return -1;
    }

    int pid = process_spawn(resolved_path, argc, argv);

    if (pid < 0)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "[SYSTEM] Could not start %s\n", resolved_path);
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
    claim_gdterm_tty();

    window_t *win = window_create(80, 80, WIN_W, WIN_H, WINDOW_FLAG_NO_BACKGROUND,
                                  "Different Terminal");
    if (!win)
        return -1;

    window_request_focus(win);

    font_t *font = font_load_bdf("/system/fonts/spleen-6x12.bdf");
    if (!font)
    {
        window_destroy(win);
        return -2;
    }
    g_terminal_font_height = font_height(font);
    g_terminal_font_ascent = font_ascent(font);

    // Initialize terminal component
    terminal_component_init(&g_terminal, 0, 0, WIN_W, WIN_H, font);
    terminal_set_default_color(&g_terminal, default_color);

    // Add terminal to window
    window_add_component(win, &g_terminal.base);

    // Load and add logo picture (drawn after terminal so it overlays text)
    g_logo_img = tga_load("/system/graphics/Logo.tga");
    if (g_logo_img && g_logo_img->pixels)
    {
        int logo_x = WIN_W - (int)g_logo_img->width - 10;
        if (logo_x < 0) 
            logo_x = 0;
        
        int logo_y = 5;

        picture_component_init(&g_logo_picture,
                               logo_x,
                               logo_y,
                               (int)g_logo_img->width,
                               (int)g_logo_img->height,
                               g_logo_img->pixels,
                               (int)g_logo_img->width);
        g_logo_picture.base.visible = g_logo_enabled;
        window_add_component(win, &g_logo_picture.base);
    }
    else
    {
        g_logo_enabled = false;
    }

    // Initialize runtime (loads commands.map and sets up PATH)
    if (rt_init("/system/commands.map") != RT_OK)
    {
        terminal_puts(&g_terminal, "[WARNING] Runtime initialization had issues.\n");
        // Non-fatal - continue anyway
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
    window_damage_terminal_full(win);

    if (drain_tty_output())
    {
        dirty = 1;
        window_damage_terminal_full(win);
    }

    if (g_logo_img && g_logo_enabled)
    {
        dirty = 1;
        window_damage_logo(win);
    }

    if (dirty)
    {
        window_paint(&win->base);
        dirty = 0;
    }

    int input_pos = 0;
    char input_line[512] = {0};

    while (!g_should_quit)
    {
        if (drain_tty_output())
        {
            dirty = 1;
            window_damage_terminal_full(win);
        }

        if (g_logo_dirty)
        {
            dirty = 1;
            g_logo_dirty = 0;
            window_damage_logo(win);
        }

        reap_children(&dirty);
        if (!g_prompt_blocked && g_need_prompt)
        {
            snprintf(prompt, sizeof(prompt), "%s> ", g_cwd);
            terminal_puts(&g_terminal, prompt);
            dirty = 1;
            g_need_prompt = false;
            window_damage_terminal_line(win, g_terminal.cursor_y);
        }

        diff_event_t ev;
        while (window_poll_event(win, &ev))
        {
            if (ev.type == DIFF_EVENT_FOCUS_GAINED)
            {
                g_has_focus = true;
                continue;
            }
            if (ev.type == DIFF_EVENT_FOCUS_LOST)
            {
                g_has_focus = false;
                continue;
            }
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
                    // Add to history before tokenizing (which modifies the string)
                    history_add(input_line);
                    g_history_index = -1;

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

                // Reset input and history browsing
                input_pos = 0;
                input_line[0] = '\0';
                g_history_index = -1;

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
                window_damage_terminal_full(win);
            }
            else if (c == '\b' || c == 127) // Backspace
            {
                if (input_pos > 0)
                {
                    input_pos--;
                    input_line[input_pos] = '\0';
                    terminal_backspace(&g_terminal);
                    dirty = 1;
                    window_damage_terminal_line(win, g_terminal.cursor_y);
                }
            }
            else if (ev.key == KEY_UP) // Up arrow - previous command
            {
                if (g_history_count > 0)
                {
                    // Clear current input from display
                    while (input_pos > 0)
                    {
                        terminal_backspace(&g_terminal);
                        input_pos--;
                    }

                    // Move to previous history entry
                    if (g_history_index < 0)
                    {
                        g_history_index = g_history_count - 1;
                    }
                    else if (g_history_index > 0)
                    {
                        g_history_index--;
                    }

                    // Copy history entry to input
                    strcpy(input_line, g_history[g_history_index]);
                    input_pos = strlen(input_line);

                    // Display the history entry
                    terminal_puts(&g_terminal, input_line);
                    dirty = 1;
                    window_damage_terminal_line(win, g_terminal.cursor_y);
                }
            }
            else if (ev.key == KEY_DOWN) // Down arrow - next command
            {
                if (g_history_index >= 0)
                {
                    // Clear current input from display
                    while (input_pos > 0)
                    {
                        terminal_backspace(&g_terminal);
                        input_pos--;
                    }

                    if (g_history_index < g_history_count - 1)
                    {
                        // Move to next history entry
                        g_history_index++;
                        strcpy(input_line, g_history[g_history_index]);
                        input_pos = strlen(input_line);
                        terminal_puts(&g_terminal, input_line);
                    }
                    else
                    {
                        // Past the end of history, show empty line
                        g_history_index = -1;
                        input_line[0] = '\0';
                        input_pos = 0;
                    }

                    dirty = 1;
                    window_damage_terminal_line(win, g_terminal.cursor_y);
                }
            }
            else if (c >= 32 && c < 127) // Printable character
            {
                if (input_pos < (int)sizeof(input_line) - 1)
                {
                    int previous_cursor_y_position = g_terminal.cursor_y;
                    input_line[input_pos++] = c;
                    terminal_putchar(&g_terminal, c);
                    dirty = 1;
                    window_damage_terminal_line(win, previous_cursor_y_position);

                    // Reset history browsing when user types
                    g_history_index = -1;
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
    if (g_logo_img)
    {
        tga_free(g_logo_img);
    }
    window_destroy(win);
    return 0;
}
