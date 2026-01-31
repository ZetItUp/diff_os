#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <system/threads.h>
#include <syscall.h>
#include <diffwm/diffwm.h>
#include <difffonts/fonts.h>
#include <diffdex/diffdex.h>
#include <runtime/process.h>

#define WINDOW_WIDTH 340
#define WINDOW_HEIGHT 160
#define UPDATE_INTERVAL_MILLISECONDS 250
#define MAX_PROCESS_ENTRIES 128

static bool g_running = true;
static terminal_component_t g_terminal;

static const char *process_state_name(int state)
{
    switch (state)
    {
        case 0:
            return "CREATED";
        case 1:
            return "READY";
        case 2:
            return "RUNNING";
        case 3:
            return "ZOMBIE";
        case 4:
            return "DEAD";
        default:
            return "UNKNOWN";
    }
}

static void terminal_write_line(terminal_component_t *terminal, const char *text)
{
    terminal_puts(terminal, text);
    terminal_putchar(terminal, '\n');
}

static void refresh_process_list(void)
{
    process_list_entry_t entries[MAX_PROCESS_ENTRIES];
    int process_count = rt_process_list(entries, MAX_PROCESS_ENTRIES);

    terminal_clear(&g_terminal);
    terminal_write_line(&g_terminal, "PID   STATE    OPEN_FD   NAME");

    if (process_count < 0)
    {
        terminal_write_line(&g_terminal, "process list failed");

        return;
    }

    for (int index = 0; index < process_count; ++index)
    {
        char name_buffer[64];
        name_buffer[0] = '\0';

        if (rt_process_get_name(entries[index].pid, name_buffer, sizeof(name_buffer)) < 0)
        {
            (void)snprintf(name_buffer, sizeof(name_buffer), "unknown");
        }

        char line_buffer[128];
        (void)snprintf(line_buffer,
                       sizeof(line_buffer),
                       "%-5d %-7s %-9d %s",
                       entries[index].pid,
                       process_state_name(entries[index].state),
                       entries[index].open_file_descriptor_count,
                       name_buffer);
        terminal_write_line(&g_terminal, line_buffer);
    }
}

static void handle_key_event(const diff_event_t *event)
{
    if (!event->key_pressed)
    {
        return;
    }

    if (event->key == 'q' || event->key == 'Q')
    {
        g_running = false;
    }
}

static void handle_event(const diff_event_t *event)
{
    switch (event->type)
    {
        case DIFF_EVENT_KEY:
            handle_key_event(event);
            break;
        default:
            break;
    }
}

int main(void)
{
    char *window_title = diffdex_get_window_title("/programs/procinfo/procinfo.dex");
    if (!window_title)
    {
        window_title = diffdex_get_application_title("/programs/procinfo/procinfo.dex");
    }

    const char *window_title_text = window_title ? window_title : "Process(s) Information";
    window_t *window = window_create(80, 80, WINDOW_WIDTH, WINDOW_HEIGHT, 0, window_title_text);
    if (!window)
    {
        if (window_title)
        {
            free(window_title);
        }

        return -1;
    }

    font_t *font = font_load_bdf("/system/fonts/spleen-6x12.bdf");
    if (!font)
    {
        window_destroy(window);

        return -1;
    }

    terminal_component_init(&g_terminal, 0, 0, WINDOW_WIDTH, WINDOW_HEIGHT, font);
    window_add_component(window, &g_terminal.base);
    window_request_focus(window);

    refresh_process_list();
    window_paint(&window->base);

    uint64_t last_update_milliseconds = 0;

    while (g_running)
    {
        diff_event_t event;
        while (window_poll_event(window, &event))
        {
            handle_event(&event);
        }

        uint64_t now_milliseconds = system_time_ms();
        if (now_milliseconds - last_update_milliseconds >= UPDATE_INTERVAL_MILLISECONDS)
        {
            refresh_process_list();
            window_mark_dirty(window);
            window_paint(&window->base);
            last_update_milliseconds = now_milliseconds;
        }

        thread_yield();
    }

    font_destroy(font);
    window_destroy(window);

    if (window_title)
    {
        free(window_title);
    }

    return 0;
}
