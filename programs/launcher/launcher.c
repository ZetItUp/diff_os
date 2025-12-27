/*
 * Launcher - Program launcher for DiffOS
 *
 * Allows the user to enter a program name or path and launch it.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <system/threads.h>
#include <diffwm/diffwm.h>
#include <diffgfx/draw.h>
#include <runtime/exec.h>
#include <system/process.h>

#define WIN_W 320
#define WIN_H 110

static bool g_running = true;
static bool g_launch_success = false;
static bool g_launch_in_progress = false;
static window_t *g_win = NULL;

static button_t btn_launch;
static label_t lbl_info;
static label_t lbl_error;
static textbox_t txt_program;
static char txt_program_buf[128];

static int try_launch_program(void)
{
    if (g_launch_in_progress || g_launch_success)
    {
        return 0;
    }

    const char *program = textbox_get_text(&txt_program);

    if (!program || !*program)
    {
        label_set_text(&lbl_error, "Please enter a program name.");
        window_paint(&g_win->base);
        return 0;
    }

    /* Initialize runtime if not already done */
    rt_init(NULL);
    g_launch_in_progress = true;

    /* Try to resolve the program */
    char resolved_path[RT_MAX_PATH];
    int rc = rt_resolve(program, resolved_path, sizeof(resolved_path), RT_RESOLVE_ALL);

    if (rc != RT_OK)
    {
        label_set_text(&lbl_error, "Program not found.");
        window_paint(&g_win->base);
        g_launch_in_progress = false;
        return 0;
    }

    /* Launch the program as a child process */
    int pid = rt_exec(resolved_path, 0, NULL, 0);

    if (pid < 0)
    {
        label_set_text(&lbl_error, "Failed to start program.");
        window_paint(&g_win->base);
        g_launch_in_progress = false;
        return 0;
    }

    /* Success - exit launcher */
    g_launch_success = true;
    g_running = false;
    if (g_win)
    {
        window_destroy(g_win);
        g_win = NULL;
    }
    // Wait for the child to exit so we don't leak a zombie if no parent waits.
    int status = 0;
    process_wait(pid, &status);
    return 1;
}

static void on_launch_click(void *user_data)
{
    (void)user_data;
    try_launch_program();
}

static void handle_key_event(const diff_event_t *ev)
{
    if (!ev->key_pressed)
        return;

    /* Enter key also launches */
    if (ev->key == '\n' || ev->key == '\r')
    {
        try_launch_program();
    }
    /* Escape key cancels */
    else if (ev->key == 0x1B)
    {
        g_running = false;
    }
}

static void handle_event(const diff_event_t *ev)
{
    switch (ev->type)
    {
        case DIFF_EVENT_KEY:
            handle_key_event(ev);
            break;

        default:
            break;
    }
}

int main(void)
{
    g_win = window_create(100, 100, WIN_W, WIN_H,
                          WINDOW_NO_MINIMIZE | WINDOW_NO_MAXIMIZE,
                          "Run Program");
    if (!g_win)
        return -1;

    /* Info label */
    label_init(&lbl_info, 10, 15, "Enter the program name or path:");

    /* Error/status label (initially empty) */
    label_init(&lbl_error, 10, 35, "");

    /* Text input */
    textbox_init(&txt_program, 10, WIN_H - 50, WIN_W - 90, 28,
                 txt_program_buf, (int)sizeof(txt_program_buf), NULL);

    /* Launch button */
    button_init(&btn_launch, WIN_W - 75, WIN_H - 50, 65, 28, "Run");
    button_set_callback(&btn_launch, on_launch_click, NULL);

    window_add_component(g_win, &lbl_info.base);
    window_add_component(g_win, &lbl_error.base);
    window_add_component(g_win, &txt_program.base);
    window_add_component(g_win, &btn_launch.base);

    window_request_focus(g_win);

    /* Initial paint */
    window_paint(&g_win->base);

    while (g_running)
    {
        diff_event_t ev;
        while (g_running && g_win && window_poll_event(g_win, &ev))
        {
            if (textbox_handle_event(&txt_program, &ev))
            {
                /* Clear error message when user types */
                if (lbl_error.text && lbl_error.text[0] != '\0')
                {
                    label_set_text(&lbl_error, "");
                }
                if (g_win)
                {
                    window_paint(&g_win->base);
                }
                continue;
            }

            if (button_handle_event(&btn_launch, &ev))
            {
                if (g_win)
                {
                    window_paint(&g_win->base);
                }
                continue;
            }

            handle_event(&ev);

            if (!g_running || !g_win)
            {
                break;
            }
        }

        thread_yield();
    }

    window_destroy(g_win);

    return g_launch_success ? 0 : 1;
}
