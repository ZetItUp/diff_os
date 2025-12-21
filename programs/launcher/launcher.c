/*
 * Window Template
 *
 * A minimal template for creating GUI window programs.
 * Copy this folder and rename to create a new window-based application.
 */

#include <stdint.h>
#include <stdbool.h>
#include <system/threads.h>
#include <diffwm/diffwm.h>
#include <diffgfx/draw.h>

#define WIN_W 300
#define WIN_H 100

static bool g_running = true;

static button_t btn_ok;
static label_t lbl_info;
static textbox_t txt_program;
static char txt_program_buf[128];

static void on_click(void *user_data)
{
    (void)user_data;
    g_running = false;
}

static void handle_key_event(const diff_event_t *ev)
{
    if (!ev->key_pressed)
        return;

    // Handle key press
    // ev->key contains the key code
    // ev->modifiers contains DIFF_MOD_SHIFT, DIFF_MOD_CTRL, etc.

    (void)ev;
}

static void handle_mouse_event(const diff_event_t *ev)
{
    // ev->mouse_x, ev->mouse_y - cursor position (window-relative)
    // ev->mouse_action - MOUSE_ACTION_MOVE, MOUSE_ACTION_DOWN, MOUSE_ACTION_UP, MOUSE_ACTION_CLICK
    // ev->mouse_button - MOUSE_BTN_LEFT, MOUSE_BTN_RIGHT, MOUSE_BTN_MIDDLE

    (void)ev;
}

static void handle_event(const diff_event_t *ev)
{
    switch (ev->type)
    {
        case DIFF_EVENT_KEY:
            handle_key_event(ev);
            break;

        case DIFF_EVENT_MOUSE:
            handle_mouse_event(ev);
            break;

        case DIFF_EVENT_FOCUS_GAINED:
            // Window gained focus
            break;

        case DIFF_EVENT_FOCUS_LOST:
            // Window lost focus
            break;

        default:
            break;
    }
}

int main(void)
{
    window_t *win = window_create(100, 100, WIN_W, WIN_H, 0, "Launcher");
    if (!win)
        return -1;

    label_init(&lbl_info, 10, 20, "Enter the program name or full path to run\nthe program.");

    button_init(&btn_ok, WIN_W - 75, WIN_H - 45, 70, 30, "Launch");
    button_set_callback(&btn_ok, on_click, NULL);

    textbox_init(&txt_program, 10, WIN_H - 45, WIN_W - 95, 30,
                 txt_program_buf, (int)sizeof(txt_program_buf), NULL);

    window_add_component(win, &lbl_info.base);
    window_add_component(win, &txt_program.base);
    window_add_component(win, &btn_ok.base);

    window_request_focus(win);

    // Initial paint
    window_paint(&win->base);

    while (g_running)
    {
        diff_event_t ev;
        while (window_poll_event(win, &ev))
        {
            if (textbox_handle_event(&txt_program, &ev))
            {
                window_paint(&win->base);
                continue;
            }

            if(button_handle_event(&btn_ok, &ev))
            {
                window_paint(&win->base);
                continue;
            }

            handle_event(&ev);
        }

        // Repaint if needed
        // window_paint(&win->base);

        // Yield to other processes
        thread_yield();
    }

    window_destroy(win);
    return 0;
}
