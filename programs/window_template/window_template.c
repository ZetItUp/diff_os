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

#define WIN_W 400
#define WIN_H 300

static bool g_running = true;

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
    window_t *win = window_create(100, 100, WIN_W, WIN_H, 0, "Window1");
    if (!win)
        return -1;

    window_request_focus(win);

    // Initial paint
    window_paint(&win->base);

    while (g_running)
    {
        diff_event_t ev;
        while (window_poll_event(win, &ev))
        {
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
