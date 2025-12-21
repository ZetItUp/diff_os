#include "event.h"
#include "wm_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syscall.h>
#include <time.h>
#include <system/messaging.h>
#include <difffonts/fonts.h>

// External font for titlebar hit testing
extern font_t *g_title_font;

// Screen dimensions (set via event context)
static int g_screen_width = 0;
static int g_screen_height = 0;

void event_init(event_context_t *ctx)
{
    if (!ctx) return;

    g_screen_width = ctx->screen_width;
    g_screen_height = ctx->screen_height;

    if (ctx->mouse)
    {
        ctx->mouse->x = 0;
        ctx->mouse->y = 0;
        ctx->mouse->prev_x = -1;
        ctx->mouse->prev_y = -1;
        ctx->mouse->buttons_down = 0;
        ctx->mouse->prev_buttons_down = 0;
        ctx->mouse->capture = NULL;
        ctx->mouse->drag_window = NULL;
        ctx->mouse->drag_offset_x = 0;
        ctx->mouse->drag_offset_y = 0;
    }

    if (ctx->clicks)
    {
        memset(ctx->clicks, 0, sizeof(click_state_t));
    }
}

int event_button_index(uint8_t button)
{
    if (button == MOUSE_BTN_LEFT) return 0;
    if (button == MOUSE_BTN_RIGHT) return 1;
    if (button == MOUSE_BTN_MIDDLE) return 2;
    return -1;
}

wm_window_t *event_find_window_at(event_context_t *ctx, int x, int y)
{
    if (!ctx) return NULL;

    // Iterate windows front-to-back (g_windows is ordered front first)
    // First window that contains the point wins - no propagation to windows behind
    for (wm_window_t *win = ctx->windows; win; win = win->next)
    {
        int wx, wy, ww, wh;
        wm_get_decor_bounds(win, &wx, &wy, &ww, &wh);

        if (x >= wx && x < wx + ww && y >= wy && y < wy + wh)
        {
            return win;  // Found topmost window at this point
        }
    }

    return NULL;
}

int event_point_in_titlebar(wm_window_t *win, int x, int y)
{
    if (!win || !g_title_font)
    {
        return 0;
    }

    int fw = font_width(g_title_font);
    int fh = font_height(g_title_font);
    int title_w = (int)strlen(win->title) * fw + TITLE_PADDING_X;
    int title_h = fh + TITLE_PADDING_Y;
    int title_x = win->x;

    if (title_x + title_w > g_screen_width)
    {
        title_x = g_screen_width - title_w;
        if (title_x < 0) title_x = 0;
    }

    int title_y = win->y - title_h;
    if (title_y < 0) title_y = 0;

    return (x >= title_x && x < title_x + title_w &&
            y >= title_y && y < title_y + title_h);
}

void event_send_mouse(wm_window_t *window, int x, int y,
                      uint8_t buttons, uint8_t action, uint8_t button)
{
    if (!window) return;

    // Convert to window-local coordinates
    int rel_x = x - window->x;
    int rel_y = y - window->y;

    // Clamp to int16_t range
    if (rel_x < -32768) rel_x = -32768;
    if (rel_x > 32767) rel_x = 32767;
    if (rel_y < -32768) rel_y = -32768;
    if (rel_y > 32767) rel_y = 32767;

    dwm_msg_t ev_msg = {0};
    ev_msg.type = DWM_MSG_EVENT;
    ev_msg.window_id = window->id;
    ev_msg.event.type = DIFF_EVENT_MOUSE;
    ev_msg.event.mouse_x = (int16_t)rel_x;
    ev_msg.event.mouse_y = (int16_t)rel_y;
    ev_msg.event.mouse_buttons = buttons;
    ev_msg.event.mouse_action = action;
    ev_msg.event.mouse_button = button;

    send_message(window->mailbox, &ev_msg, sizeof(ev_msg));
}

void event_send_key(wm_window_t *window, uint8_t key, int pressed, uint8_t modifiers)
{
    if (!window) return;

    dwm_msg_t ev_msg = {0};
    ev_msg.type = DWM_MSG_EVENT;
    ev_msg.window_id = window->id;
    ev_msg.event.type = DIFF_EVENT_KEY;
    ev_msg.event.key = key;
    ev_msg.event.key_pressed = pressed;
    ev_msg.event.modifiers = modifiers;

    send_message(window->mailbox, &ev_msg, sizeof(ev_msg));
}

void event_send_focus(wm_window_t *window, int gained)
{
    if (!window) return;

    dwm_msg_t ev_msg = {0};
    ev_msg.type = DWM_MSG_EVENT;
    ev_msg.window_id = window->id;
    ev_msg.event.type = gained ? DIFF_EVENT_FOCUS_GAINED : DIFF_EVENT_FOCUS_LOST;

    send_message(window->mailbox, &ev_msg, sizeof(ev_msg));
}

// Handle button press for a specific button
// Returns EVENT_CONSUMED if handled
static int handle_button_press(event_context_t *ctx, wm_window_t *target, uint8_t button)
{
    if (!target) return EVENT_IGNORED;

    mouse_state_t *m = ctx->mouse;

    // Send down event to target
    event_send_mouse(target, m->x, m->y, m->buttons_down, MOUSE_ACTION_DOWN, button);

    return EVENT_CONSUMED;
}

// Handle button release for a specific button
// Returns EVENT_CONSUMED if handled
static int handle_button_release(event_context_t *ctx, wm_window_t *target, uint8_t button)
{
    if (!target) return EVENT_IGNORED;

    mouse_state_t *m = ctx->mouse;
    click_state_t *c = ctx->clicks;

    // Send up event
    event_send_mouse(target, m->x, m->y, m->buttons_down, MOUSE_ACTION_UP, button);

    // Send click event
    event_send_mouse(target, m->x, m->y, m->buttons_down, MOUSE_ACTION_CLICK, button);

    // Check for double-click
    int idx = event_button_index(button);
    if (idx >= 0 && c)
    {
        uint64_t now = monotonic_ms();

        if (now - c->last_click_ms[idx] <= DWM_DBLCLICK_MS &&
            c->last_click_window_id[idx] == target->id &&
            abs(m->x - c->last_click_x[idx]) <= DWM_DBLCLICK_DIST &&
            abs(m->y - c->last_click_y[idx]) <= DWM_DBLCLICK_DIST)
        {
            event_send_mouse(target, m->x, m->y, m->buttons_down, MOUSE_ACTION_DBLCLICK, button);
        }

        // Update last click state
        c->last_click_ms[idx] = now;
        c->last_click_x[idx] = m->x;
        c->last_click_y[idx] = m->y;
        c->last_click_window_id[idx] = target->id;
    }

    return EVENT_CONSUMED;
}

int event_process_mouse(event_context_t *ctx, int mouse_moved)
{
    if (!ctx || !ctx->mouse) return EVENT_IGNORED;

    mouse_state_t *m = ctx->mouse;
    int consumed = EVENT_IGNORED;

    // Refresh button state independently of movement so press/release works while stationary
    uint8_t current = system_mouse_get_buttons_down();
    uint8_t pressed = (uint8_t)(current & (uint8_t)~m->prev_buttons_down);
    uint8_t released = (uint8_t)(m->prev_buttons_down & (uint8_t)~current);
    m->buttons_down = current;

    // No events to process
    if (!mouse_moved && pressed == 0 && released == 0)
    {
        m->prev_buttons_down = m->buttons_down;
        return EVENT_IGNORED;
    }

    // Find which window the mouse is over (topmost only - no click-through!)
    wm_window_t *hover = event_find_window_at(ctx, m->x, m->y);

    // Target is either the captured window (for drag operations) or the hover window
    // Mouse capture ensures all events go to the window that received the initial press
    wm_window_t *target = m->capture ? m->capture : hover;

    // Handle mouse movement
    if (mouse_moved)
    {
        // Handle window dragging
        if (m->drag_window)
        {
            int new_x = m->x - m->drag_offset_x;
            int new_y = m->y - m->drag_offset_y;

            // Clamp to screen bounds
            if (new_x < 0) new_x = 0;
            if (new_y < 0) new_y = 0;
            if (new_x >= g_screen_width) new_x = g_screen_width - 1;
            if (new_y >= g_screen_height) new_y = g_screen_height - 1;

            if (new_x != m->drag_window->x || new_y != m->drag_window->y)
            {
                // Clear old position
                int old_x, old_y, old_w, old_h;
                wm_get_decor_bounds(m->drag_window, &old_x, &old_y, &old_w, &old_h);
                wm_clear_region(old_x, old_y, old_w, old_h);

                // Update position
                m->drag_window->x = new_x;
                m->drag_window->y = new_y;

                // Mark new position dirty
                int new_dx, new_dy, new_dw, new_dh;
                wm_get_decor_bounds(m->drag_window, &new_dx, &new_dy, &new_dw, &new_dh);
                wm_add_dirty_rect(new_dx, new_dy, new_dw, new_dh);
                wm_mark_needs_redraw();

                consumed = EVENT_CONSUMED;
            }
        }

        // Send move event to target window
        if (target)
        {
            event_send_mouse(target, m->x, m->y, m->buttons_down, MOUSE_ACTION_MOVE, 0);
            consumed = EVENT_CONSUMED;
        }
    }

    // Handle button presses
    if (pressed)
    {
        // Set mouse capture on first button press
        // This ensures all subsequent events go to the same window until release
        if (!m->capture)
        {
            m->capture = target;
        }

        // Focus the clicked window
        if (target && ctx->focused != target)
        {
            wm_set_focus(target);
        }

        // Start drag if clicking on titlebar
        if (target && (pressed & MOUSE_BTN_LEFT) &&
            event_point_in_titlebar(target, m->x, m->y))
        {
            m->drag_window = target;
            m->drag_offset_x = m->x - target->x;
            m->drag_offset_y = m->y - target->y;
        }

        // Send button press events
        if (pressed & MOUSE_BTN_LEFT)
        {
            if (handle_button_press(ctx, target, MOUSE_BTN_LEFT) == EVENT_CONSUMED)
                consumed = EVENT_CONSUMED;
        }
        if (pressed & MOUSE_BTN_RIGHT)
        {
            if (handle_button_press(ctx, target, MOUSE_BTN_RIGHT) == EVENT_CONSUMED)
                consumed = EVENT_CONSUMED;
        }
        if (pressed & MOUSE_BTN_MIDDLE)
        {
            if (handle_button_press(ctx, target, MOUSE_BTN_MIDDLE) == EVENT_CONSUMED)
                consumed = EVENT_CONSUMED;
        }
    }

    // Handle button releases
    if (released)
    {
        if (released & MOUSE_BTN_LEFT)
        {
            if (handle_button_release(ctx, target, MOUSE_BTN_LEFT) == EVENT_CONSUMED)
                consumed = EVENT_CONSUMED;
            if (!target)
            {
                click_state_t *c = ctx->clicks;
                int idx = event_button_index(MOUSE_BTN_LEFT);
                if (idx >= 0 && c)
                {
                    uint64_t now = monotonic_ms();
                    int is_dbl = (now - c->last_click_ms[idx] <= DWM_DBLCLICK_MS &&
                                  c->last_click_window_id[idx] == 0 &&
                                  abs(m->x - c->last_click_x[idx]) <= DWM_DBLCLICK_DIST &&
                                  abs(m->y - c->last_click_y[idx]) <= DWM_DBLCLICK_DIST);

                    c->last_click_ms[idx] = now;
                    c->last_click_x[idx] = m->x;
                    c->last_click_y[idx] = m->y;
                    c->last_click_window_id[idx] = 0;

                    if (is_dbl && wm_desktop_handle_click(m->x, m->y))
                    {
                        consumed = EVENT_CONSUMED;
                    }
                }
            }
        }
        if (released & MOUSE_BTN_RIGHT)
        {
            if (handle_button_release(ctx, target, MOUSE_BTN_RIGHT) == EVENT_CONSUMED)
                consumed = EVENT_CONSUMED;
        }
        if (released & MOUSE_BTN_MIDDLE)
        {
            if (handle_button_release(ctx, target, MOUSE_BTN_MIDDLE) == EVENT_CONSUMED)
                consumed = EVENT_CONSUMED;
        }

        // Release capture and drag when all buttons are up
        if (m->buttons_down == 0)
        {
            m->capture = NULL;
            m->drag_window = NULL;
        }
    }

    m->prev_buttons_down = m->buttons_down;
    return consumed;
}

int event_process_keyboard(event_context_t *ctx)
{
    if (!ctx) return EVENT_IGNORED;

    int consumed = EVENT_IGNORED;
    system_key_event_t kev;

    while (system_keyboard_event_try(&kev))
    {
        if (!ctx->focused && ctx->windows)
        {
            wm_set_focus(ctx->windows);
            ctx->focused = wm_get_focused();
        }

        // Keyboard events always go to focused window
        if (ctx->focused)
        {
            event_send_key(ctx->focused, kev.key, kev.pressed, kev.modifiers);
            consumed = EVENT_CONSUMED;
        }
    }

    return consumed;
}
