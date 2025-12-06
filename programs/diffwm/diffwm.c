#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syscall.h>
#include <time.h>
#include <vbe/vbe.h>
#include <video.h>
#include <system/threads.h>
#include <unistd.h>
#include <system/messaging.h>
#include <system/shared_mem.h>
#include <diffwm/protocol.h>
#include <difffonts/fonts.h>

// Diff Graphics Library
#include <diffgfx/graphics.h>
#include <diffgfx/draw.h>

/*
 * Window Manager Internal Window Tracking
 *
 * This structure is used by the window manager to track client windows.
 * It's separate from the client-side window_t which has polymorphic components.
 */
typedef struct wm_window
{
    uint32_t id;
    int handle;
    void *pixels;
    int drew_once;

    int x;
    int y;
    uint32_t width;
    uint32_t height;

    int pitch;
    int mailbox;    /* Client mailbox channel index for replies/events */
    int wm_channel; /* Channel index to talk to WM */
    struct wm_window *next;
} wm_window_t;

// List of windows managed
static wm_window_t *g_windows = NULL;
static uint32_t g_next_id = 1;
static int g_mailbox = -1;
static wm_window_t *g_focused = NULL;

// Video mode and backbuffer
static video_mode_info_t g_mode;
static uint32_t *g_backbuffer = NULL;
static uint32_t g_backbuffer_stride = 0; // pixels per line

// Dirty flag for optimized rendering
static volatile int g_needs_redraw = 0;

// Darken an ARGB pixel very slightly to simulate a subtle shadow (alpha over black).
static inline uint32_t apply_shadow_20(uint32_t c)
{
    const uint32_t alpha = 32u;           // ~12.5% black
    const uint32_t inv   = 255u - alpha;  // ~87.5% original

    uint32_t a = c & 0xFF000000u;
    uint32_t r = (c >> 16) & 0xFFu;
    uint32_t g = (c >> 8) & 0xFFu;
    uint32_t b = c & 0xFFu;

    r = (r * inv + 127u) / 255u;
    g = (g * inv + 127u) / 255u;
    b = (b * inv + 127u) / 255u;

    return a | (r << 16) | (g << 8) | b;
}

static wm_window_t* wm_find(uint32_t id)
{
    for(wm_window_t *win = g_windows; win; win = win->next)
    {
        if(win->id == id)
        {
            return win;
        }
    }

    return NULL;
}

// Send focus event to a window
static void wm_send_focus_event(wm_window_t *window, int gained)
{
    if (!window) return;

    dwm_msg_t ev_msg = {0};
    ev_msg.type = DWM_MSG_EVENT;
    ev_msg.window_id = window->id;
    ev_msg.event.type = gained ? DIFF_EVENT_FOCUS_GAINED : DIFF_EVENT_FOCUS_LOST;

    send_message(window->mailbox, &ev_msg, sizeof(ev_msg));
}

// Set focus to a specific window, sending events to old and new focused windows
static void wm_set_focus(wm_window_t *window)
{
    if (g_focused == window) return;

    // Notify old focused window it lost focus
    if (g_focused)
    {
        wm_send_focus_event(g_focused, 0);
    }

    g_focused = window;

    // Notify new focused window it gained focus
    if (g_focused)
    {
        wm_send_focus_event(g_focused, 1);
    }

    g_needs_redraw = 1;  // Redraw to update focus visual
}

static void wm_add_window(wm_window_t *window)
{
    window->next = g_windows;
    g_windows = window;

    // New windows automatically get focus, but don't send focus events yet
    // (the client hasn't received its CREATE reply, so it can't handle events)
    g_focused = window;
    g_needs_redraw = 1;
}

// Clear a region of the backbuffer to the desktop background color
static void wm_clear_region(int x, int y, int w, int h)
{
    if (!g_backbuffer) return;

    const uint32_t bg = color_rgb(69, 67, 117);

    // Clamp to screen bounds
    int x0 = (x < 0) ? 0 : x;
    int y0 = (y < 0) ? 0 : y;
    int x1 = x + w;
    int y1 = y + h;
    if (x1 > (int)g_mode.width) x1 = (int)g_mode.width;
    if (y1 > (int)g_mode.height) y1 = (int)g_mode.height;

    for (int row = y0; row < y1; row++)
    {
        uint32_t *dst = g_backbuffer + (size_t)row * g_backbuffer_stride + x0;
        for (int col = x0; col < x1; col++)
        {
            *dst++ = bg;
        }
    }
}

static void wm_remove_window(uint32_t id)
{
    wm_window_t **winp = &g_windows;

    while(*winp)
    {
        if((*winp)->id == id)
        {
            wm_window_t* window = *winp;

            // Save window bounds before freeing (include border + shadow)
            int wx = window->x - 2;  // Border is 2px
            int wy = window->y - 2;
            int ww = (int)window->width + 2 + 2 + 5 + 2;  // left border + right border + shadow + extra
            int wh = (int)window->height + 2 + 2 + 5 + 2;

            *winp = window->next;
            shared_memory_unmap(window->handle);
            shared_memory_release(window->handle);

            if (g_focused == window)
            {
                // Focus the next window in the list, if any
                g_focused = NULL;
                if (g_windows)
                {
                    wm_set_focus(g_windows);
                }
            }

            free(window);

            // Clear the region where the window was and present immediately
            wm_clear_region(wx, wy, ww, wh);
            system_video_present(g_backbuffer, (int)g_mode.pitch, (int)g_mode.width, (int)g_mode.height);

            return;
        }

        winp = &(*winp)->next;
    }
}

static int wm_create_window(const dwm_window_desc_t *desc, uint32_t *out_id)
{
    int client_channel = connect_message_channel(desc->mailbox_id);
    if(client_channel < 0)
    {
        return -1;
    }

    int map_rc = shared_memory_map(desc->handle);

    if(map_rc < 0)
    {
        return -1;
    }

    void *addr = (void*)(uintptr_t)map_rc;

    if(!addr)
    {
        return -1;
    }

    wm_window_t *window = calloc(1, sizeof(*window));

    if(!window)
    {
        shared_memory_unmap(desc->handle);
        return -1;
    }

    window->id = g_next_id++;
    window->handle = desc->handle;
    window->pixels = addr;
    window->x = desc->x;
    window->y = desc->y;
    window->width = desc->width;
    window->height = desc->height;
    window->pitch = desc->width * 4;
    window->mailbox = client_channel;
    window->wm_channel = g_mailbox;
    window->drew_once = 0;

    wm_add_window(window);
    *out_id = window->id;

    return 0;
}

static void wm_draw_window(const dwm_msg_t *msg)
{
    wm_window_t *window = wm_find(msg->window_id);

    if(!window || !g_backbuffer)
    {
        return;
    }

    int x0 = window->x;
    int y0 = window->y;
    int max_y = (y0 + window->height > g_mode.height) ? (g_mode.height - y0) : window->height;
    int max_x = (x0 + window->width > g_mode.width) ? (g_mode.width - x0) : window->width;

    if(max_x <= 0 || max_y <= 0)
    {
        return;
    }

    uint32_t *src = (uint32_t*)window->pixels;
    uint32_t src_stride = (uint32_t)(window->pitch / 4);
    uint32_t *dst = g_backbuffer + (size_t)y0 * g_backbuffer_stride + (size_t)x0;

    // Optimize: use single memcpy if possible
    size_t row_bytes = (size_t)max_x * sizeof(uint32_t);
    if(src_stride == (uint32_t)max_x && g_backbuffer_stride == (uint32_t)max_x)
    {
        memcpy(dst, src, row_bytes * max_y);
    }
    else
    {
        for(int y = 0; y < max_y; ++y)
        {
            memcpy(dst, src, row_bytes);
            src += src_stride;
            dst += g_backbuffer_stride;
        }
    }

    // Draw a simple 2px border around the window area (clipped)
    // Use different colors for focused vs unfocused windows
    const int border = 2;
    const int is_focused = (window == g_focused);
    const uint32_t border_color = is_focused ? color_rgb(100, 149, 237) : color_rgb(120, 120, 120);  // Cornflower blue for focused, gray for unfocused
    const int x1 = x0 + max_x - 1;
    const int y1 = y0 + max_y - 1;

    // Top and bottom borders
    for(int b = 0; b < border && b < max_y; ++b)
    {
        uint32_t *top = g_backbuffer + (size_t)(y0 + b) * g_backbuffer_stride + (size_t)x0;
        uint32_t *bot = g_backbuffer + (size_t)(y1 - b) * g_backbuffer_stride + (size_t)x0;
        for(int x = 0; x < max_x; ++x)
        {
            top[x] = border_color;
            bot[x] = border_color;
        }
    }

    // Left and right borders (avoid double-drawing corners excessively)
    for(int y = border; y < max_y - border; ++y)
    {
        uint32_t *row = g_backbuffer + (size_t)(y0 + y) * g_backbuffer_stride;
        for(int b = 0; b < border && b < max_x; ++b)
        {
            row[x0 + b] = border_color;
            row[x1 - b] = border_color;
        }
    }

    // Shadow on right and bottom (5px, 20% alpha black)
    const int shadow = 5;
    int shadow_x0 = x0 + max_x;
    int shadow_y0 = y0 + max_y;

    int shadow_x1 = shadow_x0 + shadow;
    int shadow_y1 = shadow_y0 + shadow;

    if (shadow_x0 < (int)g_mode.width)
    {
        int sx1 = (shadow_x1 < (int)g_mode.width) ? shadow_x1 : (int)g_mode.width;
        int sy0 = y0;
        int sy1 = y0 + max_y + shadow;
        if (sy0 < 0) sy0 = 0;
        if (sy1 > (int)g_mode.height) sy1 = (int)g_mode.height;

        for (int y = sy0; y < sy1; ++y)
        {
            uint32_t *row = g_backbuffer + (size_t)y * g_backbuffer_stride;
            int y_off = y - y0;
            for (int x = shadow_x0; x < sx1; ++x)
            {
                // Bevel top of right shadow so inner edge meets the corner and fans outward.
                if (y_off < shadow)
                {
                    int max_w = y_off + 1; // start with 1px at the top, grow downward
                    if (x >= shadow_x0 + max_w) continue;
                }
                row[x] = apply_shadow_20(row[x]);
            }
        }
    }

    if (shadow_y0 < (int)g_mode.height)
    {
        int sy1 = (shadow_y1 < (int)g_mode.height) ? shadow_y1 : (int)g_mode.height;
        int sx0 = x0;
        int sx1 = x0 + max_x + shadow;
        if (sx0 < 0) sx0 = 0;
        if (sx1 > (int)g_mode.width) sx1 = (int)g_mode.width;

        for (int y = shadow_y0; y < sy1; ++y)
        {
            uint32_t *row = g_backbuffer + (size_t)y * g_backbuffer_stride;
            int y_off = y - shadow_y0;
            for (int x = sx0; x < sx1; ++x)
            {
                // Bevel bottom shadow near left: inner edge touches corner, height grows to the right.
                int x_off = x - x0;
                if (x_off < shadow)
                {
                    int max_h = x_off + 1; // start with 1px height at left corner
                    if (y_off >= max_h) continue;
                }
                row[x] = apply_shadow_20(row[x]);
            }
        }
    }
}

static void wm_handle_message(const dwm_msg_t *msg)
{
    switch(msg->type)
    {
        case DWM_MSG_CREATE_WINDOW:
            {
                dwm_msg_t *reply = calloc(1, sizeof(*reply));
                if (!reply)
                {
                    break;
                }

                reply->type = DWM_MSG_CREATE_WINDOW;
                reply->create.id = 0;

                if(wm_create_window(&msg->create, &reply->create.id) != 0)
                {
                    reply->create.id = 0;
                }

                int client_channel = connect_message_channel(msg->create.mailbox_id);
                if(client_channel < 0)
                {
                    client_channel = g_mailbox;
                }

                send_message(client_channel, reply, sizeof(*reply));
                free(reply);

                break;
            }
        case DWM_MSG_DESTROY_WINDOW:
            {
                wm_remove_window(msg->window_id);
                break;
            }
        case DWM_MSG_DRAW:
            {
                wm_draw_window(msg);
                g_needs_redraw = 1;  // Mark as dirty for batched rendering
                break;
            }
        case DWM_MSG_EVENT:
            {
                // Events are sent from WM to clients, not the other way
                break;
            }
        case DWM_MSG_REQUEST_FOCUS:
            {
                wm_window_t *window = wm_find(msg->window_id);
                if (window)
                {
                    wm_set_focus(window);
                }
                break;
            }
        default:
            break;
    }
}

static void wm_dispatch_key_events(void)
{
    system_key_event_t kev;

    while (system_keyboard_event_try(&kev))
    {
        if (!g_focused)
        {
            continue;
        }

        dwm_msg_t ev_msg = {0};
        ev_msg.type = DWM_MSG_EVENT;
        ev_msg.window_id = g_focused->id;
        ev_msg.event.type = DIFF_EVENT_KEY;
        ev_msg.event.key = kev.key;
        ev_msg.event.key_pressed = kev.pressed;

        send_message(g_focused->mailbox, &ev_msg, sizeof(ev_msg));
    }
}

int main(void)
{
    vbe_toggle_graphics_mode();
    system_console_disable();

    if(system_video_mode_get(&g_mode) < 0)
    {
        return -1;
    }

    g_backbuffer_stride = (uint32_t)(g_mode.pitch / 4);
    if (g_backbuffer_stride < g_mode.width) g_backbuffer_stride = g_mode.width;
    g_backbuffer = calloc((size_t)g_backbuffer_stride * g_mode.height, sizeof(uint32_t));

    if(!g_backbuffer)
    {
        return -2;
    }


    g_mailbox = create_message_channel(DWM_MAILBOX_ID);

    if(g_mailbox < 0)
    {
        return -3;
    }

    /* Fill background to a known color before any client draws */
    const uint32_t bg = color_rgb(69, 67, 117);
    size_t total = (size_t)g_backbuffer_stride * g_mode.height;
    for (size_t i = 0; i < total; ++i)
    {
        g_backbuffer[i] = bg;
    }

    system_video_present(g_backbuffer, (int)g_mode.pitch, (int)g_mode.width, (int)g_mode.height);

    const char *client_path = "/programs/gdterm/gdterm.dex";
    spawn_process(client_path, 0, NULL);

    dwm_msg_t *msg = (dwm_msg_t *)malloc(sizeof(dwm_msg_t));
    if (!msg)
    {
        return -4;
    }

    // Message handling loop with batched rendering
    int msg_count = 0;
    for(;;)
    {
        int handled = 0;

        // Drain any pending messages quickly
        while (system_message_try_receive(g_mailbox, msg, sizeof(*msg)) > 0)
        {
            wm_handle_message(msg);
            msg_count++;
            handled = 1;

            // Batch renders: only update screen every 4 messages or when explicitly needed
            if (g_needs_redraw && (msg_count >= 4 || msg->type == DWM_MSG_DRAW))
            {
                system_video_present(g_backbuffer, (int)g_mode.pitch, (int)g_mode.width, (int)g_mode.height);
                g_needs_redraw = 0;
                msg_count = 0;
            }
        }

        // No more messages - flush any pending redraw
        if (g_needs_redraw)
        {
            system_video_present(g_backbuffer, (int)g_mode.pitch, (int)g_mode.width, (int)g_mode.height);
            g_needs_redraw = 0;
            msg_count = 0;
            handled = 1;
        }

        // Deliver keyboard events to the currently focused window only
        wm_dispatch_key_events();

        if (!handled)
        {
            thread_sleep_ms(1); // avoid tight polling when idle
        }
    }

    free(g_backbuffer);
    free(msg);

    return 0;
}
