#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syscall.h>
#include <time.h>
#include <vbe/vbe.h>
#include <video.h>
#include <system/threads.h>
#include <system/process.h>
#include <unistd.h>
#include <system/messaging.h>
#include <system/shared_mem.h>
#include <diffwm/protocol.h>
#include <difffonts/fonts.h>

// Diff Graphics Library
#include <diffgfx/graphics.h>
#include <diffgfx/draw.h>

// DiffTGA for loading TGA images
#include <difftga.h>

// Theme system for cursors
#include "theme.h"
#include "theme.c"

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
    char title[64];

    int x;
    int y;
    uint32_t width;
    uint32_t height;

    int pitch;
    int mailbox;    /* Client mailbox channel index for replies/events */
    int wm_channel; /* Channel index to talk to WM */
    struct wm_window *next;
} wm_window_t;

// Resource parsing (matches rsbuild.py output)
#define RS_MAGIC      0x53525845u /* 'EXRS' */
#define RS_VERSION    1
#define RS_TYPE_STRING 1
#define RS_TYPE_U32    2
#define RS_TYPE_BLOB   3

typedef struct __attribute__((packed)) rs_header
{
    uint32_t magic;
    uint32_t version;
    uint32_t entry_count;
    uint32_t strtab_off;
    uint32_t strtab_size;
    uint32_t data_off;
} rs_header_t;

typedef struct __attribute__((packed)) rs_entry
{
    uint32_t name_hash;
    uint32_t type;
    uint32_t name_off;
    uint32_t data_off;
    uint32_t data_size;
} rs_entry_t;

// List of windows managed
static wm_window_t *g_windows = NULL;
static uint32_t g_next_id = 1;
static int g_mailbox = -1;
static wm_window_t *g_focused = NULL;
static void wm_draw_window(const dwm_msg_t *msg);
static void wm_apply_window_resources(wm_window_t *window, int client_mailbox_channel);
static void wm_draw_cursor(void);
static int wm_update_mouse(void);
static void wm_dispatch_mouse_events(int moved);
static void wm_get_decor_bounds(const wm_window_t *win, int *x, int *y, int *w, int *h);
static wm_window_t *wm_find_window_at(int x, int y);

// Video mode and backbuffer
static video_mode_info_t g_mode;
static uint32_t *g_buffers[2] = { NULL, NULL };
static int g_active_fb = 0;
static uint32_t *g_backbuffer = NULL;
static uint32_t g_backbuffer_stride = 0; // pixels per line
static size_t g_backbuffer_bytes = 0;
static wm_window_t *g_prev_focus = NULL;
static volatile int g_focus_dirty = 0;
static uint64_t g_last_present_ms = 0;

// Cursor theme and state
static cursor_theme_t g_cursor_theme;
static cursor_type_t g_current_cursor = CURSOR_NORMAL;
static int g_mouse_x = 0;
static int g_mouse_y = 0;
static int g_prev_mouse_x = -1;
static int g_prev_mouse_y = -1;
static wm_window_t *g_mouse_capture = NULL;
static uint8_t g_mouse_buttons_down = 0;
static uint64_t g_last_click_ms[3] = {0, 0, 0};
static int g_last_click_x[3] = {0, 0, 0};
static int g_last_click_y[3] = {0, 0, 0};
static uint32_t g_last_click_window_id[3] = {0, 0, 0};
static wm_window_t *g_drag_window = NULL;
static int g_drag_offset_x = 0;
static int g_drag_offset_y = 0;

// Window skin and title font
static tga_image_t *g_window_skin = NULL;
static font_t *g_title_font = NULL;

// Tint colors for active/inactive windows (ARGB format)
#define TITLE_TINT_ACTIVE   color_rgb(42, 112, 255)  // Cornflower blue
#define TITLE_TINT_INACTIVE color_rgb(63, 63, 116)  // Gray
#define BODY_TINT_ACTIVE    0xFF4A4A8A  // Dark blue-purple
#define BODY_TINT_INACTIVE  color_rgb(63, 63, 116)  // Dark gray

#define TITLE_PADDING_X 8
#define TITLE_PADDING_Y 6

#define DWM_DBLCLICK_MS    300
#define DWM_DBLCLICK_DIST  4

// Dirty rectangle tracking
#define MAX_DIRTY_RECTS 16
typedef struct {
    int x, y, w, h;
} dirty_rect_t;

static dirty_rect_t g_dirty_rects[MAX_DIRTY_RECTS];
static int g_dirty_count = 0;
static volatile int g_needs_redraw = 0;
static void wm_redraw_focus_dirty(void);
static int g_disable_dirty_mark = 0;

// Resource helpers
static uint32_t rs_fnv1a(const char *s)
{
    uint32_t h = 0x811C9DC5u;
    if (!s) return h;
    while (*s)
    {
        h ^= (uint8_t)(*s++);
        h *= 0x01000193u;
    }
    return h;
}

static const rs_entry_t *rs_find_entry(const rs_header_t *hdr, const uint8_t *blob, const char *key)
{
    if (!hdr || !blob || !key) return NULL;
    uint32_t hash = rs_fnv1a(key);
    const uint8_t *table = (const uint8_t *)hdr + sizeof(rs_header_t);
    for (uint32_t i = 0; i < hdr->entry_count; ++i)
    {
        const rs_entry_t *e = (const rs_entry_t *)(table + i * sizeof(rs_entry_t));
        if (e->name_hash == hash)
        {
            return e;
        }
    }
    return NULL;
}

static char *rs_get_string(const uint8_t *blob, size_t sz, const char *key)
{
    if (!blob || sz < sizeof(rs_header_t)) return NULL;
    const rs_header_t *hdr = (const rs_header_t *)blob;
    if (hdr->magic != RS_MAGIC || hdr->version != RS_VERSION)
    {
        return NULL;
    }
    const rs_entry_t *e = rs_find_entry(hdr, blob, key);
    if (!e || e->type != RS_TYPE_STRING) return NULL;
    if (e->data_off + e->data_size > sz) return NULL;
    size_t len = e->data_size;
    char *s = malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, blob + e->data_off, len);
    s[len] = '\0';

    // Strip surrounding quotes if present
    if (len >= 2 && s[0] == '\"' && s[len - 1] == '\"')
    {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }

    return s;
}

static uint8_t *wm_fetch_process_resources(int pid, uint32_t *out_sz)
{
    if (out_sz) *out_sz = 0;
    int needed = process_get_resources(pid, NULL, 0);
    if (needed <= 0 || needed > (1 << 20))
    {
        return NULL;
    }
    uint8_t *buf = malloc((size_t)needed);
    if (!buf)
    {
        return NULL;
    }
    int got = process_get_resources(pid, buf, (uint32_t)needed);
    if (got != needed)
    {
        free(buf);
        return NULL;
    }
    if (out_sz) *out_sz = (uint32_t)needed;
    return buf;
}

static void wm_apply_window_resources(wm_window_t *window, int client_mailbox_channel)
{
    if (!window) return;

    // Get the owner PID of the client mailbox
    int owner_pid = message_channel_owner(client_mailbox_channel);
    if (owner_pid <= 0) return;

    uint32_t rsz = 0;
    uint8_t *rblob = wm_fetch_process_resources(owner_pid, &rsz);
    if (!rblob) return;

    // Try to get WINDOW_TITLE first, then APPLICATION_TITLE
    char *title = rs_get_string(rblob, rsz, "WINDOW_TITLE");
    if (!title)
    {
        title = rs_get_string(rblob, rsz, "APPLICATION_TITLE");
    }

    if (title)
    {
        strncpy(window->title, title, sizeof(window->title) - 1);
        window->title[sizeof(window->title) - 1] = '\0';
        free(title);
    }
    else
    {
        strncpy(window->title, "Window", sizeof(window->title) - 1);
    }

    free(rblob);
}

// Blend helper: tint a color
static inline uint32_t blend_tint(uint32_t base, uint32_t tint)
{
    uint32_t br = (base >> 16) & 0xFF;
    uint32_t bg = (base >> 8) & 0xFF;
    uint32_t bb = base & 0xFF;

    uint32_t tr = (tint >> 16) & 0xFF;
    uint32_t tg = (tint >> 8) & 0xFF;
    uint32_t tb = tint & 0xFF;

    // Multiply blend
    uint32_t r = (br * tr) / 255;
    uint32_t g = (bg * tg) / 255;
    uint32_t b = (bb * tb) / 255;

    return 0xFF000000 | (r << 16) | (g << 8) | b;
}

// Blend a skin pixel with alpha over background, then apply tint
static inline uint32_t blend_skin_px(uint32_t bg, uint32_t skin, uint32_t tint)
{
    uint32_t alpha = (skin >> 24) & 0xFF;
    if (alpha == 0) return bg;

    // Extract skin RGB
    uint32_t sr = (skin >> 16) & 0xFF;
    uint32_t sg = (skin >> 8) & 0xFF;
    uint32_t sb = skin & 0xFF;

    // Apply tint to skin
    uint32_t tr = (tint >> 16) & 0xFF;
    uint32_t tg = (tint >> 8) & 0xFF;
    uint32_t tb = tint & 0xFF;
    sr = (sr * tr) / 255;
    sg = (sg * tg) / 255;
    sb = (sb * tb) / 255;

    if (alpha == 0xFF)
    {
        return 0xFF000000 | (sr << 16) | (sg << 8) | sb;
    }

    // Alpha blend over background
    uint32_t inv = 255 - alpha;
    uint32_t br = (bg >> 16) & 0xFF;
    uint32_t bgc = (bg >> 8) & 0xFF;
    uint32_t bb = bg & 0xFF;

    uint32_t r = (sr * alpha + br * inv) / 255;
    uint32_t g = (sg * alpha + bgc * inv) / 255;
    uint32_t b = (sb * alpha + bb * inv) / 255;

    return 0xFF000000 | (r << 16) | (g << 8) | b;
}

// Compute bounding box of a window including borders and titlebar
static void wm_get_decor_bounds(const wm_window_t *win, int *x, int *y, int *w, int *h)
{
    if (!win || !x || !y || !w || !h) return;

    const int border = 2;

    int min_x = win->x - border;
    int min_y = win->y - border;
    int max_x = win->x + (int)win->width + border;
    int max_y = win->y + (int)win->height + border;

    if (g_window_skin && g_window_skin->pixels && g_title_font)
    {
        int fw = font_width(g_title_font);
        int fh = font_height(g_title_font);
        int title_w = (int)strlen(win->title) * fw + TITLE_PADDING_X;
        int title_h = fh + TITLE_PADDING_Y;
        int title_x = win->x;
        if (title_x + title_w > (int)g_mode.width)
        {
            title_x = (int)g_mode.width - title_w;
            if (title_x < 0) title_x = 0;
        }
        int title_y = win->y - title_h;
        if (title_y < 0) title_y = 0;

        if (title_x < min_x) min_x = title_x;
        if (title_y < min_y) min_y = title_y;
        if (title_x + title_w > max_x) max_x = title_x + title_w;
        if (title_y + title_h > max_y) max_y = title_y + title_h;
    }

    *x = min_x;
    *y = min_y;
    *w = max_x - min_x;
    *h = max_y - min_y;
}

static wm_window_t *wm_find_window_at(int x, int y)
{
    for (wm_window_t *win = g_windows; win; win = win->next)
    {
        int wx, wy, ww, wh;
        wm_get_decor_bounds(win, &wx, &wy, &ww, &wh);
        if (x >= wx && x < wx + ww && y >= wy && y < wy + wh)
        {
            return win;
        }
    }

    return NULL;
}

static int wm_point_in_titlebar(const wm_window_t *win, int x, int y)
{
    if (!win || !g_window_skin || !g_window_skin->pixels || !g_title_font)
    {
        return 0;
    }

    int fw = font_width(g_title_font);
    int fh = font_height(g_title_font);
    int title_w = (int)strlen(win->title) * fw + TITLE_PADDING_X;
    int title_h = fh + TITLE_PADDING_Y;
    int title_x = win->x;
    if (title_x + title_w > (int)g_mode.width)
    {
        title_x = (int)g_mode.width - title_w;
        if (title_x < 0) title_x = 0;
    }
    int title_y = win->y - title_h;
    if (title_y < 0) title_y = 0;

    return (x >= title_x && x < title_x + title_w &&
            y >= title_y && y < title_y + title_h);
}

// Add a dirty rectangle (will be merged/clipped later)
static void wm_add_dirty_rect(int x, int y, int w, int h)
{
    if (g_disable_dirty_mark)
    {
        return;
    }

    // Clamp to screen
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > (int)g_mode.width) w = (int)g_mode.width - x;
    if (y + h > (int)g_mode.height) h = (int)g_mode.height - y;
    if (w <= 0 || h <= 0) return;

    // If full, just mark entire screen dirty
    if (g_dirty_count >= MAX_DIRTY_RECTS)
    {
        g_dirty_rects[0].x = 0;
        g_dirty_rects[0].y = 0;
        g_dirty_rects[0].w = (int)g_mode.width;
        g_dirty_rects[0].h = (int)g_mode.height;
        g_dirty_count = 1;
        return;
    }

    g_dirty_rects[g_dirty_count].x = x;
    g_dirty_rects[g_dirty_count].y = y;
    g_dirty_rects[g_dirty_count].w = w;
    g_dirty_rects[g_dirty_count].h = h;
    g_dirty_count++;
    g_needs_redraw = 1;
}

// Present only dirty region (bounding box of all dirty rects) to the screen
static void wm_request_present(void)
{
    if (!g_backbuffer || g_backbuffer_bytes == 0 || g_dirty_count == 0)
    {
        return;
    }

    // Calculate bounding box of all dirty rects
    int min_x = g_dirty_rects[0].x;
    int min_y = g_dirty_rects[0].y;
    int max_x = g_dirty_rects[0].x + g_dirty_rects[0].w;
    int max_y = g_dirty_rects[0].y + g_dirty_rects[0].h;

    for (int i = 1; i < g_dirty_count; i++)
    {
        dirty_rect_t *r = &g_dirty_rects[i];
        if (r->x < min_x) min_x = r->x;
        if (r->y < min_y) min_y = r->y;
        if (r->x + r->w > max_x) max_x = r->x + r->w;
        if (r->y + r->h > max_y) max_y = r->y + r->h;
    }

    int w = max_x - min_x;
    int h = max_y - min_y;

    // Copy only the dirty region to framebuffer
    // Calculate pointer to start of dirty region in backbuffer
    uint32_t *src = g_backbuffer + (size_t)min_y * g_backbuffer_stride + min_x;

    // Use syscall with offset pointer and adjusted dimensions
    // The pitch stays the same (full row width), but we start from offset
    system_video_present_region(src, (int)g_mode.pitch, min_x, min_y, w, h);

    g_dirty_count = 0;
    g_needs_redraw = 0;
}

static int rects_intersect(int ax, int ay, int aw, int ah, int bx, int by, int bw, int bh)
{
    return aw > 0 && ah > 0 && bw > 0 && bh > 0 &&
           ax < bx + bw && ax + aw > bx &&
           ay < by + bh && ay + ah > by;
}

static void wm_fill_bg_region(int x, int y, int w, int h)
{
    if (!g_backbuffer) return;

    // Clamp
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > (int)g_mode.width) w = (int)g_mode.width - x;
    if (y + h > (int)g_mode.height) h = (int)g_mode.height - y;
    if (w <= 0 || h <= 0) return;

    const uint32_t bg = color_rgb(69, 67, 117);
    for (int row = y; row < y + h; row++)
    {
        uint32_t *dst = g_backbuffer + (size_t)row * g_backbuffer_stride + x;
        for (int col = 0; col < w; col++)
        {
            dst[col] = bg;
        }
    }

}

// Repaint background and any windows intersecting the current dirty area
static void wm_repaint_dirty_region(void)
{
    if (g_dirty_count == 0)
    {
        return;
    }

    // Compute bounding box of current dirty rects
    int min_x = g_dirty_rects[0].x;
    int min_y = g_dirty_rects[0].y;
    int max_x = g_dirty_rects[0].x + g_dirty_rects[0].w;
    int max_y = g_dirty_rects[0].y + g_dirty_rects[0].h;

    for (int i = 1; i < g_dirty_count; i++)
    {
        dirty_rect_t *r = &g_dirty_rects[i];
        if (r->x < min_x) min_x = r->x;
        if (r->y < min_y) min_y = r->y;
        if (r->x + r->w > max_x) max_x = r->x + r->w;
        if (r->y + r->h > max_y) max_y = r->y + r->h;
    }

    int dirty_w = max_x - min_x;
    int dirty_h = max_y - min_y;

    // Temporarily suppress dirty marking during repaint
    g_disable_dirty_mark = 1;

    wm_fill_bg_region(min_x, min_y, dirty_w, dirty_h);

    // Collect windows so we can paint bottom-to-top (oldest first).
    wm_window_t *win_stack[128];
    int win_count = 0;
    for (wm_window_t *win = g_windows; win && win_count < 128; win = win->next)
    {
        win_stack[win_count++] = win;
    }

    // Paint all non-focused windows first (oldest → newest)
    for (int i = win_count - 1; i >= 0; --i)
    {
        wm_window_t *win = win_stack[i];
        if (win == g_focused)
        {
            continue;
        }
        int wx, wy, ww, wh;
        wm_get_decor_bounds(win, &wx, &wy, &ww, &wh);

        if (rects_intersect(min_x, min_y, dirty_w, dirty_h, wx, wy, ww, wh))
        {
            dwm_msg_t msg = {0};
            msg.window_id = win->id;
            wm_draw_window(&msg);
        }
    }

    // Draw focused window last so its border stays on top.
    if (g_focused)
    {
        wm_window_t *fwin = g_focused;
        int wx, wy, ww, wh;
        wm_get_decor_bounds(fwin, &wx, &wy, &ww, &wh);

        if (rects_intersect(min_x, min_y, dirty_w, dirty_h, wx, wy, ww, wh))
        {
            dwm_msg_t msg = {0};
            msg.window_id = fwin->id;
            wm_draw_window(&msg);
        }
    }

    g_disable_dirty_mark = 0;

    // Collapse dirty list to the bounding box we just repainted
    g_dirty_rects[0].x = min_x;
    g_dirty_rects[0].y = min_y;
    g_dirty_rects[0].w = dirty_w;
    g_dirty_rects[0].h = dirty_h;
    g_dirty_count = 1;
}

// Try to present, rate-limited to ~60 FPS (16ms). Returns 1 if presented.
static int wm_try_present(void)
{
    if (!g_needs_redraw)
    {
        return 0;
    }

    uint64_t now = monotonic_ms();
    if (now < g_last_present_ms)
    {
        g_last_present_ms = now;
    }
    // Rate limit to ~60 FPS (16ms between frames)
    if (now - g_last_present_ms < 16)
    {
        return 0;
    }

    wm_redraw_focus_dirty();
    wm_repaint_dirty_region();
    wm_draw_cursor();  // Draw cursor on top of everything
    wm_request_present();
    g_last_present_ms = now;
    return 1;
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

    wm_window_t *old_focus = g_focused;

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

    g_prev_focus = old_focus;
    g_focus_dirty = 1; // Need to repaint borders for focus change

    // Immediately redraw focus-sensitive decorations and present
    // wm_redraw_focus_dirty() now clears and draws directly, so no need
    // for wm_repaint_dirty_region() which would erase our drawings
    wm_redraw_focus_dirty();
    wm_draw_cursor();
    wm_request_present();
}

static void wm_add_window(wm_window_t *window)
{
    window->next = g_windows;
    g_windows = window;

    // New windows automatically get focus, but don't send focus events yet
    // (the client hasn't received its CREATE reply, so it can't handle events)
    // However, we DO need to repaint the old focused window's decorations
    wm_window_t *old_focus = g_focused;
    g_focused = window;

    // Repaint old window with unfocused decorations
    if (old_focus)
    {
        int dx, dy, dw, dh;
        wm_get_decor_bounds(old_focus, &dx, &dy, &dw, &dh);
        wm_fill_bg_region(dx, dy, dw, dh);

        dwm_msg_t msg = {0};
        msg.window_id = old_focus->id;
        wm_draw_window(&msg);

        wm_add_dirty_rect(dx, dy, dw, dh);

        // Present immediately so decorations update is visible
        wm_draw_cursor();
        wm_request_present();

        // Send focus lost event to the old window
        wm_send_focus_event(old_focus, 0);
    }

    g_needs_redraw = 1;
}

// Fast inline memset32 for WM
static inline void wm_memset32(uint32_t *dst, uint32_t val, size_t count)
{
    while (count >= 4)
    {
        dst[0] = val; dst[1] = val; dst[2] = val; dst[3] = val;
        dst += 4;
        count -= 4;
    }
    while (count--)
    {
        *dst++ = val;
    }
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

    int row_width = x1 - x0;
    int row_height = y1 - y0;
    if (row_width <= 0 || row_height <= 0) return;

    for (int row = y0; row < y1; row++)
    {
        uint32_t *dst = g_backbuffer + (size_t)row * g_backbuffer_stride + x0;
        wm_memset32(dst, bg, (size_t)row_width);
    }

    // Mark cleared region as dirty
    wm_add_dirty_rect(x0, y0, row_width, row_height);
}

// Draw the mouse cursor at the current position
static void wm_draw_cursor(void)
{
    const cursor_t *cursor = theme_get_cursor(&g_cursor_theme, g_current_cursor);
    if (!cursor || !cursor->image || !g_backbuffer) return;

    tga_image_t *img = cursor->image;
    int cursor_w = (int)img->width;
    int cursor_h = (int)img->height;

    // Calculate draw position with hotspot offset
    int draw_x = g_mouse_x - cursor->hotspot_x;
    int draw_y = g_mouse_y - cursor->hotspot_y;

    // Clamp to screen bounds
    int x0 = draw_x;
    int y0 = draw_y;
    int x1 = draw_x + cursor_w;
    int y1 = draw_y + cursor_h;

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > (int)g_mode.width) x1 = (int)g_mode.width;
    if (y1 > (int)g_mode.height) y1 = (int)g_mode.height;

    int draw_w = x1 - x0;
    int draw_h = y1 - y0;
    if (draw_w <= 0 || draw_h <= 0) return;

    // Offset into source image if x0/y0 were clamped
    int src_x = x0 - draw_x;
    int src_y = y0 - draw_y;

    for (int y = 0; y < draw_h; y++)
    {
        uint32_t *dst = g_backbuffer + (size_t)(y0 + y) * g_backbuffer_stride + x0;
        uint32_t *src = img->pixels + (size_t)(src_y + y) * cursor_w + src_x;

        for (int x = 0; x < draw_w; x++)
        {
            uint32_t pixel = src[x];
            uint8_t alpha = (pixel >> 24) & 0xFF;

            if (alpha == 0xFF)
            {
                dst[x] = pixel;
            }
            else if (alpha > 0)
            {
                uint32_t bg = dst[x];
                uint32_t inv = 255 - alpha;

                uint32_t r = (((pixel >> 16) & 0xFF) * alpha + ((bg >> 16) & 0xFF) * inv) / 255;
                uint32_t g = (((pixel >> 8) & 0xFF) * alpha + ((bg >> 8) & 0xFF) * inv) / 255;
                uint32_t b = ((pixel & 0xFF) * alpha + (bg & 0xFF) * inv) / 255;

                dst[x] = 0xFF000000 | (r << 16) | (g << 8) | b;
            }
        }
    }
}

// Update mouse position and mark areas dirty
static int wm_update_mouse(void)
{
    int moved = 0;
    // Get current mouse position from kernel
    system_mouse_get_pos(&g_mouse_x, &g_mouse_y);

    // Check if mouse moved
    if (g_mouse_x != g_prev_mouse_x || g_mouse_y != g_prev_mouse_y)
    {
        moved = 1;
        const cursor_t *cursor = theme_get_cursor(&g_cursor_theme, g_current_cursor);
        int cursor_w = cursor && cursor->image ? (int)cursor->image->width : 16;
        int cursor_h = cursor && cursor->image ? (int)cursor->image->height : 16;
        int hotspot_x = cursor ? cursor->hotspot_x : 0;
        int hotspot_y = cursor ? cursor->hotspot_y : 0;

        // Clear old cursor position (restore background)
        if (g_prev_mouse_x >= 0)
        {
            wm_clear_region(g_prev_mouse_x - hotspot_x, g_prev_mouse_y - hotspot_y,
                            cursor_w, cursor_h);
        }

        // Mark new cursor position as dirty
        wm_add_dirty_rect(g_mouse_x - hotspot_x, g_mouse_y - hotspot_y,
                          cursor_w, cursor_h);

        g_prev_mouse_x = g_mouse_x;
        g_prev_mouse_y = g_mouse_y;
        g_needs_redraw = 1;
    }

    return moved;
}

// Repaint focus-related window decorations.
// Clears and redraws both the previously focused and newly focused windows
// to update their decoration colors (title bar, border).
static void wm_redraw_focus_dirty(void)
{
    if (!g_focus_dirty)
    {
        return;
    }

    // Clear and redraw the previously focused window (now unfocused)
    if (g_prev_focus)
    {
        int dx, dy, dw, dh;
        wm_get_decor_bounds(g_prev_focus, &dx, &dy, &dw, &dh);

        // Clear the decoration area to background
        wm_fill_bg_region(dx, dy, dw, dh);

        // Redraw the window with unfocused decorations
        dwm_msg_t msg = {0};
        msg.window_id = g_prev_focus->id;
        wm_draw_window(&msg);

        wm_add_dirty_rect(dx, dy, dw, dh);
    }

    // Clear and redraw the newly focused window
    if (g_focused)
    {
        int dx, dy, dw, dh;
        wm_get_decor_bounds(g_focused, &dx, &dy, &dw, &dh);

        // Clear the decoration area to background
        wm_fill_bg_region(dx, dy, dw, dh);

        // Redraw the window with focused decorations
        dwm_msg_t msg = {0};
        msg.window_id = g_focused->id;
        wm_draw_window(&msg);

        wm_add_dirty_rect(dx, dy, dw, dh);
    }

    g_focus_dirty = 0;
}

static void wm_remove_window(uint32_t id)
{
    wm_window_t **winp = &g_windows;

    while(*winp)
    {
        if((*winp)->id == id)
        {
            wm_window_t* window = *winp;

            // Get full decorated bounds (includes titlebar, border, shadow)
            int wx, wy, ww, wh;
            wm_get_decor_bounds(window, &wx, &wy, &ww, &wh);

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
            if (g_prev_focus == window)
            {
                g_prev_focus = NULL;
            }

            free(window);

            // Clear the full decorated region and present immediately
            wm_clear_region(wx, wy, ww, wh);
            wm_repaint_dirty_region();
            wm_draw_cursor();
            wm_request_present();

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
    strncpy(window->title, "Window", sizeof(window->title) - 1);

    // Try to get window title from client's resources
    wm_apply_window_resources(window, client_channel);

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
    int max_y = (y0 + (int)window->height > (int)g_mode.height) ? ((int)g_mode.height - y0) : (int)window->height;
    int max_x = (x0 + (int)window->width > (int)g_mode.width) ? ((int)g_mode.width - x0) : (int)window->width;

    if(max_x <= 0 || max_y <= 0)
    {
        return;
    }

    uint32_t *src = (uint32_t*)window->pixels;
    uint32_t src_stride = (uint32_t)(window->pitch / 4);
    uint32_t *dst = g_backbuffer + (size_t)y0 * g_backbuffer_stride + (size_t)x0;

    // Copy window pixels to backbuffer
    size_t row_bytes = (size_t)max_x * sizeof(uint32_t);
    if(src_stride == (uint32_t)max_x && g_backbuffer_stride == (uint32_t)max_x)
    {
        memcpy(dst, src, row_bytes * (size_t)max_y);
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

    // Draw window skin if available
    const int is_focused = (window == g_focused);
    uint32_t title_tint = is_focused ? TITLE_TINT_ACTIVE : TITLE_TINT_INACTIVE;
    uint32_t body_tint = is_focused ? BODY_TINT_ACTIVE : BODY_TINT_INACTIVE;
    const int border = 2;
    int have_title = 0;
    int title_x = x0;
    int title_y = y0;
    int title_w = 0;
    int title_h = 0;

    if (g_window_skin && g_window_skin->pixels && g_title_font)
    {
        const int fw = font_width(g_title_font);
        const int fh = font_height(g_title_font);
        title_w = (int)strlen(window->title) * fw + TITLE_PADDING_X;
        title_h = fh + TITLE_PADDING_Y;
        title_x = x0;
        if (title_x + title_w > (int)g_mode.width)
        {
            title_x = (int)g_mode.width - title_w;
            if (title_x < 0) title_x = 0;
        }
        title_y = y0 - title_h;
        if (title_y < 0) title_y = 0;
        have_title = 1;

        // Helpers to sample from skin
        const uint32_t *skin = g_window_skin->pixels;
        int skin_w = (int)g_window_skin->width;
        #define SKIN(x,y) skin[(y) * skin_w + (x)]

        // Draw title bar using slices
        // Top-left 2x2 corner from (0,0)
        for (int dy = 0; dy < 2; ++dy)
        {
            int ry = title_y + dy;
            if (ry < 0 || ry >= (int)g_mode.height) continue;
            uint32_t *row = g_backbuffer + (size_t)ry * g_backbuffer_stride;
            for (int dx = 0; dx < 2; ++dx)
            {
                int rx = title_x + dx;
                if (rx >= 0 && rx < (int)g_mode.width)
                {
                    row[rx] = blend_skin_px(row[rx], SKIN(dx, dy), title_tint);
                }
            }
            // Top-right 2x2 corner from (3,0)
            for (int dx = 0; dx < 2; ++dx)
            {
                int rx = title_x + title_w - 2 + dx;
                if (rx >= 0 && rx < (int)g_mode.width)
                {
                    row[rx] = blend_skin_px(row[rx], SKIN(3 + dx, dy), title_tint);
                }
            }
        }
        // Bottom corners of title bar from (0,2) and (3,2)
        for (int dy = 0; dy < 2; ++dy)
        {
            int ry = title_y + title_h - 2 + dy;
            if (ry < 0 || ry >= (int)g_mode.height) continue;
            uint32_t *row = g_backbuffer + (size_t)ry * g_backbuffer_stride;
            for (int dx = 0; dx < 2; ++dx)
            {
                int rx = title_x + dx;
                if (rx >= 0 && rx < (int)g_mode.width)
                    row[rx] = blend_skin_px(row[rx], SKIN(dx, 2 + dy), title_tint);
                int rxr = title_x + title_w - 2 + dx;
                if (rxr >= 0 && rxr < (int)g_mode.width)
                    row[rxr] = blend_skin_px(row[rxr], SKIN(3 + dx, 2 + dy), title_tint);
            }
        }
        // Top/bottom edges of title bar
        for (int dx = 2; dx < title_w - 2; ++dx)
        {
            int rx = title_x + dx;
            if (rx < 0 || rx >= (int)g_mode.width) continue;
            for (int dy = 0; dy < 2; ++dy)
            {
                int ry = title_y + dy;
                if (ry >= 0 && ry < (int)g_mode.height)
                    g_backbuffer[(size_t)ry * g_backbuffer_stride + rx] =
                        blend_skin_px(g_backbuffer[(size_t)ry * g_backbuffer_stride + rx],
                                      SKIN(2, dy), title_tint);
                int ryb = title_y + title_h - 2 + dy;
                if (ryb >= 0 && ryb < (int)g_mode.height)
                    g_backbuffer[(size_t)ryb * g_backbuffer_stride + rx] =
                        blend_skin_px(g_backbuffer[(size_t)ryb * g_backbuffer_stride + rx],
                                      SKIN(2, 2 + dy), title_tint);
            }
        }
        // Left/right edges of title bar
        for (int dy = 2; dy < title_h - 2; ++dy)
        {
            int ry = title_y + dy;
            if (ry < 0 || ry >= (int)g_mode.height) continue;
            uint32_t *row = g_backbuffer + (size_t)ry * g_backbuffer_stride;
            for (int dx = 0; dx < 2; ++dx)
            {
                int rx = title_x + dx;
                if (rx >= 0 && rx < (int)g_mode.width)
                    row[rx] = blend_skin_px(row[rx], SKIN(dx, 2), title_tint);
                int rxr = title_x + title_w - 2 + dx;
                if (rxr >= 0 && rxr < (int)g_mode.width)
                    row[rxr] = blend_skin_px(row[rxr], SKIN(3 + dx, 2), title_tint);
            }
        }
        // Title bar fill
        for (int dy = 2; dy < title_h - 2; ++dy)
        {
            int ry = title_y + dy;
            if (ry < 0 || ry >= (int)g_mode.height) continue;
            uint32_t *row = g_backbuffer + (size_t)ry * g_backbuffer_stride;
            for (int dx = 2; dx < title_w - 2; ++dx)
            {
                int rx = title_x + dx;
                if (rx >= 0 && rx < (int)g_mode.width)
                {
                    row[rx] = blend_skin_px(row[rx], SKIN(2, 2), title_tint);
                }
            }
        }
        // Draw title text
        int text_y = title_y + ((title_h - font_height(g_title_font)) / 2) + 4;
        font_draw_text(g_title_font,
                       g_backbuffer,
                       g_backbuffer_stride,
                       title_x + (TITLE_PADDING_X / 2),
                       text_y,
                       window->title,
                       is_focused ? 0xFFFFFFFF : 0xFFB0B0B0);

        // Body frame using skin slices - draw OUTSIDE the window content
        int body_x = x0 - 2;
        int body_y = y0 - 2;
        int body_w = max_x + 4;
        int body_h = max_y + 4;

        // Body corners from (0,4), (3,4), (0,6), (3,6)
        for (int dy = 0; dy < 2; ++dy)
        {
            int ry = body_y + dy;
            if (ry >= 0 && ry < (int)g_mode.height)
            {
                uint32_t *row = g_backbuffer + (size_t)ry * g_backbuffer_stride;
                for (int dx = 0; dx < 2; ++dx)
                {
                    int rx = body_x + dx;
                    if (rx >= 0 && rx < (int)g_mode.width)
                        row[rx] = blend_skin_px(row[rx], SKIN(dx, 4 + dy), body_tint);
                    int rxr = body_x + body_w - 2 + dx;
                    if (rxr >= 0 && rxr < (int)g_mode.width)
                        row[rxr] = blend_skin_px(row[rxr], SKIN(3 + dx, 4 + dy), body_tint);
                }
            }
        }
        for (int dy = 0; dy < 2; ++dy)
        {
            int ry = body_y + body_h - 2 + dy;
            if (ry >= 0 && ry < (int)g_mode.height)
            {
                uint32_t *row = g_backbuffer + (size_t)ry * g_backbuffer_stride;
                for (int dx = 0; dx < 2; ++dx)
                {
                    int rx = body_x + dx;
                    if (rx >= 0 && rx < (int)g_mode.width)
                        row[rx] = blend_skin_px(row[rx], SKIN(dx, 6 + dy), body_tint);
                    int rxr = body_x + body_w - 2 + dx;
                    if (rxr >= 0 && rxr < (int)g_mode.width)
                        row[rxr] = blend_skin_px(row[rxr], SKIN(3 + dx, 6 + dy), body_tint);
                }
            }
        }
        // Top/bottom edges of body
        for (int dx = 2; dx < body_w - 2; ++dx)
        {
            int rx = body_x + dx;
            if (rx < 0 || rx >= (int)g_mode.width) continue;
            if (body_y >= 0)
                g_backbuffer[(size_t)body_y * g_backbuffer_stride + rx] =
                    blend_skin_px(g_backbuffer[(size_t)body_y * g_backbuffer_stride + rx],
                                  SKIN(2, 4), body_tint);
            if (body_y + 1 < (int)g_mode.height)
                g_backbuffer[(size_t)(body_y + 1) * g_backbuffer_stride + rx] =
                    blend_skin_px(g_backbuffer[(size_t)(body_y + 1) * g_backbuffer_stride + rx],
                                  SKIN(2, 5), body_tint);
            int by = body_y + body_h - 2;
            if (by >= 0 && by < (int)g_mode.height)
                g_backbuffer[(size_t)by * g_backbuffer_stride + rx] =
                    blend_skin_px(g_backbuffer[(size_t)by * g_backbuffer_stride + rx],
                                  SKIN(2, 6), body_tint);
            if (by + 1 >= 0 && by + 1 < (int)g_mode.height)
                g_backbuffer[(size_t)(by + 1) * g_backbuffer_stride + rx] =
                    blend_skin_px(g_backbuffer[(size_t)(by + 1) * g_backbuffer_stride + rx],
                                  SKIN(2, 7), body_tint);
        }
        // Left/right edges of body
        for (int dy = 2; dy < body_h - 2; ++dy)
        {
            int ry = body_y + dy;
            if (ry < 0 || ry >= (int)g_mode.height) continue;
            uint32_t *row = g_backbuffer + (size_t)ry * g_backbuffer_stride;
            for (int dx = 0; dx < 2; ++dx)
            {
                int rx = body_x + dx;
                if (rx >= 0 && rx < (int)g_mode.width)
                    row[rx] = blend_skin_px(row[rx], SKIN(dx, 6), body_tint);
                int rxr = body_x + body_w - 2 + dx;
                if (rxr >= 0 && rxr < (int)g_mode.width)
                    row[rxr] = blend_skin_px(row[rxr], SKIN(3 + dx, 6), body_tint);
            }
        }

        #undef SKIN
    }

    // Mark dirty area covering window, borders, and title bar
    int dirty_x0, dirty_y0, dirty_w, dirty_h;
    if (have_title)
    {
        wm_get_decor_bounds(window, &dirty_x0, &dirty_y0, &dirty_w, &dirty_h);
    }
    else
    {
        dirty_x0 = x0 - border;
        dirty_y0 = y0 - border;
        dirty_w = x0 + max_x + border - dirty_x0;
        dirty_h = y0 + max_y + border - dirty_y0;
    }
    wm_add_dirty_rect(dirty_x0, dirty_y0, dirty_w, dirty_h);
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
            printf("[WM] key event but no focused window\n");
            continue;
        }

        dwm_msg_t ev_msg = {0};
        ev_msg.type = DWM_MSG_EVENT;
        ev_msg.window_id = g_focused->id;
        ev_msg.event.type = DIFF_EVENT_KEY;
        ev_msg.event.key = kev.key;
        ev_msg.event.key_pressed = kev.pressed;
        ev_msg.event.modifiers = kev.modifiers;  // Pass modifier flags to client

        int rc = send_message(g_focused->mailbox, &ev_msg, sizeof(ev_msg));
        if (rc < 0)
        {
            printf("[WM] send_message failed rc=%d mailbox=%d\n", rc, g_focused->mailbox);
        }
    }
}

static int wm_button_index(uint8_t button)
{
    if (button == MOUSE_BTN_LEFT) return 0;
    if (button == MOUSE_BTN_RIGHT) return 1;
    if (button == MOUSE_BTN_MIDDLE) return 2;
    return -1;
}

static void wm_send_mouse_event(wm_window_t *window, uint8_t action, uint8_t button)
{
    if (!window)
    {
        return;
    }

    int rel_x = g_mouse_x - window->x;
    int rel_y = g_mouse_y - window->y;
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
    ev_msg.event.mouse_buttons = g_mouse_buttons_down;
    ev_msg.event.mouse_action = action;
    ev_msg.event.mouse_button = button;

    int rc = send_message(window->mailbox, &ev_msg, sizeof(ev_msg));
    if (rc < 0)
    {
        printf("[WM] send_message failed rc=%d mailbox=%d\n", rc, window->mailbox);
    }
}

static void wm_dispatch_mouse_events(int moved)
{
    uint8_t pressed = system_mouse_get_buttons_pressed();
    uint8_t released = system_mouse_get_buttons_clicked();

    if (!moved && pressed == 0 && released == 0)
    {
        return;
    }

    wm_window_t *hover = wm_find_window_at(g_mouse_x, g_mouse_y);
    wm_window_t *target = g_mouse_capture ? g_mouse_capture : hover;

    if (moved)
    {
        if (g_drag_window)
        {
            int new_x = g_mouse_x - g_drag_offset_x;
            int new_y = g_mouse_y - g_drag_offset_y;

            if (new_x < 0) new_x = 0;
            if (new_y < 0) new_y = 0;
            if (new_x >= (int)g_mode.width) new_x = (int)g_mode.width - 1;
            if (new_y >= (int)g_mode.height) new_y = (int)g_mode.height - 1;

            if (new_x != g_drag_window->x || new_y != g_drag_window->y)
            {
                int old_x, old_y, old_w, old_h;
                wm_get_decor_bounds(g_drag_window, &old_x, &old_y, &old_w, &old_h);
                wm_clear_region(old_x, old_y, old_w, old_h);

                g_drag_window->x = new_x;
                g_drag_window->y = new_y;

                int new_dx, new_dy, new_dw, new_dh;
                wm_get_decor_bounds(g_drag_window, &new_dx, &new_dy, &new_dw, &new_dh);
                wm_add_dirty_rect(new_dx, new_dy, new_dw, new_dh);
                g_needs_redraw = 1;
            }
        }

        if (target)
        {
            wm_send_mouse_event(target, MOUSE_ACTION_MOVE, 0);
        }
    }

    if (pressed)
    {
        g_mouse_buttons_down |= pressed;

        if (!g_mouse_capture)
        {
            g_mouse_capture = target;
        }

        if (target && g_focused != target)
        {
            wm_set_focus(target);
        }

        if (target && (pressed & MOUSE_BTN_LEFT) &&
            wm_point_in_titlebar(target, g_mouse_x, g_mouse_y))
        {
            g_drag_window = target;
            g_drag_offset_x = g_mouse_x - target->x;
            g_drag_offset_y = g_mouse_y - target->y;
        }

        if (pressed & MOUSE_BTN_LEFT)
        {
            wm_send_mouse_event(target, MOUSE_ACTION_DOWN, MOUSE_BTN_LEFT);
        }
        if (pressed & MOUSE_BTN_RIGHT)
        {
            wm_send_mouse_event(target, MOUSE_ACTION_DOWN, MOUSE_BTN_RIGHT);
        }
        if (pressed & MOUSE_BTN_MIDDLE)
        {
            wm_send_mouse_event(target, MOUSE_ACTION_DOWN, MOUSE_BTN_MIDDLE);
        }
    }

    if (released)
    {
        g_mouse_buttons_down &= (uint8_t)~released;

        if (released & MOUSE_BTN_LEFT)
        {
            wm_send_mouse_event(target, MOUSE_ACTION_UP, MOUSE_BTN_LEFT);
        }
        if (released & MOUSE_BTN_RIGHT)
        {
            wm_send_mouse_event(target, MOUSE_ACTION_UP, MOUSE_BTN_RIGHT);
        }
        if (released & MOUSE_BTN_MIDDLE)
        {
            wm_send_mouse_event(target, MOUSE_ACTION_UP, MOUSE_BTN_MIDDLE);
        }

        if (target)
        {
            uint64_t now = monotonic_ms();

            if (released & MOUSE_BTN_LEFT)
            {
                wm_send_mouse_event(target, MOUSE_ACTION_CLICK, MOUSE_BTN_LEFT);
                int idx = wm_button_index(MOUSE_BTN_LEFT);
                if (idx >= 0 &&
                    now - g_last_click_ms[idx] <= DWM_DBLCLICK_MS &&
                    g_last_click_window_id[idx] == target->id &&
                    abs(g_mouse_x - g_last_click_x[idx]) <= DWM_DBLCLICK_DIST &&
                    abs(g_mouse_y - g_last_click_y[idx]) <= DWM_DBLCLICK_DIST)
                {
                    wm_send_mouse_event(target, MOUSE_ACTION_DBLCLICK, MOUSE_BTN_LEFT);
                }
                g_last_click_ms[idx] = now;
                g_last_click_x[idx] = g_mouse_x;
                g_last_click_y[idx] = g_mouse_y;
                g_last_click_window_id[idx] = target->id;
            }
            if (released & MOUSE_BTN_RIGHT)
            {
                wm_send_mouse_event(target, MOUSE_ACTION_CLICK, MOUSE_BTN_RIGHT);
                int idx = wm_button_index(MOUSE_BTN_RIGHT);
                if (idx >= 0 &&
                    now - g_last_click_ms[idx] <= DWM_DBLCLICK_MS &&
                    g_last_click_window_id[idx] == target->id &&
                    abs(g_mouse_x - g_last_click_x[idx]) <= DWM_DBLCLICK_DIST &&
                    abs(g_mouse_y - g_last_click_y[idx]) <= DWM_DBLCLICK_DIST)
                {
                    wm_send_mouse_event(target, MOUSE_ACTION_DBLCLICK, MOUSE_BTN_RIGHT);
                }
                g_last_click_ms[idx] = now;
                g_last_click_x[idx] = g_mouse_x;
                g_last_click_y[idx] = g_mouse_y;
                g_last_click_window_id[idx] = target->id;
            }
            if (released & MOUSE_BTN_MIDDLE)
            {
                wm_send_mouse_event(target, MOUSE_ACTION_CLICK, MOUSE_BTN_MIDDLE);
                int idx = wm_button_index(MOUSE_BTN_MIDDLE);
                if (idx >= 0 &&
                    now - g_last_click_ms[idx] <= DWM_DBLCLICK_MS &&
                    g_last_click_window_id[idx] == target->id &&
                    abs(g_mouse_x - g_last_click_x[idx]) <= DWM_DBLCLICK_DIST &&
                    abs(g_mouse_y - g_last_click_y[idx]) <= DWM_DBLCLICK_DIST)
                {
                    wm_send_mouse_event(target, MOUSE_ACTION_DBLCLICK, MOUSE_BTN_MIDDLE);
                }
                g_last_click_ms[idx] = now;
                g_last_click_x[idx] = g_mouse_x;
                g_last_click_y[idx] = g_mouse_y;
                g_last_click_window_id[idx] = target->id;
            }
        }

        if (g_mouse_buttons_down == 0)
        {
            g_mouse_capture = NULL;
            g_drag_window = NULL;
        }
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
    g_backbuffer_bytes = (size_t)g_backbuffer_stride * g_mode.height * sizeof(uint32_t);

    // Allocate double buffers and start drawing into buffer 0.
    for (int i = 0; i < 2; ++i)
    {
        g_buffers[i] = calloc((size_t)g_backbuffer_stride * g_mode.height, sizeof(uint32_t));
        if (!g_buffers[i])
        {
            return -2;
        }
    }
    g_backbuffer = g_buffers[g_active_fb];

    // Load cursor theme
    if (theme_load(&g_cursor_theme, "/system/themes/default.theme") < 0)
    {
        // Theme load failed, but we can continue without cursors
    }

    // Load window skin and title font
    g_window_skin = tga_load("/system/graphics/window.tga");
    g_title_font = font_load_bdf("/system/fonts/spleen-8x16.bdf");
    if (!g_title_font)
    {
        g_title_font = font_load_bdf("/system/fonts/spleen-6x12.bdf");
    }
    if (!g_title_font)
    {
        g_title_font = font_load_bdf("/system/fonts/spleen-5x8.bdf");
    }

    // Set mouse bounds and center cursor
    system_mouse_set_bounds((int)g_mode.width, (int)g_mode.height);
    system_mouse_set_pos((int)g_mode.width / 2, (int)g_mode.height / 2);
    g_mouse_x = (int)g_mode.width / 2;
    g_mouse_y = (int)g_mode.height / 2;
    g_mouse_buttons_down = system_mouse_get_buttons_down();

    g_mailbox = create_message_channel(DWM_MAILBOX_ID);

    if(g_mailbox < 0)
    {
        return -3;
    }

    /* Fill background to a known color before any client draws */
    const uint32_t bg = color_rgb(69, 67, 117);
    size_t total = (size_t)g_backbuffer_stride * g_mode.height;
    for (int b = 0; b < 2; ++b)
    {
        uint32_t *dst = g_buffers[b];
        size_t n = total;
        // Fast unrolled fill
        while (n >= 8)
        {
            dst[0] = bg; dst[1] = bg; dst[2] = bg; dst[3] = bg;
            dst[4] = bg; dst[5] = bg; dst[6] = bg; dst[7] = bg;
            dst += 8;
            n -= 8;
        }
        while (n--)
        {
            *dst++ = bg;
        }

        g_backbuffer = g_buffers[b];
    }
    g_backbuffer = g_buffers[g_active_fb];

    // Initialize previous mouse position for dirty tracking
    g_prev_mouse_x = g_mouse_x;
    g_prev_mouse_y = g_mouse_y;

    // Draw initial cursor
    wm_draw_cursor();

    // Initial full-screen present
    system_video_present(g_backbuffer, (int)g_mode.pitch, (int)g_mode.width, (int)g_mode.height);
    g_last_present_ms = monotonic_ms();

    const char *client_path = "/programs/gdterm/gdterm.dex";
    spawn_process(client_path, 0, NULL);

    dwm_msg_t *msg = (dwm_msg_t *)malloc(sizeof(dwm_msg_t));
    if (!msg)
    {
        return -4;
    }

    // Message handling loop with blocking receive + timeout
    // This avoids busy-polling: we block until a message arrives or timeout expires.
    // Timeout allows us to periodically check for keyboard events even when no messages.
    int msg_count = 0;
    const uint32_t RECV_TIMEOUT_MS = 16; // ~60 FPS max, allows keyboard polling

    for(;;)
    {
        // Block until message arrives or timeout (16ms = ~60Hz input polling)
        int rc = receive_message_timeout(g_mailbox, msg, sizeof(*msg), RECV_TIMEOUT_MS);

        if (rc > 0)
        {
            // Got a message - process it
            wm_handle_message(msg);
            msg_count++;

            // Drain any additional queued messages without blocking
            while (msg_count < 64 && try_receive_message(g_mailbox, msg, sizeof(*msg)) > 0)
            {
                wm_handle_message(msg);
                msg_count++;

                // Batch renders: update screen every 4 messages or on explicit draw
                if (g_needs_redraw && (msg_count >= 4 || msg->type == DWM_MSG_DRAW))
                {
                    wm_try_present();
                    msg_count = 0;
                }
            }
        }

        // Update mouse position and check for movement
        int mouse_moved = wm_update_mouse();
        wm_dispatch_mouse_events(mouse_moved);

        // Flush any pending redraw (either from messages or timeout)
        if (g_needs_redraw)
        {
            wm_try_present();
            msg_count = 0;
        }

        // Deliver keyboard events to the currently focused window
        wm_dispatch_key_events();
    }

    free(g_backbuffer);
    free(msg);

    return 0;
}
