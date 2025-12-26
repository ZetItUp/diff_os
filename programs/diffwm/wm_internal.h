#pragma once

#include <stdint.h>

// Window Manager Internal Window Tracking
//
// This structure is used by the window manager to track client windows.
// It's separate from the client-side window_t which has polymorphic components.
typedef struct wm_window
{
    uint32_t id;
    int handle;
    void *pixels;
    int drew_once;
    char title[64];
    int title_overridden;

    int x;
    int y;
    uint32_t width;
    uint32_t height;
    uint32_t flags;

    int pitch;
    int mailbox;    // Client mailbox channel index for replies/events
    int wm_channel; // Channel index to talk to WM
    int focus_notified;
    int client_drawn;
    uint8_t titlebar_hover_button;
    uint8_t titlebar_pressed_button;
    struct wm_window *next;
} wm_window_t;

// Double-click timing constants
#define DWM_DBLCLICK_MS    300
#define DWM_DBLCLICK_DIST  4

// Title bar padding
#define TITLE_PADDING_X 8
#define TITLE_PADDING_Y 6

// Global state accessors (implemented in diffwm.c)
wm_window_t *wm_get_windows(void);
wm_window_t *wm_get_focused(void);
void wm_set_focused(wm_window_t *window);
void wm_request_close(wm_window_t *window);

// Window decoration bounds
void wm_get_decor_bounds(const wm_window_t *win, int *x, int *y, int *w, int *h);

// Focus management with dirty region tracking
void wm_set_focus(wm_window_t *window);

// Find window by ID
wm_window_t *wm_find(uint32_t id);

// Dirty region management (for window dragging)
void wm_clear_region(int x, int y, int w, int h);
void wm_add_dirty_rect(int x, int y, int w, int h);
void wm_mark_needs_redraw(void);

// Desktop icon handling
int wm_desktop_handle_click(int x, int y);
int wm_desktop_handle_single_click(int x, int y);
