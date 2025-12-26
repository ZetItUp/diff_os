#pragma once

#include <stdint.h>
#include <diffwm/protocol.h>

// Event System for DiffWM
//
// This implements proper event consumption/propagation:
// - Events are dispatched top-down through the window z-order
// - When a window/widget handles an event, it returns 1 (consumed)
// - Consumed events are NOT passed to windows below
// - This prevents "click-through" to overlapping windows

// Forward declaration
struct wm_window;

// Event result codes
#define EVENT_IGNORED   0   // Event not handled, continue propagation
#define EVENT_CONSUMED  1   // Event handled, stop propagation

// Mouse state tracking
typedef struct mouse_state
{
    int x;
    int y;
    int prev_x;
    int prev_y;
    uint8_t buttons_down;
    uint8_t prev_buttons_down;
    struct wm_window *capture;      // Window that captured mouse
    struct wm_window *drag_window;  // Window being dragged
    struct wm_window *hover_window; // Window currently hovered
    int drag_offset_x;
    int drag_offset_y;
} mouse_state_t;

// Double-click tracking
typedef struct click_state
{
    uint64_t last_click_ms[3];
    int last_click_x[3];
    int last_click_y[3];
    uint32_t last_click_window_id[3];
} click_state_t;

// Event context passed to handlers
typedef struct event_context
{
    mouse_state_t *mouse;
    click_state_t *clicks;
    struct wm_window *focused;
    struct wm_window *windows;  // Head of window list
    int screen_width;
    int screen_height;
} event_context_t;

// Initialize the event system
void event_init(event_context_t *ctx);

// Process mouse events
// Returns 1 if any event was consumed, 0 otherwise
int event_process_mouse(event_context_t *ctx, int mouse_moved);

// Process keyboard events
// Returns 1 if any event was consumed, 0 otherwise
int event_process_keyboard(event_context_t *ctx);

// Find the topmost window at screen coordinates
// Uses z-order (front to back) for proper hit testing
struct wm_window *event_find_window_at(event_context_t *ctx, int x, int y);

// Check if a point is in a window's titlebar
int event_point_in_titlebar(struct wm_window *win, int x, int y);

// Send a mouse event to a specific window
void event_send_mouse(struct wm_window *window, int x, int y,
                      uint8_t buttons, uint8_t action, uint8_t button);

// Send a keyboard event to a specific window
void event_send_key(struct wm_window *window, uint8_t key,
                    int pressed, uint8_t modifiers);

// Send focus gained/lost event
void event_send_focus(struct wm_window *window, int gained);

// Get button index for double-click tracking (0=left, 1=right, 2=middle)
int event_button_index(uint8_t button);
