#pragma once

#include <stdint.h>
#include <diffwm/window_component.h>
#include <diffwm/protocol.h>

#define WINDOW_MAX_CHILDREN 8
#define WINDOW_FLAG_NO_BACKGROUND 0x80000000u

typedef struct window_t
{
    window_component_t base;

    const char *title;

    /* Rendering */
    uint32_t *backbuffer;  // Owned by window, allocated in window_create
    uint32_t flags;
    int draw_background;
    int presented;

    /* Child components */
    window_component_t *children[WINDOW_MAX_CHILDREN];
    int child_count;

    /* Window manager communication fields (used by diff_ipc.c) */
    uint32_t id;
    int handle;
    void *pixels;  // Shared memory with WM (not owned by window)
    int pitch;
    int mailbox;    /* Client mailbox channel index for replies/events */
    int wm_channel; /* Channel index to talk to WM */
    struct window_t *next;

    // Pending damage tracking (window-local coordinates)
    int damage_pending;
    int damage_x_position;
    int damage_y_position;
    int damage_width;
    int damage_height;

    // Dirty flag for automatic repaint tracking
    int dirty;
} window_t;

/* High-level window API for GUI programming */
void window_init(window_t *window, int x, int y, int width, int height, const char *title);
void window_add_component(window_t *window, window_component_t *component);
void window_set_background(window_t *window, int enabled);
int window_has_minimize_button(const window_t *window);
int window_has_maximize_button(const window_t *window);

/* Polymorphic methods (virtual functions) */
void window_update(window_component_t *self);
void window_paint(window_component_t *self);

/* Dirty tracking - automatic repaint management */
void window_mark_dirty(window_t *window);
int window_needs_repaint(window_t *window);
void window_clear_dirty(window_t *window);
