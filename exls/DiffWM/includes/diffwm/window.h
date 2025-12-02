#pragma once

#include <stdint.h>
#include <diffwm/window_component.h>
#include <diffwm/protocol.h>

#define WINDOW_MAX_CHILDREN 8

typedef struct window_t
{
    window_component_t base;

    const char *title;

    /* Rendering */
    uint32_t *backbuffer;  // Owned by window, allocated in window_create

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
} window_t;

/* High-level window API for GUI programming */
void window_init(window_t *window, int x, int y, int width, int height, const char *title);
void window_add_component(window_t *window, window_component_t *component);

/* Polymorphic methods (virtual functions) */
void window_update(window_component_t *self);
void window_paint(window_component_t *self);
