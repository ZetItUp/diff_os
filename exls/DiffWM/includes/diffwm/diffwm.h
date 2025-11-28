#pragma once

#include <stdint.h>
#include <diffwm/protocol.h>

typedef struct window
{
    uint32_t id;
    int handle;
    void *pixels;
    
    int x;
    int y;
    uint32_t width;
    uint32_t height;

    int pitch;
    int mailbox;    /* Client mailbox channel index for replies/events */
    int wm_channel; /* Channel index to talk to WM */
    struct window *next;
} window_t;

window_t* window_create(int x, int y, int width, int height, uint32_t flags);
void window_draw(window_t *window, const void *pixels);
int window_poll_event(window_t *window, diff_event_t *event);
void window_destroy(window_t *window);
