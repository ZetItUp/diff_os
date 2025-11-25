#pragma once

#include <stdint.h>

typedef struct window
{
    uint32_t id;
    int handle;
    void *pixels;
    int width;
    int height;
    int pitch;
    int mailbox;
} window_t;

window_t window_create(int x, int y, int width, int height, uint32_t flags);
void window_draw(window_t *window, const void *pixels);
int window_poll_event(window_t *window, diffwm_event_t *event);
void window_destroy(window_t *window);
