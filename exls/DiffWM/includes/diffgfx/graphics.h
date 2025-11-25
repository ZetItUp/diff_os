#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct diff_window diff_window_t;

typedef enum
{
    DIFFWM_EVENT_NONE = 0,
    DIFFWM_EVENT_KEY,
    DIFFEM_EVENT_MOUSE
} diffwm_event_type_t;

typedef struct
{
    diffwm_event_type_t type;
    uint8_t key;
    int16_t mouse_x;
    int16_t mouse_y;
    uint8_t mouse_buttons;
} diffwm_event_t;
 // already allowed

diff_window_t* diff_window_create(int x, int y, int width, int height, uint32_t flags);
void diff_window_destroy(diff_window_t *window);
void diff_window_present(diff_window_t *window, const void *pixels, size_t pitch);
int diff_poll_event(diff_window_t *window, diffwm_event_t *event);
