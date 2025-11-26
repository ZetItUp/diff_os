#pragma once

#include <stddef.h>
#include <stdint.h>
#include <diffwm/diffwm.h>
#include <diffwm/protocol.h>
#include <diffgfx/draw.h>

/* Public API: window_* */
window_t* window_create(int x, int y, int width, int height, uint32_t flags);
void window_destroy(window_t *window);
void window_draw(window_t *window, const void *pixels);
int window_poll_event(window_t *window, diff_event_t *event);
