#pragma once

#include <stdint.h>
#include <diffwm/window.h>
#include <diffwm/protocol.h>

/*
 * DiffWM IPC Interface
 *
 * Low-level window manager communication functions.
 * Most GUI applications should use the higher-level window component API.
 */

/* Window lifecycle */
window_t* window_create(int x, int y, int width, int height, uint32_t flags, const char *title);
void window_destroy(window_t *window);

/* Window operations */
void window_present(window_t *window, const void *pixels);
int window_poll_event(window_t *window, diff_event_t *event);
