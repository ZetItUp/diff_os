#pragma once

#include <diffwm/window.h>

// Report a damaged content rectangle (window-local coordinates) for next present.
void window_damage(window_t *window, int x_position, int y_position, int width, int height);
