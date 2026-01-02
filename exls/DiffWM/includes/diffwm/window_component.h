#pragma once

#include <stdbool.h>

struct window_t;
typedef struct window_t window_t;

typedef struct window_component_t window_component_t;

struct window_component_t
{
    window_t *parent; // owning window, set when attached
    int x;
    int y;
    int width;
    int height;

    bool visible;
    bool enabled;

    // Mouse tracking
    bool mouse_inside;

    // Window Component Functions
    void (*update)(window_component_t *self);
    void (*draw)(window_component_t *self);

    // Mouse enter/leave callbacks (optional)
    void (*on_mouse_enter)(window_component_t *self);
    void (*on_mouse_leave)(window_component_t *self);
};

void window_component_init(window_component_t *window_comp, int x, int y, int width, int height);
void window_component_update(window_component_t *self);
void window_component_draw(window_component_t *self);

// Check if point is inside component bounds
bool window_component_contains(window_component_t *self, int x, int y);

// Update mouse tracking and fire enter/leave events
// Returns true if mouse state changed (entered or left)
bool window_component_update_mouse(window_component_t *self, int mouse_x, int mouse_y);
