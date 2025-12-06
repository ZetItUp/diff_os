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

    // Window Component Functions
    void (*update)(window_component_t *self);
    void (*draw)(window_component_t *self);
};

void window_component_init(window_component_t *window_comp, int x, int y, int width, int height);
void window_component_update(window_component_t *self);
void window_component_draw(window_component_t *self);
