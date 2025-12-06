#pragma once

#include <diffwm/window_component.h>


typedef struct label_t
{
    window_component_t base;
    const char *text;
} label_t;

void label_init(label_t *label, int x, int y, const char *text);
void label_set_text(label_t *label, const char *text);
void label_update(window_component_t *self);
void label_draw(window_component_t *self);
