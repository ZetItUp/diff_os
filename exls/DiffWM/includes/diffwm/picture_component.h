#pragma once

#include <diffwm/window_component.h>
#include <stdint.h>

typedef struct picture_component
{
    window_component_t base;
    const uint32_t *pixels; // ARGB32 source image
    int stride;             // source stride in pixels
} picture_component_t;

void picture_component_init(picture_component_t *pic,
                            int x,
                            int y,
                            int width,
                            int height,
                            const uint32_t *pixels,
                            int stride_pixels);

// Update the image data/size after init (e.g. for dynamic images).
void picture_component_set_image(picture_component_t *pic,
                                 const uint32_t *pixels,
                                 int width,
                                 int height,
                                 int stride_pixels);

void picture_component_update(window_component_t *self);
void picture_component_draw(window_component_t *self);
