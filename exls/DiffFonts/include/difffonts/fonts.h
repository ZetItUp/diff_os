#pragma once

#include <stdint.h>
#include <stddef.h>

typedef enum
{
    FONT_TYPE_NONE = 0,
    FONT_TYPE_BDF  = 1,
} font_type_t;

typedef struct font font_t;

// Load a BDF font from path. Returns NULL on failure.
font_t *font_load_bdf(const char *path);

// Destroy/unload a font.
void font_destroy(font_t *font);

// Metrics
int font_width(const font_t *font);   // advance width (pixels)
int font_height(const font_t *font);  // pixel height
int font_ascent(const font_t *font);  // pixels above baseline
int font_descent(const font_t *font); // pixels below baseline

// Draw ASCII text (ARGB32 target, pitch in pixels). Leaves background untouched.
void font_draw_text(const font_t *font,
                    uint32_t *dst,
                    int pitch_pixels,
                    int x,
                    int y,
                    const char *text,
                    uint32_t fg_argb);
