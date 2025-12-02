#pragma once

#include <diffwm/window_component.h>
#include <diffwm/text_utils.h>
#include <difffonts/fonts.h>
#include <stdint.h>

#define TERM_MAX_LINES 128
#define TERM_MAX_COLS 80

// Terminal color structure
typedef struct term_color_t
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
} term_color_t;

// Terminal line structure
typedef struct term_line_t
{
    char text[TERM_MAX_COLS];
    term_color_t colors[TERM_MAX_COLS];
    int len;
} term_line_t;

// Terminal component (embeddable terminal widget)
typedef struct terminal_component_t
{
    window_component_t base;

    term_line_t lines[TERM_MAX_LINES];
    int line_count;
    int cursor_x;
    int cursor_y;

    text_selection_t selection;
    font_t *font;

    term_color_t current_color;
    term_color_t bg_color;
    uint32_t selection_color;
} terminal_component_t;

// Initialize terminal component
void terminal_component_init(terminal_component_t *term, int x, int y, int width, int height, font_t *font);

// Terminal operations
void terminal_putchar(terminal_component_t *term, char c);
void terminal_puts(terminal_component_t *term, const char *s);
void terminal_set_color(terminal_component_t *term, term_color_t color);
void terminal_clear(terminal_component_t *term);
void terminal_backspace(terminal_component_t *term);

// Polymorphic methods
void terminal_component_update(window_component_t *self);
void terminal_component_paint(window_component_t *self);

// Render to pixel buffer
void terminal_component_render(terminal_component_t *term, uint32_t *pixels, int pitch_pixels);
