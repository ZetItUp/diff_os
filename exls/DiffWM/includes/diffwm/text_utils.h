#pragma once

#include <stdbool.h>
#include <stdint.h>

// Forward declaration
typedef struct font font_t;

// Text selection state
typedef struct text_selection_t
{
    int start_col;
    int start_row;
    int end_col;
    int end_row;
    bool active;
    bool dragging;
} text_selection_t;

// Selection management
void text_selection_init(text_selection_t *sel);
void text_selection_start(text_selection_t *sel, int col, int row);
void text_selection_extend(text_selection_t *sel, int col, int row);
void text_selection_clear(text_selection_t *sel);
bool text_selection_contains(text_selection_t *sel, int col, int row);

// Hit testing - convert screen coordinates to text grid coordinates
bool text_hit_test(int screen_x, int screen_y,
                   int offset_x, int offset_y,
                   font_t *font,
                   int *out_col, int *out_row);

// Check if point is within text bounds
bool text_point_in_bounds(int col, int row, int max_cols, int max_rows);

// Render selection highlight
void text_render_selection(uint32_t *pixels, int pitch, int width, int height,
                           text_selection_t *sel,
                           int offset_x, int offset_y,
                           font_t *font,
                           uint32_t selection_color);
