#include <diffwm/text_utils.h>
#include <string.h>

void text_selection_init(text_selection_t *sel)
{
    if (!sel)
        return;

    sel->start_col = 0;
    sel->start_row = 0;
    sel->end_col = 0;
    sel->end_row = 0;
    sel->active = false;
    sel->dragging = false;
}

void text_selection_start(text_selection_t *sel, int col, int row)
{
    if (!sel)
        return;

    sel->start_col = col;
    sel->start_row = row;
    sel->end_col = col;
    sel->end_row = row;
    sel->active = true;
    sel->dragging = true;
}

void text_selection_extend(text_selection_t *sel, int col, int row)
{
    if (!sel || !sel->active)
        return;

    sel->end_col = col;
    sel->end_row = row;
}

void text_selection_clear(text_selection_t *sel)
{
    if (!sel)
        return;

    sel->active = false;
    sel->dragging = false;
}

bool text_selection_contains(text_selection_t *sel, int col, int row)
{
    if (!sel || !sel->active)
        return false;

    // Normalize selection bounds (start might be after end if dragging backwards)
    int min_row = sel->start_row < sel->end_row ? sel->start_row : sel->end_row;
    int max_row = sel->start_row > sel->end_row ? sel->start_row : sel->end_row;
    int min_col = sel->start_col < sel->end_col ? sel->start_col : sel->end_col;
    int max_col = sel->start_col > sel->end_col ? sel->start_col : sel->end_col;

    // Check if point is within selection
    if (row < min_row || row > max_row)
        return false;

    // For single-line selections
    if (min_row == max_row)
    {
        return col >= min_col && col <= max_col;
    }

    // Multi-line selections
    if (row == min_row)
        return col >= min_col;
    else if (row == max_row)
        return col <= max_col;
    else
        return true; // Middle rows are fully selected
}

bool text_hit_test(int screen_x, int screen_y,
                   int offset_x, int offset_y,
                   font_t *font,
                   int *out_col, int *out_row)
{
    if (!font || !out_col || !out_row)
        return false;

    int fw = font_width(font);
    int fh = font_height(font);

    // Convert screen coordinates to grid coordinates
    int rel_x = screen_x - offset_x;
    int rel_y = screen_y - offset_y;

    if (rel_x < 0 || rel_y < 0)
        return false;

    *out_col = rel_x / fw;
    *out_row = rel_y / fh;

    return true;
}

bool text_point_in_bounds(int col, int row, int max_cols, int max_rows)
{
    return col >= 0 && col < max_cols && row >= 0 && row < max_rows;
}

void text_render_selection(uint32_t *pixels, int pitch, int width, int height,
                           text_selection_t *sel,
                           int offset_x, int offset_y,
                           font_t *font,
                           uint32_t selection_color)
{
    if (!pixels || !sel || !sel->active || !font)
        return;

    int fw = font_width(font);
    int fh = font_height(font);

    // Normalize selection bounds
    int min_row = sel->start_row < sel->end_row ? sel->start_row : sel->end_row;
    int max_row = sel->start_row > sel->end_row ? sel->start_row : sel->end_row;
    int min_col = sel->start_col < sel->end_col ? sel->start_col : sel->end_col;
    int max_col = sel->start_col > sel->end_col ? sel->start_col : sel->end_col;

    // Render selection rectangles
    for (int row = min_row; row <= max_row; row++)
    {
        int start_col, end_col;

        if (min_row == max_row)
        {
            // Single line selection
            start_col = min_col;
            end_col = max_col;
        }
        else if (row == min_row)
        {
            // First line of multi-line selection
            start_col = min_col;
            end_col = 999; // To end of line
        }
        else if (row == max_row)
        {
            // Last line of multi-line selection
            start_col = 0;
            end_col = max_col;
        }
        else
        {
            // Middle lines - fully selected
            start_col = 0;
            end_col = 999;
        }

        // Calculate screen coordinates
        int y0 = offset_y + row * fh;
        int y1 = y0 + fh;
        int x0 = offset_x + start_col * fw;
        int x1 = offset_x + (end_col + 1) * fw;

        // Clip to bounds
        if (y0 < 0) y0 = 0;
        if (y1 > height) y1 = height;
        if (x0 < 0) x0 = 0;
        if (x1 > width) x1 = width;

        // Draw selection rectangle
        for (int y = y0; y < y1; y++)
        {
            for (int x = x0; x < x1; x++)
            {
                pixels[y * pitch + x] = selection_color;
            }
        }
    }
}
