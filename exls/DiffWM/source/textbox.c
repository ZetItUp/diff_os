#include <diffwm/textbox.h>
#include <diffwm/window_component.h>
#include <string.h>

void textbox_init(textbox_t *box, int x, int y, int width, int height,
                  char *text_buffer, int max_length, font_t *font)
{
    if (!box)
        return;

    // Initialize base component
    window_component_init(&box->base, x, y, width, height);

    // Set textbox-specific fields
    box->text = text_buffer;
    box->max_length = max_length;
    box->cursor_pos = 0;
    box->font = font;

    // Default colors (white bg, black fg)
    box->bg_color = 0xFFFFFFFF;
    box->fg_color = 0xFF000000;
    box->selection_color = 0xFF3366CC;
    box->border_color = 0xFF888888;

    // Initialize selection
    text_selection_init(&box->selection);

    // Set polymorphic function pointers
    box->base.update = textbox_update;
    box->base.draw = textbox_paint;
}

void textbox_set_colors(textbox_t *box, uint32_t bg, uint32_t fg,
                       uint32_t selection, uint32_t border)
{
    if (!box)
        return;

    box->bg_color = bg;
    box->fg_color = fg;
    box->selection_color = selection;
    box->border_color = border;
}

void textbox_insert_char(textbox_t *box, char c)
{
    if (!box || !box->text)
        return;

    int len = strlen(box->text);

    // Check if we have space
    if (len >= box->max_length - 1)
        return;

    // Shift characters to make room
    for (int i = len; i >= box->cursor_pos; i--)
    {
        box->text[i + 1] = box->text[i];
    }

    // Insert character
    box->text[box->cursor_pos] = c;
    box->cursor_pos++;
}

void textbox_delete_char(textbox_t *box)
{
    if (!box || !box->text)
        return;

    if (box->cursor_pos == 0)
        return;

    int len = strlen(box->text);

    // Shift characters left
    for (int i = box->cursor_pos - 1; i < len; i++)
    {
        box->text[i] = box->text[i + 1];
    }

    box->cursor_pos--;
}

void textbox_move_cursor(textbox_t *box, int delta)
{
    if (!box || !box->text)
        return;

    int new_pos = box->cursor_pos + delta;
    int len = strlen(box->text);

    if (new_pos < 0)
        new_pos = 0;
    if (new_pos > len)
        new_pos = len;

    box->cursor_pos = new_pos;
}

void textbox_set_cursor(textbox_t *box, int pos)
{
    if (!box || !box->text)
        return;

    int len = strlen(box->text);

    if (pos < 0)
        pos = 0;
    if (pos > len)
        pos = len;

    box->cursor_pos = pos;
}

const char* textbox_get_text(textbox_t *box)
{
    if (!box)
        return NULL;

    return box->text;
}

void textbox_update(window_component_t *self)
{
    // No update logic needed for now
    (void)self;
}

void textbox_paint(window_component_t *self)
{
    textbox_t *box = (textbox_t*)self;

    if (!self->visible || !box->text || !box->font)
        return;

    // TODO: Actual rendering would happen here with a graphics context
    // For now this is a placeholder showing the structure
    // In a real implementation, you'd:
    // 1. Fill background with bg_color
    // 2. Render selection using text_render_selection()
    // 3. Render text using font_draw_text()
    // 4. Render cursor
    // 5. Draw border

    // Example pseudo-code:
    // uint32_t *pixels = get_parent_buffer();
    // int pitch = get_parent_pitch();
    //
    // // Clear background
    // fill_rect(pixels, pitch, self->x, self->y, self->width, self->height, box->bg_color);
    //
    // // Render selection
    // text_render_selection(pixels, pitch, self->width, self->height,
    //                      &box->selection, self->x + 4, self->y + 4,
    //                      box->font, box->selection_color);
    //
    // // Render text
    // font_draw_text(box->font, pixels, pitch,
    //               self->x + 4, self->y + 4,
    //               box->text, box->fg_color);
    //
    // // Render cursor
    // int cursor_x = self->x + 4 + box->cursor_pos * font_width(box->font);
    // draw_line(pixels, pitch, cursor_x, self->y + 2, cursor_x, self->y + self->height - 2, box->fg_color);
    //
    // // Draw border
    // draw_rect(pixels, pitch, self->x, self->y, self->width, self->height, box->border_color);
}
