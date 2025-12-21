#pragma once

#include <diffwm/window_component.h>
#include <diffwm/text_utils.h>
#include <diffwm/protocol.h>
#include <difffonts/fonts.h>
#include <stdbool.h>

// Single-line text input component
typedef struct textbox_t
{
    window_component_t base;

    char *text;
    int max_length;
    int cursor_pos;
    int scroll_x;

    text_selection_t selection;
    font_t *font;
    bool focused;
    bool multiline;

    uint32_t bg_color;
    uint32_t fg_color;
    uint32_t selection_color;
    uint32_t border_color;
} textbox_t;

// Initialize textbox with given buffer
void textbox_init(textbox_t *box, int x, int y, int width, int height,
                  char *text_buffer, int max_length, font_t *font);

// Set colors
void textbox_set_colors(textbox_t *box, uint32_t bg, uint32_t fg,
                       uint32_t selection, uint32_t border);

// Insert character at cursor
void textbox_insert_char(textbox_t *box, char c);

// Delete character at cursor
void textbox_delete_char(textbox_t *box);

// Move cursor
void textbox_move_cursor(textbox_t *box, int delta);

// Set cursor position
void textbox_set_cursor(textbox_t *box, int pos);

// Set text (copies into buffer)
void textbox_set_text(textbox_t *box, const char *text);

// Set multiline behavior
void textbox_set_multiline(textbox_t *box, bool multiline);

// Get text
const char* textbox_get_text(textbox_t *box);

// Handle mouse/key events - returns true if event was consumed
bool textbox_handle_event(textbox_t *box, const diff_event_t *event);

// Polymorphic methods
void textbox_update(window_component_t *self);
void textbox_paint(window_component_t *self);
