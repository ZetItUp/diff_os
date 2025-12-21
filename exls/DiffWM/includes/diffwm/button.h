#pragma once

#include <diffwm/window_component.h>
#include <diffwm/protocol.h>
#include <diffgfx/draw.h>
#include <difffonts/fonts.h>
#include <difftga.h>
#include <stdbool.h>
#include <stdint.h>

// Button visual states
typedef enum {
    BUTTON_STATE_NORMAL = 0,
    BUTTON_STATE_HOVER,
    BUTTON_STATE_PRESSED
} button_state_t;

// Button click callback
typedef void (*button_callback_t)(void *user_data);

typedef struct button_t
{
    window_component_t base;

    // Text
    const char *text;
    font_t *font;

    // Visual state
    button_state_t state;

    // Skin (shared, not owned)
    tga_image_t *skin;

    // Tint colors for each state (ARGB format)
    uint32_t tint_normal;
    uint32_t tint_hover;
    uint32_t tint_pressed;

    // Text colors for each state
    uint32_t text_color_normal;
    uint32_t text_color_hover;
    uint32_t text_color_pressed;

    // Click callback
    button_callback_t on_click;
    void *user_data;

    // Key binding (0 = none)
    uint8_t hotkey;

    // Internal tracking
    bool mouse_inside;
    bool mouse_down;
} button_t;

// Border size (matches window skin)
#define BUTTON_BORDER 2

// Initialize button with default skin and colors
void button_init(button_t *button, int x, int y, int width, int height, const char *text);

// Set button text
void button_set_text(button_t *button, const char *text);

// Set custom font (NULL for default)
void button_set_font(button_t *button, font_t *font);

// Set custom skin (NULL for default)
void button_set_skin(button_t *button, tga_image_t *skin);

// Set click callback
void button_set_callback(button_t *button, button_callback_t callback, void *user_data);

// Set hotkey (keyboard shortcut)
void button_set_hotkey(button_t *button, uint8_t key);

// Set custom tint colors
void button_set_tints(button_t *button, uint32_t normal, uint32_t hover, uint32_t pressed);

// Set custom text colors
void button_set_text_colors(button_t *button, uint32_t normal, uint32_t hover, uint32_t pressed);

// Handle mouse/key events - returns true if event was consumed
bool button_handle_event(button_t *button, const diff_event_t *event);

// Polymorphic methods
void button_update(window_component_t *self);
void button_paint(window_component_t *self);
