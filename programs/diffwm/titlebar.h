#pragma once

#include <stdint.h>
#include <difftga.h>
#include <difffonts/fonts.h>
#include "wm_internal.h"

// Tint colors for active/inactive windows (ARGB format)
#define TITLE_TINT_ACTIVE   0xFF2A70FF  // Cornflower blue
#define TITLE_TINT_INACTIVE 0xFF3F3F74  // Gray
#define BODY_TINT_ACTIVE    0xFF4A4A8A  // Dark blue-purple
#define BODY_TINT_INACTIVE  0xFF3F3F74  // Dark gray

// Initialize the titlebar subsystem (loads skin and font)
void titlebar_init(void);

// Get the loaded window skin image
tga_image_t *titlebar_get_skin(void);

// Get the loaded title font
font_t *titlebar_get_font(void);

// Get the height of the titlebar in pixels
int titlebar_get_height(void);

// Titlebar button identifiers
#define TITLEBAR_BUTTON_NONE      0
#define TITLEBAR_BUTTON_MINIMIZE  1
#define TITLEBAR_BUTTON_MAXIMIZE  2
#define TITLEBAR_BUTTON_CLOSE     3

// Compute titlebar rectangle (including text padding and buttons)
int titlebar_get_title_rect(const wm_window_t *win, int screen_width, int screen_height,
                            int *out_x, int *out_y, int *out_w, int *out_h);

// Hit test a titlebar button at screen coordinates
int titlebar_hit_test_button(const wm_window_t *win, int screen_width, int screen_height,
                             int x, int y);

// Compute bounding box of a window including borders and titlebar
void titlebar_get_decor_bounds(const wm_window_t *win, int screen_width, int screen_height,
                               int *out_x, int *out_y, int *out_w, int *out_h);

// Draw the titlebar and window frame decorations
// Parameters:
//   win         - the window to decorate
//   backbuffer  - the destination buffer to draw to
//   stride      - pixels per row in backbuffer
//   screen_w/h  - screen dimensions for clipping
//   is_focused  - whether this window has focus
void titlebar_draw(const wm_window_t *win, uint32_t *backbuffer, uint32_t stride,
                   int screen_w, int screen_h, int is_focused);

// Blend helper: apply tint to a color (multiply blend)
uint32_t titlebar_blend_tint(uint32_t base, uint32_t tint);

// Blend a skin pixel with alpha over background, then apply tint
uint32_t titlebar_blend_skin_px(uint32_t bg, uint32_t skin, uint32_t tint);
