#pragma once

#include <stdint.h>
#include <difftga.h>

// Cursor types supported by the theme system
typedef enum {
    CURSOR_NORMAL = 0,      // Default pointer
    CURSOR_RESIZE_H,        // Horizontal resize (left-right)
    CURSOR_RESIZE_V,        // Vertical resize (up-down)
    CURSOR_RESIZE_DIAG_L,   // Diagonal resize (top-left to bottom-right)
    CURSOR_RESIZE_DIAG_R,   // Diagonal resize (top-right to bottom-left)
    CURSOR_MOVE,            // Move/drag cursor
    CURSOR_TEXT,            // Text selection (I-beam)
    CURSOR_HAND,            // Hand/pointer for links
    CURSOR_WAIT,            // Busy/loading
    CURSOR_CROSSHAIR,       // Precision select
    CURSOR_COUNT            // Number of cursor types
} cursor_type_t;

// A single cursor definition
typedef struct {
    tga_image_t *image;     // Loaded TGA image (NULL if not loaded)
    int hotspot_x;          // X offset for the click point
    int hotspot_y;          // Y offset for the click point
} cursor_t;

// A complete mouse cursor theme
typedef struct {
    char name[64];                  // Theme name
    cursor_t cursors[CURSOR_COUNT]; // All cursor types
} cursor_theme_t;

// Load a theme from a .theme file
// Returns 0 on success, -1 on failure
int theme_load(cursor_theme_t *theme, const char *theme_path);

// Free all resources used by a theme
void theme_free(cursor_theme_t *theme);

// Get a cursor from the theme (returns NULL if not available)
const cursor_t *theme_get_cursor(const cursor_theme_t *theme, cursor_type_t type);
