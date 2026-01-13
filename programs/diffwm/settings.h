#pragma once

#include <stdint.h>
#include <diffgfx/draw.h>

// Icon selection tint color (light ocean blue)
// Applied when desktop icons are selected
#define ICON_TINT_SELECTED  0xFF7DC8F5  // RGB(125, 200, 245)

// Window button graphics paths
#define GFX_MINIMIZE            "/system/graphics/minimize.tga"
#define GFX_MINIMIZE_HOVER      "/system/graphics/minimize_hover.tga"
#define GFX_MINIMIZE_PRESSED    "/system/graphics/minimize_pressed.tga"

#define GFX_MAXIMIZE            "/system/graphics/maximize.tga"
#define GFX_MAXIMIZE_HOVER      "/system/graphics/maximize_hover.tga"
#define GFX_MAXIMIZE_PRESSED    "/system/graphics/maximize_pressed.tga"

#define GFX_CLOSE               "/system/graphics/close.tga"
#define GFX_CLOSE_HOVER         "/system/graphics/close_hover.tga"
#define GFX_CLOSE_PRESSED       "/system/graphics/close_pressed.tga"

#define desktop_background_color color_rgb(7, 0, 63)
// #define desktop_background_color color_rgb(69, 67, 117)
