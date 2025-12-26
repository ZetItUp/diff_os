#include "titlebar.h"
#include "settings.h"
#include <string.h>
#include <diffgfx/graphics.h>
#include <diffwm/protocol.h>

// Window skin and title font (static to this module)
static tga_image_t *g_window_skin = NULL;
static font_t *g_title_font = NULL;
static tga_image_t *g_btn_minimize = NULL;
static tga_image_t *g_btn_minimize_hover = NULL;
static tga_image_t *g_btn_minimize_pressed = NULL;
static tga_image_t *g_btn_maximize = NULL;
static tga_image_t *g_btn_maximize_hover = NULL;
static tga_image_t *g_btn_maximize_pressed = NULL;
static tga_image_t *g_btn_close = NULL;
static tga_image_t *g_btn_close_hover = NULL;
static tga_image_t *g_btn_close_pressed = NULL;

#define TITLEBAR_TEXT_BUTTON_PADDING 15

void titlebar_init(void)
{
    // Load window skin
    g_window_skin = tga_load("/system/graphics/window.tga");

    // Load title font (try multiple sizes)
    g_title_font = font_load_bdf("/system/fonts/spleen-8x16.bdf");
    if (!g_title_font)
    {
        g_title_font = font_load_bdf("/system/fonts/spleen-6x12.bdf");
    }
    if (!g_title_font)
    {
        g_title_font = font_load_bdf("/system/fonts/spleen-5x8.bdf");
    }

    // Load button graphics
    g_btn_minimize = tga_load(GFX_MINIMIZE);
    g_btn_minimize_hover = tga_load(GFX_MINIMIZE_HOVER);
    g_btn_minimize_pressed = tga_load(GFX_MINIMIZE_PRESSED);
    g_btn_maximize = tga_load(GFX_MAXIMIZE);
    g_btn_maximize_hover = tga_load(GFX_MAXIMIZE_HOVER);
    g_btn_maximize_pressed = tga_load(GFX_MAXIMIZE_PRESSED);
    g_btn_close = tga_load(GFX_CLOSE);
    g_btn_close_hover = tga_load(GFX_CLOSE_HOVER);
    g_btn_close_pressed = tga_load(GFX_CLOSE_PRESSED);
}

tga_image_t *titlebar_get_skin(void)
{
    return g_window_skin;
}

font_t *titlebar_get_font(void)
{
    return g_title_font;
}

int titlebar_get_height(void)
{
    if (!g_title_font)
    {
        return 0;
    }
    return font_height(g_title_font) + TITLE_PADDING_Y + 4;
}

static int titlebar_window_has_minimize(const wm_window_t *win)
{
    if (!win) return 0;
    return (win->flags & WINDOW_NO_MINIMIZE) == 0;
}

static int titlebar_window_has_maximize(const wm_window_t *win)
{
    if (!win) return 0;
    return (win->flags & WINDOW_NO_MAXIMIZE) == 0;
}

static void titlebar_add_button(const tga_image_t *img,
                                int x, int y, int max_buttons,
                                int *button_count, int *out_total_w,
                                int *out_x,
                                int *out_y, int *out_w, int *out_h)
{
    if (!img || !img->pixels || !button_count || !out_total_w)
    {
        return;
    }

    if (*button_count < max_buttons && out_x && out_y && out_w && out_h)
    {
        out_x[*button_count] = x;
        out_y[*button_count] = y;
        out_w[*button_count] = (int)img->width;
        out_h[*button_count] = (int)img->height;
    }

    *out_total_w += (int)img->width;
    (*button_count)++;
}

static int titlebar_compute_layout(const wm_window_t *win, int screen_width, int screen_height,
                                   int *out_title_x, int *out_title_y, int *out_title_w, int *out_title_h,
                                   int *out_text_x, int *out_text_w,
                                   int *out_button_types, int *out_button_x,
                                   int *out_button_y, int *out_button_w, int *out_button_h,
                                   int max_buttons, int *out_button_count)
{
    if (!win || !g_title_font)
    {
        return 0;
    }

    (void)screen_height;

    int fw = font_width(g_title_font);
    int fh = font_height(g_title_font);
    int text_w = (int)strlen(win->title) * fw;
    int title_h = fh + TITLE_PADDING_Y + 4;

    int button_total_w = 0;
    int button_count = 0;

    if (titlebar_window_has_minimize(win))
    {
        titlebar_add_button(g_btn_minimize,
                            0, 0, max_buttons, &button_count,
                            &button_total_w,
                            out_button_x, out_button_y, out_button_w, out_button_h);
    }
    if (titlebar_window_has_maximize(win))
    {
        titlebar_add_button(g_btn_maximize,
                            0, 0, max_buttons, &button_count,
                            &button_total_w,
                            out_button_x, out_button_y, out_button_w, out_button_h);
    }
    titlebar_add_button(g_btn_close,
                        0, 0, max_buttons, &button_count,
                        &button_total_w,
                        out_button_x, out_button_y, out_button_w, out_button_h);

    int title_w = text_w + TITLE_PADDING_X;
    if (button_total_w > 0)
    {
        title_w += TITLEBAR_TEXT_BUTTON_PADDING + button_total_w + 2;
    }

    int title_x = win->x;
    if (title_x + title_w > screen_width)
    {
        title_x = screen_width - title_w;
        if (title_x < 0) title_x = 0;
    }

    int title_y = win->y - title_h;
    if (title_y < 0) title_y = 0;

    int text_x = title_x + (TITLE_PADDING_X / 2) + 4;
    int button_x = text_x + text_w + TITLEBAR_TEXT_BUTTON_PADDING;

    for (int i = 0; i < button_count && i < max_buttons; ++i)
    {
        int bw = out_button_w ? out_button_w[i] : 0;
        int bh = out_button_h ? out_button_h[i] : 0;
        if (out_button_x) out_button_x[i] = button_x;
        if (out_button_y) out_button_y[i] = title_y + (title_h - bh) / 2;
        button_x += bw;
    }

    if (out_title_x) *out_title_x = title_x;
    if (out_title_y) *out_title_y = title_y;
    if (out_title_w) *out_title_w = title_w;
    if (out_title_h) *out_title_h = title_h;
    if (out_text_x) *out_text_x = text_x;
    if (out_text_w) *out_text_w = text_w;
    if (out_button_types)
    {
        int type_index = 0;
        if (titlebar_window_has_minimize(win) && g_btn_minimize && g_btn_minimize->pixels)
        {
            out_button_types[type_index++] = TITLEBAR_BUTTON_MINIMIZE;
        }
        if (titlebar_window_has_maximize(win) && g_btn_maximize && g_btn_maximize->pixels)
        {
            out_button_types[type_index++] = TITLEBAR_BUTTON_MAXIMIZE;
        }
        if (g_btn_close && g_btn_close->pixels)
        {
            out_button_types[type_index++] = TITLEBAR_BUTTON_CLOSE;
        }
    }

    if (out_button_count)
    {
        *out_button_count = button_count;
    }

    return 1;
}

int titlebar_get_title_rect(const wm_window_t *win, int screen_width, int screen_height,
                            int *out_x, int *out_y, int *out_w, int *out_h)
{
    return titlebar_compute_layout(win, screen_width, screen_height,
                                   out_x, out_y, out_w, out_h,
                                   NULL, NULL,
                                   NULL, NULL, NULL, NULL, NULL, 0, NULL);
}

int titlebar_hit_test_button(const wm_window_t *win, int screen_width, int screen_height,
                             int x, int y)
{
    int button_types[3] = {0};
    int button_x[3] = {0};
    int button_y[3] = {0};
    int button_w[3] = {0};
    int button_h[3] = {0};

    int count = 0;
    if (!titlebar_compute_layout(win, screen_width, screen_height,
                                 NULL, NULL, NULL, NULL,
                                 NULL, NULL,
                                 button_types, button_x, button_y, button_w, button_h, 3, &count))
    {
        return TITLEBAR_BUTTON_NONE;
    }

    for (int i = 0; i < count && i < 3; ++i)
    {
        if (x >= button_x[i] && x < button_x[i] + button_w[i] &&
            y >= button_y[i] && y < button_y[i] + button_h[i])
        {
            return button_types[i];
        }
    }

    return TITLEBAR_BUTTON_NONE;
}

// Blend helper: apply tint to a color (multiply blend)
uint32_t titlebar_blend_tint(uint32_t base, uint32_t tint)
{
    uint32_t br = (base >> 16) & 0xFF;
    uint32_t bg = (base >> 8) & 0xFF;
    uint32_t bb = base & 0xFF;

    uint32_t tr = (tint >> 16) & 0xFF;
    uint32_t tg = (tint >> 8) & 0xFF;
    uint32_t tb = tint & 0xFF;

    // Multiply blend
    uint32_t r = (br * tr) / 255;
    uint32_t g = (bg * tg) / 255;
    uint32_t b = (bb * tb) / 255;

    return 0xFF000000 | (r << 16) | (g << 8) | b;
}

// Blend a skin pixel with alpha over background, then apply tint
uint32_t titlebar_blend_skin_px(uint32_t bg, uint32_t skin, uint32_t tint)
{
    uint32_t alpha = (skin >> 24) & 0xFF;
    if (alpha == 0) return bg;

    // Extract skin RGB
    uint32_t sr = (skin >> 16) & 0xFF;
    uint32_t sg = (skin >> 8) & 0xFF;
    uint32_t sb = skin & 0xFF;

    // Apply tint to skin
    uint32_t tr = (tint >> 16) & 0xFF;
    uint32_t tg = (tint >> 8) & 0xFF;
    uint32_t tb = tint & 0xFF;
    sr = (sr * tr) / 255;
    sg = (sg * tg) / 255;
    sb = (sb * tb) / 255;

    if (alpha == 0xFF)
    {
        return 0xFF000000 | (sr << 16) | (sg << 8) | sb;
    }

    // Alpha blend over background
    uint32_t inv = 255 - alpha;
    uint32_t bgr = (bg >> 16) & 0xFF;
    uint32_t bgg = (bg >> 8) & 0xFF;
    uint32_t bgb = bg & 0xFF;

    uint32_t r = (sr * alpha + bgr * inv) / 255;
    uint32_t g = (sg * alpha + bgg * inv) / 255;
    uint32_t b = (sb * alpha + bgb * inv) / 255;

    return 0xFF000000 | (r << 16) | (g << 8) | b;
}

void titlebar_get_decor_bounds(const wm_window_t *win, int screen_width, int screen_height,
                               int *out_x, int *out_y, int *out_w, int *out_h)
{
    (void)screen_height;  // Reserved for future use
    if (!win || !out_x || !out_y || !out_w || !out_h) return;

    const int border = 2;

    int min_x = win->x - border;
    int min_y = win->y - border;
    int max_x = win->x + (int)win->width + border;
    int max_y = win->y + (int)win->height + border;

    if (g_window_skin && g_window_skin->pixels && g_title_font)
    {
        int title_x = 0;
        int title_y = 0;
        int title_w = 0;
        int title_h = 0;
        if (titlebar_get_title_rect(win, screen_width, screen_height,
                                    &title_x, &title_y, &title_w, &title_h))
        {
            if (title_x < min_x) min_x = title_x;
            if (title_y < min_y) min_y = title_y;
            if (title_x + title_w > max_x) max_x = title_x + title_w;
            if (title_y + title_h > max_y) max_y = title_y + title_h;
        }
    }

    *out_x = min_x;
    *out_y = min_y;
    *out_w = max_x - min_x;
    *out_h = max_y - min_y;
}

void titlebar_draw(const wm_window_t *win, uint32_t *backbuffer, uint32_t stride,
                   int screen_w, int screen_h, int is_focused)
{
    if (!win || !backbuffer) return;
    if (!g_window_skin || !g_window_skin->pixels || !g_title_font) return;

    int x0 = win->x;
    int y0 = win->y;
    int max_x = (x0 + (int)win->width > screen_w) ? (screen_w - x0) : (int)win->width;
    int max_y = (y0 + (int)win->height > screen_h) ? (screen_h - y0) : (int)win->height;

    if (max_x <= 0 || max_y <= 0) return;

    uint32_t title_tint = is_focused ? TITLE_TINT_ACTIVE : TITLE_TINT_INACTIVE;
    uint32_t body_tint = is_focused ? BODY_TINT_ACTIVE : BODY_TINT_INACTIVE;

    int title_x = 0;
    int title_y = 0;
    int title_w = 0;
    int title_h = 0;
    int text_x = 0;
    int text_w = 0;
    int button_types[3] = {0};
    int button_x[3] = {0};
    int button_y[3] = {0};
    int button_w[3] = {0};
    int button_h[3] = {0};
    int button_count = 0;
    if (!titlebar_compute_layout(win, screen_w, screen_h,
                                 &title_x, &title_y, &title_w, &title_h,
                                 &text_x, &text_w,
                                 button_types, button_x, button_y, button_w, button_h, 3, &button_count))
    {
        return;
    }

    // Helpers to sample from skin
    const uint32_t *skin = g_window_skin->pixels;
    int skin_w = (int)g_window_skin->width;
    #define SKIN(sx,sy) skin[(sy) * skin_w + (sx)]

    // Draw title bar using slices
    // Top-left 2x2 corner from (0,0)
    for (int dy = 0; dy < 2; ++dy)
    {
        int ry = title_y + dy;
        if (ry < 0 || ry >= screen_h) continue;
        uint32_t *row = backbuffer + (size_t)ry * stride;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = title_x + dx;
            if (rx >= 0 && rx < screen_w)
            {
                row[rx] = titlebar_blend_skin_px(row[rx], SKIN(dx, dy), title_tint);
            }
        }
        // Top-right 2x2 corner from (3,0)
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = title_x + title_w - 2 + dx;
            if (rx >= 0 && rx < screen_w)
            {
                row[rx] = titlebar_blend_skin_px(row[rx], SKIN(3 + dx, dy), title_tint);
            }
        }
    }

    // Bottom corners of title bar from (0,2) and (3,2)
    for (int dy = 0; dy < 2; ++dy)
    {
        int ry = title_y + title_h - 2 + dy;
        if (ry < 0 || ry >= screen_h) continue;
        uint32_t *row = backbuffer + (size_t)ry * stride;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = title_x + dx;
            if (rx >= 0 && rx < screen_w)
                row[rx] = titlebar_blend_skin_px(row[rx], SKIN(dx, 2 + dy), title_tint);
            int rxr = title_x + title_w - 2 + dx;
            if (rxr >= 0 && rxr < screen_w)
                row[rxr] = titlebar_blend_skin_px(row[rxr], SKIN(3 + dx, 2 + dy), title_tint);
        }
    }

    // Top/bottom edges of title bar
    for (int dx = 2; dx < title_w - 2; ++dx)
    {
        int rx = title_x + dx;
        if (rx < 0 || rx >= screen_w) continue;
        for (int dy = 0; dy < 2; ++dy)
        {
            int ry = title_y + dy;
            if (ry >= 0 && ry < screen_h)
                backbuffer[(size_t)ry * stride + rx] =
                    titlebar_blend_skin_px(backbuffer[(size_t)ry * stride + rx],
                                           SKIN(2, dy), title_tint);
            int ryb = title_y + title_h - 2 + dy;
            if (ryb >= 0 && ryb < screen_h)
                backbuffer[(size_t)ryb * stride + rx] =
                    titlebar_blend_skin_px(backbuffer[(size_t)ryb * stride + rx],
                                           SKIN(2, 2 + dy), title_tint);
        }
    }

    // Left/right edges of title bar
    for (int dy = 2; dy < title_h - 2; ++dy)
    {
        int ry = title_y + dy;
        if (ry < 0 || ry >= screen_h) continue;
        uint32_t *row = backbuffer + (size_t)ry * stride;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = title_x + dx;
            if (rx >= 0 && rx < screen_w)
                row[rx] = titlebar_blend_skin_px(row[rx], SKIN(dx, 2), title_tint);
            int rxr = title_x + title_w - 2 + dx;
            if (rxr >= 0 && rxr < screen_w)
                row[rxr] = titlebar_blend_skin_px(row[rxr], SKIN(3 + dx, 2), title_tint);
        }
    }

    // Title bar fill
    for (int dy = 2; dy < title_h - 2; ++dy)
    {
        int ry = title_y + dy;
        if (ry < 0 || ry >= screen_h) continue;
        uint32_t *row = backbuffer + (size_t)ry * stride;
        for (int dx = 2; dx < title_w - 2; ++dx)
        {
            int rx = title_x + dx;
            if (rx >= 0 && rx < screen_w)
            {
                row[rx] = titlebar_blend_skin_px(row[rx], SKIN(2, 2), title_tint);
            }
        }
    }

    // Draw title text
    int text_y = title_y + ((title_h - font_height(g_title_font)) / 2) + 4;
    font_draw_text(g_title_font,
                   backbuffer,
                   stride,
                   text_x,
                   text_y,
                   win->title,
                   is_focused ? 0xFFFFFFFF : 0xFFB0B0B0);

    // Draw titlebar buttons
    for (int i = 0; i < button_count && i < 3; ++i)
    {
        const tga_image_t *img = NULL;
        const tga_image_t *img_hover = NULL;
        const tga_image_t *img_pressed = NULL;
        if (button_types[i] == TITLEBAR_BUTTON_MINIMIZE)
        {
            img = g_btn_minimize;
            img_hover = g_btn_minimize_hover;
            img_pressed = g_btn_minimize_pressed;
        }
        else if (button_types[i] == TITLEBAR_BUTTON_MAXIMIZE)
        {
            img = g_btn_maximize;
            img_hover = g_btn_maximize_hover;
            img_pressed = g_btn_maximize_pressed;
        }
        else if (button_types[i] == TITLEBAR_BUTTON_CLOSE)
        {
            img = g_btn_close;
            img_hover = g_btn_close_hover;
            img_pressed = g_btn_close_pressed;
        }

        if (!img || !img->pixels)
        {
            continue;
        }

        int hovered = (win->titlebar_hover_button == button_types[i]);
        int pressed = (win->titlebar_pressed_button == button_types[i]) && hovered;
        const tga_image_t *use_img = img;
        if (pressed && img_pressed)
        {
            use_img = img_pressed;
        }
        else if (hovered && img_hover)
        {
            use_img = img_hover;
        }

        // Draw with alpha blend
        int img_w = (int)use_img->width;
        int img_h = (int)use_img->height;
        int dst_x = button_x[i];
        int dst_y = button_y[i];
        int x0b = dst_x;
        int y0b = dst_y;
        int x1b = dst_x + img_w;
        int y1b = dst_y + img_h;

        if (x0b < 0) x0b = 0;
        if (y0b < 0) y0b = 0;
        if (x1b > screen_w) x1b = screen_w;
        if (y1b > screen_h) y1b = screen_h;

        int draw_w = x1b - x0b;
        int draw_h = y1b - y0b;
        if (draw_w <= 0 || draw_h <= 0)
        {
            continue;
        }

        int src_x = x0b - dst_x;
        int src_y = y0b - dst_y;

        for (int y = 0; y < draw_h; ++y)
        {
            uint32_t *dst = backbuffer + (size_t)(y0b + y) * stride + x0b;
            uint32_t *src = use_img->pixels + (size_t)(src_y + y) * img_w + src_x;

            for (int x = 0; x < draw_w; ++x)
            {
                uint32_t pixel = src[x];
                uint8_t alpha = (pixel >> 24) & 0xFF;

                if (alpha == 0xFF)
                {
                    dst[x] = pixel;
                }
                else if (alpha > 0)
                {
                    uint32_t bg = dst[x];
                    uint32_t inv = 255 - alpha;

                    uint32_t r = (((pixel >> 16) & 0xFF) * alpha + ((bg >> 16) & 0xFF) * inv) / 255;
                    uint32_t g = (((pixel >> 8) & 0xFF) * alpha + ((bg >> 8) & 0xFF) * inv) / 255;
                    uint32_t b = ((pixel & 0xFF) * alpha + (bg & 0xFF) * inv) / 255;

                    dst[x] = 0xFF000000 | (r << 16) | (g << 8) | b;
                }
            }
        }
    }

    // Body frame using skin slices - draw OUTSIDE the window content
    int body_x = x0 - 2;
    int body_y = y0 - 2;
    int body_w = max_x + 4;
    int body_h = max_y + 4;

    // Body corners from (0,4), (3,4), (0,6), (3,6)
    for (int dy = 0; dy < 2; ++dy)
    {
        int ry = body_y + dy;
        if (ry >= 0 && ry < screen_h)
        {
            uint32_t *row = backbuffer + (size_t)ry * stride;
            for (int dx = 0; dx < 2; ++dx)
            {
                int rx = body_x + dx;
                if (rx >= 0 && rx < screen_w)
                    row[rx] = titlebar_blend_skin_px(row[rx], SKIN(dx, 4 + dy), body_tint);
                int rxr = body_x + body_w - 2 + dx;
                if (rxr >= 0 && rxr < screen_w)
                    row[rxr] = titlebar_blend_skin_px(row[rxr], SKIN(3 + dx, 4 + dy), body_tint);
            }
        }
    }
    for (int dy = 0; dy < 2; ++dy)
    {
        int ry = body_y + body_h - 2 + dy;
        if (ry >= 0 && ry < screen_h)
        {
            uint32_t *row = backbuffer + (size_t)ry * stride;
            for (int dx = 0; dx < 2; ++dx)
            {
                int rx = body_x + dx;
                if (rx >= 0 && rx < screen_w)
                    row[rx] = titlebar_blend_skin_px(row[rx], SKIN(dx, 6 + dy), body_tint);
                int rxr = body_x + body_w - 2 + dx;
                if (rxr >= 0 && rxr < screen_w)
                    row[rxr] = titlebar_blend_skin_px(row[rxr], SKIN(3 + dx, 6 + dy), body_tint);
            }
        }
    }

    // Top/bottom edges of body
    for (int dx = 2; dx < body_w - 2; ++dx)
    {
        int rx = body_x + dx;
        if (rx < 0 || rx >= screen_w) continue;
        if (body_y >= 0)
            backbuffer[(size_t)body_y * stride + rx] =
                titlebar_blend_skin_px(backbuffer[(size_t)body_y * stride + rx],
                                       SKIN(2, 4), body_tint);
        if (body_y + 1 < screen_h)
            backbuffer[(size_t)(body_y + 1) * stride + rx] =
                titlebar_blend_skin_px(backbuffer[(size_t)(body_y + 1) * stride + rx],
                                       SKIN(2, 5), body_tint);
        int by = body_y + body_h - 2;
        if (by >= 0 && by < screen_h)
            backbuffer[(size_t)by * stride + rx] =
                titlebar_blend_skin_px(backbuffer[(size_t)by * stride + rx],
                                       SKIN(2, 6), body_tint);
        if (by + 1 >= 0 && by + 1 < screen_h)
            backbuffer[(size_t)(by + 1) * stride + rx] =
                titlebar_blend_skin_px(backbuffer[(size_t)(by + 1) * stride + rx],
                                       SKIN(2, 7), body_tint);
    }

    // Left/right edges of body
    for (int dy = 2; dy < body_h - 2; ++dy)
    {
        int ry = body_y + dy;
        if (ry < 0 || ry >= screen_h) continue;
        uint32_t *row = backbuffer + (size_t)ry * stride;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = body_x + dx;
            if (rx >= 0 && rx < screen_w)
                row[rx] = titlebar_blend_skin_px(row[rx], SKIN(dx, 6), body_tint);
            int rxr = body_x + body_w - 2 + dx;
            if (rxr >= 0 && rxr < screen_w)
                row[rxr] = titlebar_blend_skin_px(row[rxr], SKIN(3 + dx, 6), body_tint);
        }
    }

    #undef SKIN
}
