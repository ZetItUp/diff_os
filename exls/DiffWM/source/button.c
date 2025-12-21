// Button component implementation
#include <diffwm/button.h>
#include <diffwm/window.h>
#include <string.h>

// Default tint colors (matches window title bar colors from diffwm)
#define BUTTON_TINT_NORMAL   0xFF2A70FF   // color_rgb(42, 112, 255) - Same as TITLE_TINT_ACTIVE
#define BUTTON_TINT_PRESSED  0xFF3F3F74   // color_rgb(63, 63, 116) - Same as TITLE_TINT_INACTIVE
#define BUTTON_TINT_HOVER    0xFF488CFF   // color_rgb(72, 140, 255) - Lighter blue for hover

// Default text colors
#define BUTTON_TEXT_NORMAL   0xFFFFFFFF  // White
#define BUTTON_TEXT_HOVER    0xFFFFFFFF  // White
#define BUTTON_TEXT_PRESSED  0xFFB0B0B0  // Light gray

// Shared skin for all buttons (loaded once)
static tga_image_t *g_button_skin = NULL;
static font_t *g_button_font = NULL;

// Load default skin
static tga_image_t *button_default_skin(void)
{
    if (!g_button_skin)
    {
        g_button_skin = tga_load("/system/graphics/window.tga");
    }
    return g_button_skin;
}

// Load default font
static font_t *button_default_font(void)
{
    if (!g_button_font)
    {
        g_button_font = font_load_bdf("/system/fonts/spleen-8x16.bdf");
    }
    return g_button_font;
}

// Blend a skin pixel with alpha over background, then apply tint
static inline uint32_t blend_skin_px(uint32_t bg, uint32_t skin, uint32_t tint)
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
    uint32_t br = (bg >> 16) & 0xFF;
    uint32_t bgc = (bg >> 8) & 0xFF;
    uint32_t bb = bg & 0xFF;

    uint32_t r = (sr * alpha + br * inv) / 255;
    uint32_t g = (sg * alpha + bgc * inv) / 255;
    uint32_t b = (sb * alpha + bb * inv) / 255;

    return 0xFF000000 | (r << 16) | (g << 8) | b;
}

void button_init(button_t *button, int x, int y, int width, int height, const char *text)
{
    if (!button)
        return;

    window_component_init(&button->base, x, y, width, height);

    button->text = text ? text : "";
    button->font = NULL;  // Will use default
    button->state = BUTTON_STATE_NORMAL;
    button->skin = NULL;  // Will use default

    // Default colors
    button->tint_normal = BUTTON_TINT_NORMAL;
    button->tint_hover = BUTTON_TINT_HOVER;
    button->tint_pressed = BUTTON_TINT_PRESSED;

    button->text_color_normal = BUTTON_TEXT_NORMAL;
    button->text_color_hover = BUTTON_TEXT_HOVER;
    button->text_color_pressed = BUTTON_TEXT_PRESSED;

    button->on_click = NULL;
    button->user_data = NULL;
    button->hotkey = 0;

    button->mouse_inside = false;
    button->mouse_down = false;

    // Set component callbacks
    button->base.update = button_update;
    button->base.draw = button_paint;
}

void button_set_text(button_t *button, const char *text)
{
    if (button)
        button->text = text ? text : "";
}

void button_set_font(button_t *button, font_t *font)
{
    if (button)
        button->font = font;
}

void button_set_skin(button_t *button, tga_image_t *skin)
{
    if (button)
        button->skin = skin;
}

void button_set_callback(button_t *button, button_callback_t callback, void *user_data)
{
    if (button)
    {
        button->on_click = callback;
        button->user_data = user_data;
    }
}

void button_set_hotkey(button_t *button, uint8_t key)
{
    if (button)
        button->hotkey = key;
}

void button_set_tints(button_t *button, uint32_t normal, uint32_t hover, uint32_t pressed)
{
    if (button)
    {
        button->tint_normal = normal;
        button->tint_hover = hover;
        button->tint_pressed = pressed;
    }
}

void button_set_text_colors(button_t *button, uint32_t normal, uint32_t hover, uint32_t pressed)
{
    if (button)
    {
        button->text_color_normal = normal;
        button->text_color_hover = hover;
        button->text_color_pressed = pressed;
    }
}

bool button_handle_event(button_t *button, const diff_event_t *event)
{
    if (!button || !event || !button->base.enabled)
        return false;

    int bx = button->base.x;
    int by = button->base.y;
    int bw = button->base.width;
    int bh = button->base.height;

    if (event->type == DIFF_EVENT_MOUSE)
    {
        int mx = event->mouse_x;
        int my = event->mouse_y;
        bool left_down = (event->mouse_buttons & MOUSE_BTN_LEFT) != 0;

        bool inside = (mx >= bx && mx < bx + bw && my >= by && my < by + bh);

        switch (event->mouse_action)
        {
            case MOUSE_ACTION_MOVE:
            {
                bool was_inside = button->mouse_inside;
                button->mouse_inside = inside;

                if (left_down && button->mouse_down)
                {
                    button->state = inside ? BUTTON_STATE_PRESSED : BUTTON_STATE_NORMAL;
                    return true;
                }
                if (!left_down && button->mouse_down)
                {
                    button->mouse_down = false;
                    button->state = inside ? BUTTON_STATE_HOVER : BUTTON_STATE_NORMAL;
                    return true;
                }
                if (left_down && inside)
                {
                    // Ignore presses that started outside the button.
                    return true;
                }
                if (inside && !was_inside)
                {
                    // Mouse enter
                    if (!button->mouse_down)
                        button->state = BUTTON_STATE_HOVER;
                    return true;
                }
                if (!inside && was_inside)
                {
                    // Mouse leave
                    if (!button->mouse_down)
                        button->state = BUTTON_STATE_NORMAL;
                    return true;
                }
                break;
            }

            case MOUSE_ACTION_DOWN:
                if (inside && ((event->mouse_button & MOUSE_BTN_LEFT) || left_down))
                {
                    button->mouse_down = true;
                    button->state = BUTTON_STATE_PRESSED;
                    return true;
                }
                break;

            case MOUSE_ACTION_UP:
                if (button->mouse_down && ((event->mouse_button & MOUSE_BTN_LEFT) || !left_down))
                {
                    button->mouse_down = false;
                    if (inside)
                    {
                        button->state = BUTTON_STATE_HOVER;
                    }
                    else
                    {
                        button->state = BUTTON_STATE_NORMAL;
                        button->mouse_inside = false;
                    }
                    return true;
                }
                break;

            case MOUSE_ACTION_CLICK:
                if (inside && (event->mouse_button & MOUSE_BTN_LEFT))
                {
                    // Trigger callback
                    if (button->on_click)
                    {
                        button->on_click(button->user_data);
                    }
                    return true;
                }
                break;

            default:
                break;
        }
    }
    else if (event->type == DIFF_EVENT_KEY)
    {
        // Handle hotkey
        if (button->hotkey != 0 && event->key == button->hotkey && event->key_pressed)
        {
            // Trigger callback on hotkey press
            if (button->on_click)
            {
                button->on_click(button->user_data);
            }
            return true;
        }
    }

    return false;
}

void button_update(window_component_t *self)
{
    (void)self;
    // State is updated via events, nothing to do here
}

void button_paint(window_component_t *self)
{
    if (!self || !self->visible)
        return;

    button_t *button = (button_t *)self;
    window_t *parent = self->parent;

    if (!parent || !parent->backbuffer)
        return;

    // Get skin and font
    tga_image_t *skin = button->skin ? button->skin : button_default_skin();
    font_t *font = button->font ? button->font : button_default_font();

    if (!skin || !skin->pixels)
        return;

    // Get current tint and text color based on state
    uint32_t tint;
    uint32_t text_color;
    switch (button->state)
    {
        case BUTTON_STATE_HOVER:
            tint = button->tint_hover;
            text_color = button->text_color_hover;
            break;
        case BUTTON_STATE_PRESSED:
            tint = button->tint_pressed;
            text_color = button->text_color_pressed;
            break;
        default:
            tint = button->tint_normal;
            text_color = button->text_color_normal;
            break;
    }

    int btn_x = self->x;
    int btn_y = self->y;
    int btn_w = self->width;
    int btn_h = self->height;

    uint32_t *fb = parent->backbuffer;
    int fb_w = parent->base.width;
    int fb_h = parent->base.height;

    // Helper macro to access skin pixels
    int skin_w = (int)skin->width;
    #define SKIN(sx, sy) skin->pixels[(sy) * skin_w + (sx)]

    // Draw button using 9-slice technique (same as window title bar)
    // Border is 2 pixels

    // Clamp button to framebuffer bounds
    int x0 = btn_x < 0 ? 0 : btn_x;
    int y0 = btn_y < 0 ? 0 : btn_y;
    int x1 = btn_x + btn_w > fb_w ? fb_w : btn_x + btn_w;
    int y1 = btn_y + btn_h > fb_h ? fb_h : btn_y + btn_h;

    if (x1 <= x0 || y1 <= y0)
        return;

    // Draw corners (2x2 each)
    // Top-left corner from (0,0)
    for (int dy = 0; dy < 2; ++dy)
    {
        int ry = btn_y + dy;
        if (ry < 0 || ry >= fb_h) continue;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = btn_x + dx;
            if (rx >= 0 && rx < fb_w)
            {
                uint32_t bg = fb[ry * fb_w + rx];
                fb[ry * fb_w + rx] = blend_skin_px(bg, SKIN(dx, dy), tint);
            }
        }
    }

    // Top-right corner from (3,0)
    for (int dy = 0; dy < 2; ++dy)
    {
        int ry = btn_y + dy;
        if (ry < 0 || ry >= fb_h) continue;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = btn_x + btn_w - 2 + dx;
            if (rx >= 0 && rx < fb_w)
            {
                uint32_t bg = fb[ry * fb_w + rx];
                fb[ry * fb_w + rx] = blend_skin_px(bg, SKIN(3 + dx, dy), tint);
            }
        }
    }

    // Bottom-left corner from (0,2)
    for (int dy = 0; dy < 2; ++dy)
    {
        int ry = btn_y + btn_h - 2 + dy;
        if (ry < 0 || ry >= fb_h) continue;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = btn_x + dx;
            if (rx >= 0 && rx < fb_w)
            {
                uint32_t bg = fb[ry * fb_w + rx];
                fb[ry * fb_w + rx] = blend_skin_px(bg, SKIN(dx, 2 + dy), tint);
            }
        }
    }

    // Bottom-right corner from (3,2)
    for (int dy = 0; dy < 2; ++dy)
    {
        int ry = btn_y + btn_h - 2 + dy;
        if (ry < 0 || ry >= fb_h) continue;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = btn_x + btn_w - 2 + dx;
            if (rx >= 0 && rx < fb_w)
            {
                uint32_t bg = fb[ry * fb_w + rx];
                fb[ry * fb_w + rx] = blend_skin_px(bg, SKIN(3 + dx, 2 + dy), tint);
            }
        }
    }

    // Top edge (from x=2 to w-2)
    for (int dx = 2; dx < btn_w - 2; ++dx)
    {
        int rx = btn_x + dx;
        if (rx < 0 || rx >= fb_w) continue;
        for (int dy = 0; dy < 2; ++dy)
        {
            int ry = btn_y + dy;
            if (ry >= 0 && ry < fb_h)
            {
                uint32_t bg = fb[ry * fb_w + rx];
                fb[ry * fb_w + rx] = blend_skin_px(bg, SKIN(2, dy), tint);
            }
        }
    }

    // Bottom edge
    for (int dx = 2; dx < btn_w - 2; ++dx)
    {
        int rx = btn_x + dx;
        if (rx < 0 || rx >= fb_w) continue;
        for (int dy = 0; dy < 2; ++dy)
        {
            int ry = btn_y + btn_h - 2 + dy;
            if (ry >= 0 && ry < fb_h)
            {
                uint32_t bg = fb[ry * fb_w + rx];
                fb[ry * fb_w + rx] = blend_skin_px(bg, SKIN(2, 2 + dy), tint);
            }
        }
    }

    // Left edge
    for (int dy = 2; dy < btn_h - 2; ++dy)
    {
        int ry = btn_y + dy;
        if (ry < 0 || ry >= fb_h) continue;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = btn_x + dx;
            if (rx >= 0 && rx < fb_w)
            {
                uint32_t bg = fb[ry * fb_w + rx];
                fb[ry * fb_w + rx] = blend_skin_px(bg, SKIN(dx, 2), tint);
            }
        }
    }

    // Right edge
    for (int dy = 2; dy < btn_h - 2; ++dy)
    {
        int ry = btn_y + dy;
        if (ry < 0 || ry >= fb_h) continue;
        for (int dx = 0; dx < 2; ++dx)
        {
            int rx = btn_x + btn_w - 2 + dx;
            if (rx >= 0 && rx < fb_w)
            {
                uint32_t bg = fb[ry * fb_w + rx];
                fb[ry * fb_w + rx] = blend_skin_px(bg, SKIN(3 + dx, 2), tint);
            }
        }
    }

    // Center fill
    for (int dy = 2; dy < btn_h - 2; ++dy)
    {
        int ry = btn_y + dy;
        if (ry < 0 || ry >= fb_h) continue;
        for (int dx = 2; dx < btn_w - 2; ++dx)
        {
            int rx = btn_x + dx;
            if (rx >= 0 && rx < fb_w)
            {
                uint32_t bg = fb[ry * fb_w + rx];
                fb[ry * fb_w + rx] = blend_skin_px(bg, SKIN(2, 2), tint);
            }
        }
    }

    #undef SKIN

    // Draw centered text with clipping
    if (font && button->text && button->text[0] != '\0')
    {
        int fw = font_width(font);
        int fh = font_height(font);
        int ascent = font_ascent(font);
        int descent = font_descent(font);
        int text_len = (int)strlen(button->text);
        int text_w = text_len * fw;
        int has_metrics = (ascent > 0 || descent > 0);
        int text_h = has_metrics ? (ascent + descent) : fh;

        // Content area (inside border)
        int content_x = btn_x + BUTTON_BORDER;
        int content_y = btn_y + BUTTON_BORDER;
        int content_w = btn_w - BUTTON_BORDER * 2;
        int content_h = btn_h - BUTTON_BORDER * 2;

        if (content_w <= 0 || content_h <= 0)
            return;

        // Center text
        int text_x = content_x + (content_w - text_w) / 2;
        int text_y = content_y + (content_h - text_h) / 2 +
                     (has_metrics ? descent : 0);

        // Clip text to content area by only drawing visible characters
        int start_char = 0;
        int end_char = text_len;

        // Calculate which characters are visible
        if (text_x < content_x)
        {
            // Text starts before content area
            int skip = (content_x - text_x) / fw;
            start_char = skip;
            text_x += skip * fw;
        }

        int text_end_x = text_x + (end_char - start_char) * fw;
        if (text_end_x > content_x + content_w)
        {
            // Text extends past content area
            int visible_chars = (content_x + content_w - text_x) / fw;
            end_char = start_char + visible_chars;
        }

        // Draw visible portion of text
        if (end_char > start_char && text_y >= 0 && text_y + fh <= fb_h)
        {
            for (int i = start_char; i < end_char; i++)
            {
                int char_x = text_x + (i - start_char) * fw;
                if (char_x >= 0 && char_x + fw <= fb_w)
                {
                    char single[2] = { button->text[i], '\0' };
                    font_draw_text(font, fb, fb_w, char_x, text_y, single, text_color);
                }
            }
        }
    }
}
