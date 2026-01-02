#include <diffwm/textbox.h>
#include <diffwm/window.h>
#include <diffwm/window_component.h>
#include <diffgfx/draw.h>
#include <string.h>
#include <time.h>

typedef struct textbox_blink_state_t
{
    textbox_t *box;
    uint64_t blink_start_ms;
    bool last_on;
    bool last_focused;
} textbox_blink_state_t;

static textbox_blink_state_t g_textbox_blink_states[32];

static textbox_blink_state_t *textbox_blink_state(textbox_t *box, bool create)
{
    if (!box)
    {
        return NULL;
    }

    for (size_t i = 0; i < sizeof(g_textbox_blink_states) / sizeof(g_textbox_blink_states[0]); i++)
    {
        if (g_textbox_blink_states[i].box == box)
        {
            return &g_textbox_blink_states[i];
        }
    }

    if (!create)
    {
        return NULL;
    }

    for (size_t i = 0; i < sizeof(g_textbox_blink_states) / sizeof(g_textbox_blink_states[0]); i++)
    {
        if (!g_textbox_blink_states[i].box)
        {
            g_textbox_blink_states[i].box = box;
            g_textbox_blink_states[i].blink_start_ms = 0;
            g_textbox_blink_states[i].last_on = true;
            g_textbox_blink_states[i].last_focused = false;
            return &g_textbox_blink_states[i];
        }
    }

    return NULL;
}

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
    box->scroll_x = 0;
    box->font = font;
    box->focused = false;
    box->multiline = false;

    // Default colors (white bg, black fg)
    box->bg_color = 0xFFFFFFFF;
    box->fg_color = 0xFF000000;
    box->selection_color = 0xFF3366CC;
    box->border_color = 0xFF202020;

    // Initialize selection
    text_selection_init(&box->selection);

    // Set polymorphic function pointers
    box->base.update = textbox_update;
    box->base.draw = textbox_paint;
    (void)textbox_blink_state(box, true);
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

void textbox_set_text(textbox_t *box, const char *text)
{
    if (!box || !box->text || box->max_length <= 0)
        return;

    const char *src = text ? text : "";
    size_t max_copy = (size_t)box->max_length - 1;
    size_t len = strlen(src);
    if (len > max_copy)
        len = max_copy;

    memcpy(box->text, src, len);
    box->text[len] = '\0';
    box->cursor_pos = (int)len;
    box->scroll_x = 0;
}

void textbox_set_multiline(textbox_t *box, bool multiline)
{
    if (!box)
        return;

    box->multiline = multiline ? true : false;
}

const char* textbox_get_text(textbox_t *box)
{
    if (!box)
        return NULL;

    return box->text;
}

static void textbox_ensure_cursor_visible(textbox_t *box, int visible_width, int fw)
{
    if (!box || fw <= 0 || visible_width <= 0)
        return;

    int cursor_px = box->cursor_pos * fw;
    if (cursor_px < box->scroll_x)
    {
        box->scroll_x = cursor_px;
    }
    else if (cursor_px >= box->scroll_x + visible_width)
    {
        box->scroll_x = cursor_px - visible_width + fw;
    }

    if (box->scroll_x < 0)
        box->scroll_x = 0;

    box->scroll_x = (box->scroll_x / fw) * fw;
}

static int textbox_text_padding_x(const textbox_t *box)
{
    (void)box;
    return 4;
}

static int textbox_text_padding_y(const textbox_t *box)
{
    (void)box;
    return 2;
}

static void fill_rect(uint32_t *pixels, int pitch, int x, int y, int w, int h, uint32_t color)
{
    if (!pixels || w <= 0 || h <= 0)
        return;

    for (int ry = 0; ry < h; ++ry)
    {
        uint32_t *row = pixels + (size_t)(y + ry) * pitch + x;
        for (int rx = 0; rx < w; ++rx)
        {
            row[rx] = color;
        }
    }
}

static void draw_rect(uint32_t *pixels, int pitch, int x, int y, int w, int h, uint32_t color)
{
    if (!pixels || w <= 0 || h <= 0)
        return;

    for (int rx = 0; rx < w; ++rx)
    {
        pixels[(size_t)y * pitch + x + rx] = color;
        pixels[(size_t)(y + h - 1) * pitch + x + rx] = color;
    }

    for (int ry = 0; ry < h; ++ry)
    {
        pixels[(size_t)(y + ry) * pitch + x] = color;
        pixels[(size_t)(y + ry) * pitch + x + w - 1] = color;
    }
}

static void draw_vline(uint32_t *pixels, int pitch, int x, int y, int h, uint32_t color)
{
    if (!pixels || h <= 0)
        return;

    for (int ry = 0; ry < h; ++ry)
    {
        pixels[(size_t)(y + ry) * pitch + x] = color;
    }
}

static font_t *textbox_default_font(void)
{
    static font_t *font = NULL;
    if (!font)
    {
        font = font_load_bdf("/system/fonts/spleen-6x12.bdf");
    }
    return font;
}

bool textbox_handle_event(textbox_t *box, const diff_event_t *event)
{
    if (!box || !event || !box->base.enabled)
        return false;

    int bx = box->base.x;
    int by = box->base.y;
    int bw = box->base.width;
    int bh = box->base.height;

    if (event->type == DIFF_EVENT_MOUSE)
    {
        int mx = event->mouse_x;
        int my = event->mouse_y;
        bool inside = (mx >= bx && mx < bx + bw && my >= by && my < by + bh);

        if (event->mouse_action == MOUSE_ACTION_DOWN && (event->mouse_button & MOUSE_BTN_LEFT))
        {
            box->focused = inside;
            if (inside && box->text && box->font)
            {
                int padding_x = textbox_text_padding_x(box);
                int fw = font_width(box->font);
                int text_x = bx + padding_x;
                int rel = mx - text_x + box->scroll_x;
                int len = (int)strlen(box->text);
                int pos = (fw > 0) ? (rel / fw) : 0;
                if (pos < 0) pos = 0;
                if (pos > len) pos = len;
                box->cursor_pos = pos;
            }
            return inside;  // Only consume if click was inside textbox
        }
        return inside;
    }

    if (event->type == DIFF_EVENT_FOCUS_LOST)
    {
        box->focused = false;
        return false;
    }

    if (event->type == DIFF_EVENT_KEY && box->focused && event->key_pressed)
    {
        uint8_t key = event->key;
        if (key == 0xac)
        {
            textbox_move_cursor(box, -1);
            return true;
        }
        if (key == 0xae)
        {
            textbox_move_cursor(box, 1);
            return true;
        }
        if (key == 8 || key == 127)
        {
            textbox_delete_char(box);
            return true;
        }
        if (key == '\n' || key == '\r')
        {
            if (box->multiline)
            {
                textbox_insert_char(box, '\n');
                return true;
            }
            return false;
        }
        if (key >= 32 && key < 127)
        {
            textbox_insert_char(box, (char)key);
            return true;
        }
        return false;
    }

    return false;
}

void textbox_update(window_component_t *self)
{
    if (!self)
    {
        return;
    }

    textbox_t *box = (textbox_t *)self;
    window_t *parent = self->parent;
    if (!parent)
    {
        return;
    }

    textbox_blink_state_t *state = textbox_blink_state(box, true);
    if (!state)
    {
        return;
    }

    uint64_t now = monotonic_ms();
    bool focused = box->focused;

    if (focused != state->last_focused)
    {
        state->last_focused = focused;
        state->blink_start_ms = now;
        state->last_on = focused;
        window_paint(&parent->base);
        return;
    }

    if (focused)
    {
        bool on = (((now - state->blink_start_ms) / 1000) % 2) == 0;
        if (on != state->last_on)
        {
            state->last_on = on;
            window_paint(&parent->base);
        }
    }
}

void textbox_paint(window_component_t *self)
{
    textbox_t *box = (textbox_t*)self;

    if (!self->visible || !box->text)
        return;

    window_t *parent = self->parent;
    if (!parent || !parent->backbuffer)
        return;

    if (!box->font)
    {
        box->font = textbox_default_font();
    }

    if (!box->font)
        return;

    uint32_t *pixels = parent->backbuffer;
    int pitch = parent->base.width;

    int x = self->x;
    int y = self->y;
    int w = self->width;
    int h = self->height;
    int max_w = parent->base.width;
    int max_h = parent->base.height;

    if (w <= 0 || h <= 0 || max_w <= 0 || max_h <= 0)
        return;

    // Clamp to parent bounds.
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > max_w) w = max_w - x;
    if (y + h > max_h) h = max_h - y;
    if (w <= 0 || h <= 0)
        return;

    // Clear background
    fill_rect(pixels, pitch, x, y, w, h, box->bg_color);

    // Render text
    int padding_x = textbox_text_padding_x(box);
    int padding_y = textbox_text_padding_y(box);
    int text_x = x + padding_x + 1;
    int text_y = y + padding_y + 1;
    int content_w = w - 2 - padding_x * 2;
    int content_h = h - 2 - padding_y * 2;
    if (content_w <= 0 || content_h <= 0)
        return;

    int single_ascent = 0;
    int single_descent = 0;
    int single_text_h = 0;
    int single_text_top = 0;
    if (!box->multiline)
    {
        int fh = font_height(box->font);
        int ascent = font_ascent(box->font);
        int descent = font_descent(box->font);
        int has_metrics = (ascent > 0 || descent > 0);
        int text_h = has_metrics ? (ascent + descent) : fh;
        int baseline = y + 1 + (h - 2 - text_h) / 2 + (has_metrics ? descent : 0);
        text_y = baseline;
        single_ascent = has_metrics ? ascent : 0;
        single_descent = has_metrics ? descent : 0;
        single_text_h = text_h;
        single_text_top = baseline - (has_metrics ? ascent : 0);
    }

    if (!box->multiline)
    {
        int fw = font_width(box->font);
        int fh = font_height(box->font);
        int len = (int)strlen(box->text);
        int visible_width = content_w;

        textbox_ensure_cursor_visible(box, visible_width, fw);

        int start_char = (fw > 0) ? (box->scroll_x / fw) : 0;
        int max_chars = (fw > 0) ? (visible_width / fw) + 1 : len;
        int end_char = start_char + max_chars;
        if (end_char > len) end_char = len;

        int draw_x = text_x;
        for (int i = start_char; i < end_char; ++i)
        {
            char buf[2] = { box->text[i], '\0' };
            font_draw_text(box->font, pixels, pitch, draw_x, text_y, buf, box->fg_color);
            draw_x += fw;
            if (draw_x >= x + w - 1)
                break;
        }
    }
    else
    {
        int fw = font_width(box->font);
        int fh = font_height(box->font);
        int cur_x = text_x;
        int cur_y = text_y;
        int max_x = x + w - 1;
        int max_y = y + h - 1;

        const char *p = box->text ? box->text : "";
        for (; *p; ++p)
        {
            if (*p == '\n')
            {
                cur_x = text_x;
                cur_y += fh;
                if (cur_y + fh > max_y)
                    break;
                continue;
            }
            if (cur_x + fw > max_x)
            {
                continue;
            }
            if (cur_y + fh > max_y)
            {
                break;
            }
            char buf[2] = { *p, '\0' };
            font_draw_text(box->font, pixels, pitch, cur_x, cur_y, buf, box->fg_color);
            cur_x += fw;
        }
    }

    // Render blinking cursor (single vertical line)
    if (box->focused)
    {
        textbox_blink_state_t *state = textbox_blink_state(box, false);
        bool draw_cursor = true;
        if (state)
        {
            draw_cursor = state->last_on;
        }

        if (draw_cursor)
        {
            int fw = font_width(box->font);
            int fh = font_height(box->font);
            int cursor_x = text_x + box->cursor_pos * fw - box->scroll_x;
            int cursor_y = text_y - (single_descent > 0 ? single_descent : 0);
            int cursor_h = single_text_h > 0 ? single_text_h : fh;
            if (cursor_x >= x + 1 && cursor_x < x + w - 1 && !box->multiline)
            {
                draw_vline(pixels, pitch, cursor_x, cursor_y, cursor_h, box->fg_color);
            }
        }
    }

    // Draw border (1px)
    draw_rect(pixels, pitch, x, y, w, h, box->border_color);
}
