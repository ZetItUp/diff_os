#include <diffwm/terminal_component.h>
#include <diffwm/window_component.h>
#include <diffwm/window.h>
#include <string.h>

#include <stdbool.h>

static int terminal_max_visible_lines(const terminal_component_t *term, int fh, int height)
{
    int usable = height - 8; // leave top padding
    int max_visible_lines = usable / fh;
    if (max_visible_lines < 1) max_visible_lines = 1;
    if (max_visible_lines > TERM_MAX_LINES) max_visible_lines = TERM_MAX_LINES;
    return max_visible_lines;
}

static void ensure_line(terminal_component_t *term, int y)
{
    if (!term)
        return;

    while (term->line_count <= y)
    {
        if (term->line_count >= TERM_MAX_LINES)
        {
            // Scroll up
            for (int i = 0; i < TERM_MAX_LINES - 1; i++)
            {
                term->lines[i] = term->lines[i + 1];
            }
            term->line_count = TERM_MAX_LINES - 1;
        }

        term->lines[term->line_count].len = 0;
        term->lines[term->line_count].text[0] = '\0';
        term->line_count++;
    }
}

static void putc_at(terminal_component_t *term, int x, int y, char c, term_color_t color)
{
    if (!term)
        return;

    if (y < 0 || y >= TERM_MAX_LINES || x < 0 || x >= TERM_MAX_COLS)
        return;

    ensure_line(term, y);

    if (x >= term->lines[y].len)
    {
        // Extend line
        for (int i = term->lines[y].len; i < x; i++)
        {
            term->lines[y].text[i] = ' ';
            term->lines[y].colors[i] = color;
        }
        term->lines[y].len = x + 1;
    }

    term->lines[y].text[x] = c;
    term->lines[y].colors[x] = color;
    term->lines[y].text[term->lines[y].len] = '\0';
}

static void terminal_scroll_buffer(terminal_component_t *term, int lines)
{
    if (!term || lines <= 0)
    {
        return;
    }

    if (lines >= TERM_MAX_LINES)
    {
        lines = TERM_MAX_LINES - 1;
    }

    int remaining = TERM_MAX_LINES - lines;
    for (int i = 0; i < remaining; i++)
    {
        term->lines[i] = term->lines[i + lines];
    }

    for (int i = remaining; i < TERM_MAX_LINES; i++)
    {
        term->lines[i].len = 0;
        term->lines[i].text[0] = '\0';
    }

    term->line_count = remaining;
}

void terminal_component_init(terminal_component_t *term, int x, int y, int width, int height, font_t *font)
{
    if (!term)
        return;

    // Initialize base component
    window_component_init(&term->base, x, y, width, height);

    // Initialize terminal state
    term->line_count = 0;
    term->cursor_x = 0;
    term->cursor_y = 0;
    term->font = font;

    // Default colors (light blue on black - matching gdterm)
    term->default_color.r = 203;
    term->default_color.g = 219;
    term->default_color.b = 252;
    term->default_color.a = 255;

    term->current_color = term->default_color;

    term->bg_color.r = 0;
    term->bg_color.g = 0;
    term->bg_color.b = 0;
    term->bg_color.a = 255;

    term->selection_color = 0xFF3366CC;

    term->view_offset = 0;

    // Initialize ANSI escape sequence state
    term->esc_state = 0;
    term->esc_len = 0;

    // Initialize selection
    text_selection_init(&term->selection);

    // Set polymorphic function pointers
    term->base.update = terminal_component_update;
    term->base.draw = terminal_component_paint;
}

// ANSI color code to RGB conversion
// Standard colors (30-37, 40-47) and bright colors (90-97, 100-107)
static term_color_t ansi_to_rgb(int code, term_color_t default_color)
{
    // Standard ANSI color palette
    static const term_color_t colors[16] = {
        {0, 0, 0, 255},         // 0: Black
        {170, 0, 0, 255},       // 1: Red
        {0, 170, 0, 255},       // 2: Green
        {170, 85, 0, 255},      // 3: Yellow/Brown
        {0, 0, 170, 255},       // 4: Blue
        {170, 0, 170, 255},     // 5: Magenta
        {0, 170, 170, 255},     // 6: Cyan
        {170, 170, 170, 255},   // 7: White/Light Gray
        {85, 85, 85, 255},      // 8: Bright Black/Dark Gray
        {255, 85, 85, 255},     // 9: Bright Red
        {85, 255, 85, 255},     // 10: Bright Green
        {255, 255, 85, 255},    // 11: Bright Yellow
        {85, 85, 255, 255},     // 12: Bright Blue
        {255, 85, 255, 255},    // 13: Bright Magenta
        {85, 255, 255, 255},    // 14: Bright Cyan
        {255, 255, 255, 255},   // 15: Bright White
    };

    int index = -1;

    // Foreground colors
    if (code >= 30 && code <= 37)
        index = code - 30;
    else if (code >= 90 && code <= 97)
        index = code - 90 + 8;
    // Background colors
    else if (code >= 40 && code <= 47)
        index = code - 40;
    else if (code >= 100 && code <= 107)
        index = code - 100 + 8;

    if (index >= 0 && index < 16)
        return colors[index];

    // Default to the terminal's default color
    return default_color;
}

// Parse and apply ANSI escape sequence
static void terminal_apply_ansi(terminal_component_t *term)
{
    term->esc_buf[term->esc_len] = '\0';

    // Empty sequence (ESC[m) means reset
    if (term->esc_len == 0)
    {
        term->current_color = term->default_color;
        return;
    }

    // Parse CSI parameters (e.g., "32;40" for green fg, black bg)
    int params[8] = {0};
    int param_count = 0;
    char *p = term->esc_buf;

    while (*p && param_count < 8)
    {
        if (*p >= '0' && *p <= '9')
        {
            params[param_count] = 0;
            while (*p >= '0' && *p <= '9')
            {
                params[param_count] = params[param_count] * 10 + (*p - '0');
                p++;
            }
            param_count++;
        }
        if (*p == ';')
            p++;
        else
            break;
    }

    // No params also means reset
    if (param_count == 0)
    {
        term->current_color = term->default_color;
        return;
    }

    // Apply color codes
    for (int i = 0; i < param_count; i++)
    {
        int code = params[i];

        if (code == 0)
        {
            // Reset to default color
            term->current_color = term->default_color;
            term->bg_color = (term_color_t){0, 0, 0, 255};
        }
        else if (code == 39)
        {
            // Default foreground color
            term->current_color = term->default_color;
        }
        else if (code == 49)
        {
            // Default background color
            term->bg_color = (term_color_t){0, 0, 0, 255};
        }
        else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97))
        {
            // Foreground color
            term->current_color = ansi_to_rgb(code, term->default_color);
        }
        else if ((code >= 40 && code <= 47) || (code >= 100 && code <= 107))
        {
            // Background color (stored but not currently used per-char)
            term->bg_color = ansi_to_rgb(code, term->default_color);
        }
    }
}

void terminal_putchar(terminal_component_t *term, char c)
{
    if (!term)
        return;

    // ANSI escape sequence state machine
    if (term->esc_state == 1)
    {
        // After ESC, expect '['
        if (c == '[')
        {
            term->esc_state = 2;
            term->esc_len = 0;
            return;
        }
        // Not a CSI sequence, output ESC and continue
        term->esc_state = 0;
    }
    else if (term->esc_state == 2)
    {
        // Inside CSI sequence, collect until we hit a letter
        if (c >= 0x40 && c <= 0x7E)
        {
            // End of sequence
            if (c == 'm')
            {
                // SGR (Select Graphic Rendition) - colors
                terminal_apply_ansi(term);
            }
            // Other commands (cursor movement, etc.) can be added here
            term->esc_state = 0;
            return;
        }
        else if (term->esc_len < 15)
        {
            term->esc_buf[term->esc_len++] = c;
            return;
        }
        else
        {
            // Buffer overflow, abort sequence
            term->esc_state = 0;
        }
    }

    // Check for ESC character
    if (c == '\033')
    {
        term->esc_state = 1;
        return;
    }

    if (c == '\n')
    {
        term->cursor_y++;
        term->cursor_x = 0;
        if (term->cursor_y >= TERM_MAX_LINES)
        {
            terminal_scroll_buffer(term, 1);
            term->cursor_y = TERM_MAX_LINES - 1;
        }
        ensure_line(term, term->cursor_y);
        term->view_offset = 0; // auto-scroll to bottom on new line
        return;
    }

    if (c == '\r')
    {
        term->cursor_x = 0;
        return;
    }

    putc_at(term, term->cursor_x, term->cursor_y, c, term->current_color);
    term->cursor_x++;
    term->view_offset = 0; // auto-scroll to bottom on new text

    if (term->cursor_x >= TERM_MAX_COLS)
    {
        term->cursor_x = 0;
        term->cursor_y++;
        if (term->cursor_y >= TERM_MAX_LINES)
        {
            terminal_scroll_buffer(term, 1);
            term->cursor_y = TERM_MAX_LINES - 1;
        }
        ensure_line(term, term->cursor_y);
    }
}

void terminal_puts(terminal_component_t *term, const char *s)
{
    if (!term || !s)
        return;

    while (*s)
    {
        terminal_putchar(term, *s++);
    }
}

void terminal_set_color(terminal_component_t *term, term_color_t color)
{
    if (!term)
        return;

    term->current_color = color;
}

void terminal_set_default_color(terminal_component_t *term, term_color_t color)
{
    if (!term)
        return;

    term->default_color = color;
    term->current_color = color;
}

void terminal_clear(terminal_component_t *term)
{
    if (!term)
        return;

    term->line_count = 0;
    term->cursor_x = 0;
    term->cursor_y = 0;
    term->view_offset = 0;
    text_selection_clear(&term->selection);
}

void terminal_backspace(terminal_component_t *term)
{
    if (!term)
        return;

    if (term->cursor_x > 0)
    {
        term->cursor_x--;

        // Ensure line exists
        ensure_line(term, term->cursor_y);

        // Replace character with space
        if (term->cursor_x < term->lines[term->cursor_y].len)
        {
            term->lines[term->cursor_y].text[term->cursor_x] = ' ';
            term->lines[term->cursor_y].colors[term->cursor_x] = term->current_color;

            // If we're backspacing the last character, shrink the line
            if (term->cursor_x == term->lines[term->cursor_y].len - 1)
            {
                // Trim trailing spaces
                while (term->lines[term->cursor_y].len > 0 &&
                       term->lines[term->cursor_y].text[term->lines[term->cursor_y].len - 1] == ' ')
                {
                    term->lines[term->cursor_y].len--;
                }
                term->lines[term->cursor_y].text[term->lines[term->cursor_y].len] = '\0';
            }
        }
    }

    term->view_offset = 0;
}

void terminal_component_update(window_component_t *self)
{
    // No update logic needed for now
    (void)self;
}

void terminal_component_paint(window_component_t *self)
{
    if (!self)
    {
        return;
    }

    terminal_component_t *term = (terminal_component_t *)self;
    window_t *parent = self->parent;

    if (!parent || !parent->backbuffer)
    {
        return;
    }

    terminal_component_render(term, parent->backbuffer, parent->base.width);
}

// Fast 32-bit memset for terminal
static void term_memset32(uint32_t *dst, uint32_t val, size_t count)
{
    while (count >= 8)
    {
        dst[0] = val; dst[1] = val; dst[2] = val; dst[3] = val;
        dst[4] = val; dst[5] = val; dst[6] = val; dst[7] = val;
        dst += 8;
        count -= 8;
    }
    while (count--)
    {
        *dst++ = val;
    }
}

void terminal_component_render(terminal_component_t *term, uint32_t *pixels, int pitch_pixels)
{
    if (!term || !pixels || !term->font)
        return;

    int width = term->base.width;
    int height = term->base.height;
    int origin_x = term->base.x;
    int origin_y = term->base.y;
    int fh = font_height(term->font);
    int fw = font_width(term->font);
    int max_visible_lines = terminal_max_visible_lines(term, fh, height);

    // Clamp view_offset to available history
    if (term->view_offset < 0) term->view_offset = 0;
    int max_scroll = (term->line_count > max_visible_lines) ? (term->line_count - max_visible_lines) : 0;
    if (term->view_offset > max_scroll) term->view_offset = max_scroll;

    // Clear background to bg_color (fast path)
    uint32_t bg = (term->bg_color.a << 24) | (term->bg_color.r << 16) |
                  (term->bg_color.g << 8) | term->bg_color.b;

    for (int y = 0; y < height; y++)
    {
        uint32_t *row = pixels + (size_t)(origin_y + y) * pitch_pixels + origin_x;
        term_memset32(row, bg, (size_t)width);
    }

    // Render selection highlight (if any)
    // text_render_selection(pixels, pitch_pixels, width, height,
    //                      &term->selection, 8, 8, term->font, term->selection_color);

    // Render text lines
    int start_line = 0;
    if (term->line_count > max_visible_lines)
    {
        start_line = term->line_count - max_visible_lines - term->view_offset;
        if (start_line < 0) start_line = 0;
    }

    int y_pos = origin_y + 8;
    for (int i = start_line; i < term->line_count && i < TERM_MAX_LINES; i++)
    {
        int x_pos = origin_x + 8;
        for (int j = 0; j < term->lines[i].len && j < TERM_MAX_COLS; j++)
        {
            term_color_t fg = term->lines[i].colors[j];
            uint32_t fg_color = (fg.a << 24) | (fg.r << 16) | (fg.g << 8) | fg.b;
            char buf[2] = {term->lines[i].text[j], '\0'};
            font_draw_text(term->font, pixels, pitch_pixels, x_pos, y_pos, buf, fg_color);
            x_pos += fw;
        }
        y_pos += fh;
        if (y_pos >= origin_y + height - fh)
            break;
    }

    // Draw cursor as underscore
    if (term->cursor_y >= start_line && term->cursor_y < term->line_count)
    {
        int cursor_screen_y = origin_y + 8 + (term->cursor_y - start_line) * fh;
        int cursor_screen_x = origin_x + 8 + term->cursor_x * fw;

        if (cursor_screen_y < origin_y + height - fh)
        {
            for (int x = 0; x < fw - 1; x++)
            {
                int px = cursor_screen_x + x;
                int py = cursor_screen_y + fh - 5;
                if (px < origin_x + width && py < origin_y + height)
                {
                    uint32_t cursor_color = (term->current_color.a << 24) |
                                           (term->current_color.r << 16) |
                                           (term->current_color.g << 8) |
                                           term->current_color.b;
                    pixels[py * pitch_pixels + px] = cursor_color;
                }
            }
        }
    }
}

void terminal_scroll(terminal_component_t *term, int delta_lines)
{
    if (!term || !term->font)
        return;

    int fh = font_height(term->font);
    int max_visible_lines = terminal_max_visible_lines(term, fh, term->base.height);
    int max_scroll = (term->line_count > max_visible_lines) ? (term->line_count - max_visible_lines) : 0;

    term->view_offset += delta_lines;
    if (term->view_offset < 0) term->view_offset = 0;
    if (term->view_offset > max_scroll) term->view_offset = max_scroll;
}

void terminal_scroll_to_bottom(terminal_component_t *term)
{
    if (!term)
        return;
    term->view_offset = 0;
}
