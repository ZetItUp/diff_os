// Menu bar component implementation
#include <diffwm/menu.h>
#include <diffwm/window.h>
#include <string.h>

// Default font for menu
static font_t *g_menu_font = NULL;

static font_t *menu_default_font(void)
{
    if (!g_menu_font)
    {
        g_menu_font = font_load_bdf("/system/fonts/spleen-8x16.bdf");
    }

    return g_menu_font;
}

// Called when mouse leaves the menubar component
static void menubar_on_mouse_leave(window_component_t *self)
{
    menubar_t *menubar = (menubar_t *)self;

    // Only clear hover if dropdown is not open
    if (!menubar->dropdown_open)
    {
        if (menubar->hover_menu != -1 || menubar->hover_item != -1)
        {
            menubar->hover_menu = -1;
            menubar->hover_item = -1;
            // Mark dirty so the change is visible
            if (menubar->base.parent)
            {
                window_mark_dirty(menubar->base.parent);
            }
        }
    }
}

void menubar_init(menubar_t *menubar, int x, int y, int width)
{
    if (!menubar)
    {
        return;
    }

    window_component_init(&menubar->base, x, y, width, MENUBAR_HEIGHT);

    menubar->menu_count = 0;
    menubar->open_menu = -1;
    menubar->hover_menu = -1;
    menubar->hover_item = -1;
    menubar->font = NULL;
    menubar->dropdown_open = false;

    for (int i = 0; i < MENUBAR_MAX_MENUS; i++)
    {
        menubar->menus[i].title = NULL;
        menubar->menus[i].item_count = 0;
    }

    menubar->base.update = menubar_update;
    menubar->base.draw = menubar_paint;
    window_component_set_mouse_callbacks(&menubar->base, NULL, menubar_on_mouse_leave);
}

int menubar_add_menu(menubar_t *menubar, const char *title)
{
    if (!menubar || !title || menubar->menu_count >= MENUBAR_MAX_MENUS)
    {
        return -1;
    }

    int index = menubar->menu_count;
    menubar->menus[index].title = title;
    menubar->menus[index].item_count = 0;
    menubar->menu_count++;

    return index;
}

int menu_add_item(menubar_t *menubar, int menu_index, const char *text,
                  menu_item_callback_t callback, void *user_data)
{
    if (!menubar || menu_index < 0 || menu_index >= menubar->menu_count)
    {
        return -1;
    }

    menu_t *menu = &menubar->menus[menu_index];

    if (menu->item_count >= MENU_MAX_ITEMS)
    {
        return -1;
    }

    int index = menu->item_count;
    menu->items[index].type = MENU_ITEM_TEXT;
    menu->items[index].text = text;
    menu->items[index].on_click = callback;
    menu->items[index].user_data = user_data;
    menu->items[index].enabled = true;
    menu->item_count++;

    return index;
}

int menu_add_separator(menubar_t *menubar, int menu_index)
{
    if (!menubar || menu_index < 0 || menu_index >= menubar->menu_count)
    {
        return -1;
    }

    menu_t *menu = &menubar->menus[menu_index];

    if (menu->item_count >= MENU_MAX_ITEMS)
    {
        return -1;
    }

    int index = menu->item_count;
    menu->items[index].type = MENU_ITEM_SEPARATOR;
    menu->items[index].text = NULL;
    menu->items[index].on_click = NULL;
    menu->items[index].user_data = NULL;
    menu->items[index].enabled = false;
    menu->item_count++;

    return index;
}

void menu_set_item_enabled(menubar_t *menubar, int menu_index, int item_index, bool enabled)
{
    if (!menubar || menu_index < 0 || menu_index >= menubar->menu_count)
    {
        return;
    }

    menu_t *menu = &menubar->menus[menu_index];

    if (item_index < 0 || item_index >= menu->item_count)
    {
        return;
    }

    menu->items[item_index].enabled = enabled;
}

void menubar_set_font(menubar_t *menubar, font_t *font)
{
    if (menubar)
    {
        menubar->font = font;
    }
}

void menubar_close(menubar_t *menubar)
{
    if (menubar)
    {
        menubar->open_menu = -1;
        menubar->hover_item = -1;
        menubar->dropdown_open = false;
    }
}

bool menubar_is_open(const menubar_t *menubar)
{
    return menubar && menubar->dropdown_open;
}

// Compute layout for menu titles in the bar
static void menubar_compute_layout(menubar_t *menubar, font_t *font)
{
    if (!menubar || !font)
    {
        return;
    }

    int fw = font_width(font);
    int x = menubar->base.x;

    for (int i = 0; i < menubar->menu_count; i++)
    {
        menu_t *menu = &menubar->menus[i];

        if (!menu->title)
        {
            continue;
        }

        int text_len = (int)strlen(menu->title);
        int title_width = text_len * fw + MENUBAR_ITEM_PADDING_X * 2;

        menu->title_x = x;
        menu->title_width = title_width;

        x += title_width;
    }
}

// Compute dropdown dimensions for a menu
static void menubar_compute_dropdown(menubar_t *menubar, int menu_index, font_t *font)
{
    if (!menubar || !font || menu_index < 0 || menu_index >= menubar->menu_count)
    {
        return;
    }

    menu_t *menu = &menubar->menus[menu_index];
    int fw = font_width(font);
    int fh = font_height(font);

    int max_width = 0;
    int total_height = 0;

    for (int i = 0; i < menu->item_count; i++)
    {
        if (menu->items[i].type == MENU_ITEM_SEPARATOR)
        {
            total_height += MENUBAR_SEPARATOR_HEIGHT;
        }
        else
        {
            int text_len = menu->items[i].text ? (int)strlen(menu->items[i].text) : 0;
            int item_width = text_len * fw + MENUBAR_ITEM_PADDING_X * 2;

            if (item_width > max_width)
            {
                max_width = item_width;
            }

            total_height += fh + MENUBAR_ITEM_PADDING_Y * 2;
        }
    }

    // Apply minimum width
    if (max_width < MENUBAR_DROPDOWN_MIN_WIDTH)
    {
        max_width = MENUBAR_DROPDOWN_MIN_WIDTH;
    }

    // Add space for 3D border (2 pixels each side)
    menu->dropdown_x = menu->title_x;
    menu->dropdown_y = menubar->base.y + menubar->base.height;
    menu->dropdown_width = max_width + 4;
    menu->dropdown_height = total_height + 4;
}

// Hit test which menu title is at position
static int menubar_hit_test_title(menubar_t *menubar, int x, int y)
{
    if (!menubar)
    {
        return -1;
    }

    if (y < menubar->base.y || y >= menubar->base.y + menubar->base.height)
    {
        return -1;
    }

    for (int i = 0; i < menubar->menu_count; i++)
    {
        menu_t *menu = &menubar->menus[i];

        if (x >= menu->title_x && x < menu->title_x + menu->title_width)
        {
            return i;
        }
    }

    return -1;
}

// Hit test which item in the dropdown is at position
static int menubar_hit_test_item(menubar_t *menubar, int menu_index, int x, int y, font_t *font)
{
    if (!menubar || !font || menu_index < 0 || menu_index >= menubar->menu_count)
    {
        return -1;
    }

    menu_t *menu = &menubar->menus[menu_index];

    // Check if inside dropdown bounds
    if (x < menu->dropdown_x || x >= menu->dropdown_x + menu->dropdown_width ||
        y < menu->dropdown_y || y >= menu->dropdown_y + menu->dropdown_height)
    {
        return -1;
    }

    int fh = font_height(font);
    int item_y = menu->dropdown_y + 2;

    for (int i = 0; i < menu->item_count; i++)
    {
        int item_height;

        if (menu->items[i].type == MENU_ITEM_SEPARATOR)
        {
            item_height = MENUBAR_SEPARATOR_HEIGHT;
        }
        else
        {
            item_height = fh + MENUBAR_ITEM_PADDING_Y * 2;
        }

        if (y >= item_y && y < item_y + item_height)
        {
            // Only return text items, not separators
            if (menu->items[i].type == MENU_ITEM_TEXT)
            {
                return i;
            }

            return -1;
        }

        item_y += item_height;
    }

    return -1;
}

// Helper to mark parent window dirty
static void menubar_mark_dirty(menubar_t *menubar)
{
    if (menubar && menubar->base.parent)
    {
        window_mark_dirty(menubar->base.parent);
    }
}

bool menubar_handle_event(menubar_t *menubar, const diff_event_t *event)
{
    if (!menubar || !event || !menubar->base.enabled)
    {
        return false;
    }

    font_t *font = menubar->font ? menubar->font : menu_default_font();

    if (!font)
    {
        return false;
    }

    menubar_compute_layout(menubar, font);

    if (event->type == DIFF_EVENT_MOUSE)
    {
        int mx = event->mouse_x;
        int my = event->mouse_y;

        // Check if mouse is in menubar area
        bool in_bar = (mx >= menubar->base.x &&
                       mx < menubar->base.x + menubar->base.width &&
                       my >= menubar->base.y &&
                       my < menubar->base.y + menubar->base.height);

        // Check if mouse is in open dropdown
        bool in_dropdown = false;

        if (menubar->dropdown_open && menubar->open_menu >= 0)
        {
            menu_t *open = &menubar->menus[menubar->open_menu];

            in_dropdown = (mx >= open->dropdown_x &&
                          mx < open->dropdown_x + open->dropdown_width &&
                          my >= open->dropdown_y &&
                          my < open->dropdown_y + open->dropdown_height);
        }

        switch (event->mouse_action)
        {
            case MOUSE_ACTION_MOVE:
            {
                // Use base class mouse tracking (fires on_mouse_leave callback)
                bool mouse_changed = window_component_update_mouse(&menubar->base, mx, my);

                // Track previous state to detect actual changes
                int prev_hover_menu = menubar->hover_menu;
                int prev_hover_item = menubar->hover_item;
                int prev_open_menu = menubar->open_menu;

                if (in_bar)
                {
                    int title_hit = menubar_hit_test_title(menubar, mx, my);
                    menubar->hover_menu = title_hit;

                    // If dropdown is open and we hover a different menu, switch to it
                    if (menubar->dropdown_open && title_hit >= 0 && title_hit != menubar->open_menu)
                    {
                        menubar->open_menu = title_hit;
                        menubar_compute_dropdown(menubar, title_hit, font);
                        menubar->hover_item = -1;
                    }

                    // Only mark dirty if state changed
                    if (menubar->hover_menu != prev_hover_menu ||
                        menubar->open_menu != prev_open_menu)
                    {
                        menubar_mark_dirty(menubar);
                    }
                    return true;
                }
                else if (in_dropdown)
                {
                    // Clear menu bar hover when in dropdown
                    menubar->hover_menu = -1;
                    menubar->hover_item = menubar_hit_test_item(menubar, menubar->open_menu, mx, my, font);

                    // Only mark dirty if hover item changed
                    if (menubar->hover_item != prev_hover_item ||
                        menubar->hover_menu != prev_hover_menu)
                    {
                        menubar_mark_dirty(menubar);
                    }
                    return true;
                }
                else if (menubar->dropdown_open)
                {
                    // Mouse outside but dropdown open - clear all hovers
                    menubar->hover_menu = -1;
                    menubar->hover_item = -1;

                    if (prev_hover_menu != -1 || prev_hover_item != -1)
                    {
                        menubar_mark_dirty(menubar);
                    }
                    return true;
                }
                else if (mouse_changed)
                {
                    // Mouse left the menubar - callback already cleared hover
                    if (prev_hover_menu != -1)
                    {
                        menubar_mark_dirty(menubar);
                    }
                    return true;
                }

                break;
            }

            case MOUSE_ACTION_DOWN:
            {
                // Mouse down on menu title opens the dropdown
                if (in_bar)
                {
                    int title_hit = menubar_hit_test_title(menubar, mx, my);

                    if (title_hit >= 0)
                    {
                        if (menubar->dropdown_open && menubar->open_menu == title_hit)
                        {
                            // Clicking same menu closes it
                            menubar_close(menubar);
                        }
                        else
                        {
                            // Open the clicked menu
                            menubar->open_menu = title_hit;
                            menubar->dropdown_open = true;
                            menubar_compute_dropdown(menubar, title_hit, font);
                            menubar->hover_item = -1;
                        }

                        menubar_mark_dirty(menubar);
                        return true;
                    }
                }
                else if (!in_bar && !in_dropdown && menubar->dropdown_open)
                {
                    // Click outside closes dropdown
                    menubar_close(menubar);

                    menubar_mark_dirty(menubar);
                    return true;
                }

                break;
            }

            case MOUSE_ACTION_CLICK:
            {
                // Click on item triggers callback
                if (in_dropdown)
                {
                    int item_hit = menubar_hit_test_item(menubar, menubar->open_menu, mx, my, font);

                    if (item_hit >= 0)
                    {
                        menu_t *menu = &menubar->menus[menubar->open_menu];
                        menu_item_t *item = &menu->items[item_hit];

                        if (item->enabled && item->on_click)
                        {
                            item->on_click(item->user_data);
                        }

                        menubar_close(menubar);

                        menubar_mark_dirty(menubar);
                        return true;
                    }
                }

                break;
            }

            default:
                break;
        }
    }

    return false;
}

void menubar_update(window_component_t *self)
{
    (void)self;
}

// Draw a horizontal line
static void draw_hline(uint32_t *fb, int fb_w, int fb_h, int x, int y, int width, uint32_t color)
{
    if (y < 0 || y >= fb_h)
    {
        return;
    }

    int x0 = x < 0 ? 0 : x;
    int x1 = x + width > fb_w ? fb_w : x + width;

    if (x1 <= x0)
    {
        return;
    }

    uint32_t *row = fb + (size_t)y * fb_w + x0;

    for (int i = 0; i < x1 - x0; i++)
    {
        row[i] = color;
    }
}

// Draw a vertical line
static void draw_vline(uint32_t *fb, int fb_w, int fb_h, int x, int y, int height, uint32_t color)
{
    if (x < 0 || x >= fb_w)
    {
        return;
    }

    int y0 = y < 0 ? 0 : y;
    int y1 = y + height > fb_h ? fb_h : y + height;

    if (y1 <= y0)
    {
        return;
    }

    for (int i = y0; i < y1; i++)
    {
        fb[(size_t)i * fb_w + x] = color;
    }
}

// Fill a rectangle
static void fill_rect(uint32_t *fb, int fb_w, int fb_h, int x, int y, int w, int h, uint32_t color)
{
    int x0 = x < 0 ? 0 : x;
    int y0 = y < 0 ? 0 : y;
    int x1 = x + w > fb_w ? fb_w : x + w;
    int y1 = y + h > fb_h ? fb_h : y + h;

    if (x1 <= x0 || y1 <= y0)
    {
        return;
    }

    for (int row = y0; row < y1; row++)
    {
        uint32_t *dst = fb + (size_t)row * fb_w + x0;

        for (int col = 0; col < x1 - x0; col++)
        {
            dst[col] = color;
        }
    }
}

// Draw 3D raised border (light on top/left, dark on bottom/right)
static void draw_3d_border_raised(uint32_t *fb, int fb_w, int fb_h,
                                  int x, int y, int w, int h)
{
    // Outer light (top and left)
    draw_hline(fb, fb_w, fb_h, x, y, w, MENUBAR_BORDER_LIGHT);
    draw_vline(fb, fb_w, fb_h, x, y, h, MENUBAR_BORDER_LIGHT);

    // Outer dark (bottom and right)
    draw_hline(fb, fb_w, fb_h, x, y + h - 1, w, MENUBAR_BORDER_DARK);
    draw_vline(fb, fb_w, fb_h, x + w - 1, y, h, MENUBAR_BORDER_DARK);

    // Inner light (second line from top/left)
    draw_hline(fb, fb_w, fb_h, x + 1, y + 1, w - 2, MENUBAR_BORDER_LIGHT);
    draw_vline(fb, fb_w, fb_h, x + 1, y + 1, h - 2, MENUBAR_BORDER_LIGHT);

    // Inner dark (second line from bottom/right)
    draw_hline(fb, fb_w, fb_h, x + 1, y + h - 2, w - 2, MENUBAR_BORDER_MID);
    draw_vline(fb, fb_w, fb_h, x + w - 2, y + 1, h - 2, MENUBAR_BORDER_MID);
}

void menubar_paint(window_component_t *self)
{
    if (!self || !self->visible)
    {
        return;
    }

    menubar_t *menubar = (menubar_t *)self;
    window_t *parent = self->parent;

    if (!parent || !parent->backbuffer)
    {
        return;
    }

    font_t *font = menubar->font ? menubar->font : menu_default_font();

    if (!font)
    {
        return;
    }

    uint32_t *fb = parent->backbuffer;
    int fb_w = parent->base.width;
    int fb_h = parent->base.height;
    int fh = font_height(font);

    // Compute layout
    menubar_compute_layout(menubar, font);

    // Draw menubar background
    fill_rect(fb, fb_w, fb_h, self->x, self->y, self->width, self->height, MENUBAR_BG_COLOR);

    // Draw 3D shadow at bottom of menubar
    draw_hline(fb, fb_w, fb_h, self->x, self->y + self->height - 2, self->width, MENUBAR_BORDER_MID);
    draw_hline(fb, fb_w, fb_h, self->x, self->y + self->height - 1, self->width, MENUBAR_BORDER_DARK);

    // Draw menu titles
    for (int i = 0; i < menubar->menu_count; i++)
    {
        menu_t *menu = &menubar->menus[i];

        if (!menu->title)
        {
            continue;
        }

        bool is_hover = (i == menubar->hover_menu);
        bool is_open = (menubar->dropdown_open && i == menubar->open_menu);

        // Highlight background if hovered or open
        if (is_hover || is_open)
        {
            fill_rect(fb, fb_w, fb_h,
                      menu->title_x, self->y,
                      menu->title_width, self->height,
                      MENUBAR_HOVER_COLOR);
        }

        // Draw title text
        int text_x = menu->title_x + MENUBAR_ITEM_PADDING_X;
        int text_y = self->y + (self->height - fh) / 2 + 4;
        uint32_t text_color = (is_hover || is_open) ? MENUBAR_HOVER_TEXT : MENUBAR_TEXT_COLOR;

        font_draw_text(font, fb, fb_w, text_x, text_y, menu->title, text_color);
    }

    // Draw open dropdown
    if (menubar->dropdown_open && menubar->open_menu >= 0)
    {
        menu_t *menu = &menubar->menus[menubar->open_menu];
        menubar_compute_dropdown(menubar, menubar->open_menu, font);

        int dx = menu->dropdown_x;
        int dy = menu->dropdown_y;
        int dw = menu->dropdown_width;
        int dh = menu->dropdown_height;

        // Fill dropdown background
        fill_rect(fb, fb_w, fb_h, dx, dy, dw, dh, MENUBAR_BG_COLOR);

        // Draw 3D raised border
        draw_3d_border_raised(fb, fb_w, fb_h, dx, dy, dw, dh);

        // Draw menu items
        int item_y = dy + 2;

        for (int i = 0; i < menu->item_count; i++)
        {
            menu_item_t *item = &menu->items[i];

            if (item->type == MENU_ITEM_SEPARATOR)
            {
                // Draw 3D separator line (shadow on top, light below)
                int sep_x = dx + 4;
                int sep_w = dw - 8;
                int sep_y = item_y + MENUBAR_SEPARATOR_HEIGHT / 2 - 1;

                draw_hline(fb, fb_w, fb_h, sep_x, sep_y, sep_w, MENUBAR_BORDER_MID);
                draw_hline(fb, fb_w, fb_h, sep_x, sep_y + 1, sep_w, MENUBAR_BORDER_LIGHT);

                item_y += MENUBAR_SEPARATOR_HEIGHT;
            }
            else
            {
                int item_height = fh + MENUBAR_ITEM_PADDING_Y * 2;
                bool is_hover = (i == menubar->hover_item);

                // Highlight background if hovered
                if (is_hover && item->enabled)
                {
                    fill_rect(fb, fb_w, fb_h,
                              dx + 2, item_y,
                              dw - 4, item_height,
                              MENUBAR_HOVER_COLOR);
                }

                // Draw item text
                int text_x = dx + MENUBAR_ITEM_PADDING_X + 2;
                int text_y = item_y + (item_height - fh) / 2 + 4;
                uint32_t text_color;

                if (!item->enabled)
                {
                    text_color = MENUBAR_DISABLED_TEXT;
                }
                else if (is_hover)
                {
                    text_color = MENUBAR_HOVER_TEXT;
                }
                else
                {
                    text_color = MENUBAR_TEXT_COLOR;
                }

                if (item->text)
                {
                    font_draw_text(font, fb, fb_w, text_x, text_y, item->text, text_color);
                }

                item_y += item_height;
            }
        }
    }
}
