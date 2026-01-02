#pragma once

#include <diffwm/window_component.h>
#include <diffwm/protocol.h>
#include <difffonts/fonts.h>
#include <stdbool.h>
#include <stdint.h>

// Menu item types
typedef enum
{
    MENU_ITEM_TEXT = 0,
    MENU_ITEM_SEPARATOR
} menu_item_type_t;

// Menu item click callback
typedef void (*menu_item_callback_t)(void *user_data);

// Single menu item in a dropdown
typedef struct menu_item_t
{
    menu_item_type_t type;
    const char *text;
    menu_item_callback_t on_click;
    void *user_data;
    bool enabled;
} menu_item_t;

// A menu (dropdown) containing multiple items
#define MENU_MAX_ITEMS 16

typedef struct menu_t
{
    const char *title;
    menu_item_t items[MENU_MAX_ITEMS];
    int item_count;

    // Computed layout (set during rendering)
    int title_x;
    int title_width;
    int dropdown_x;
    int dropdown_y;
    int dropdown_width;
    int dropdown_height;
} menu_t;

// Menu bar component (horizontal bar at top of window)
#define MENUBAR_MAX_MENUS 8
#define MENUBAR_HEIGHT 20
#define MENUBAR_ITEM_PADDING_X 8
#define MENUBAR_ITEM_PADDING_Y 2
#define MENUBAR_DROPDOWN_PADDING 4
#define MENUBAR_SEPARATOR_HEIGHT 7
#define MENUBAR_DROPDOWN_MIN_WIDTH 100

// Menu bar colors
#define MENUBAR_BG_COLOR        0xFFC0C0C0  // Gray background
#define MENUBAR_TEXT_COLOR      0xFF000000  // Black text
#define MENUBAR_HOVER_COLOR     0xFF153787  // Dark blue rgb(21, 55, 135)
#define MENUBAR_HOVER_TEXT      0xFFFFFFFF  // White text on hover
#define MENUBAR_DISABLED_TEXT   0xFF808080  // Gray text for disabled items
#define MENUBAR_SEPARATOR_COLOR 0xFF808080  // Gray separator line

// 3D border colors for dropdown
#define MENUBAR_BORDER_LIGHT    0xFFFFFFFF  // White highlight (top/left)
#define MENUBAR_BORDER_DARK     0xFF404040  // Dark shadow (bottom/right)
#define MENUBAR_BORDER_MID      0xFF808080  // Mid gray for inner shadow

typedef struct menubar_t
{
    window_component_t base;

    menu_t menus[MENUBAR_MAX_MENUS];
    int menu_count;

    // State tracking
    int open_menu;          // Index of currently open menu (-1 if none)
    int hover_menu;         // Index of hovered menu title (-1 if none)
    int hover_item;         // Index of hovered item in open menu (-1 if none)

    // Font
    font_t *font;

    // Internal tracking
    bool dropdown_open;
} menubar_t;

// Initialize an empty menu bar
void menubar_init(menubar_t *menubar, int x, int y, int width);

// Add a new menu to the menu bar
// Returns the menu index, or -1 on failure
int menubar_add_menu(menubar_t *menubar, const char *title);

// Add a text item to a menu
// Returns the item index, or -1 on failure
int menu_add_item(menubar_t *menubar, int menu_index, const char *text,
                  menu_item_callback_t callback, void *user_data);

// Add a separator line to a menu
// Returns the item index, or -1 on failure
int menu_add_separator(menubar_t *menubar, int menu_index);

// Enable or disable a menu item
void menu_set_item_enabled(menubar_t *menubar, int menu_index, int item_index, bool enabled);

// Set custom font (NULL for default)
void menubar_set_font(menubar_t *menubar, font_t *font);

// Close any open dropdown
void menubar_close(menubar_t *menubar);

// Check if the menubar has an open dropdown
bool menubar_is_open(const menubar_t *menubar);

// Handle mouse/key events - returns true if event was consumed
bool menubar_handle_event(menubar_t *menubar, const diff_event_t *event);

// Polymorphic methods
void menubar_update(window_component_t *self);
void menubar_paint(window_component_t *self);
