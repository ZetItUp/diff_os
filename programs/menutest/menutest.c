// Menu Test Program
// Demonstrates the menu bar component with File and Edit menus

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <system/threads.h>
#include <diffwm/diffwm.h>
#include <diffgfx/draw.h>

#define WIN_W 400
#define WIN_H 300

static bool g_running = true;
static bool g_dirty = true;
static window_t *g_window = NULL;
static menubar_t g_menubar;
static const char *g_last_action = "Click a menu item";
static font_t *g_font = NULL;

// File menu callbacks
static void on_file_new(void *data)
{
    (void)data;
    g_last_action = "File -> New";
    g_dirty = true;
}

static void on_file_open(void *data)
{
    (void)data;
    g_last_action = "File -> Open";
    g_dirty = true;
}

static void on_file_save(void *data)
{
    (void)data;
    g_last_action = "File -> Save";
    g_dirty = true;
}

static void on_file_exit(void *data)
{
    (void)data;
    g_running = false;
}

// Edit menu callbacks
static void on_edit_undo(void *data)
{
    (void)data;
    g_last_action = "Edit -> Undo";
    g_dirty = true;
}

static void on_edit_redo(void *data)
{
    (void)data;
    g_last_action = "Edit -> Redo";
    g_dirty = true;
}

static void on_edit_cut(void *data)
{
    (void)data;
    g_last_action = "Edit -> Cut";
    g_dirty = true;
}

static void on_edit_copy(void *data)
{
    (void)data;
    g_last_action = "Edit -> Copy";
    g_dirty = true;
}

static void on_edit_paste(void *data)
{
    (void)data;
    g_last_action = "Edit -> Paste";
    g_dirty = true;
}

static void handle_event(diff_event_t *ev)
{
    // Let menubar handle events first
    if (menubar_handle_event(&g_menubar, ev))
    {
        g_dirty = true;

        return;
    }

    switch (ev->type)
    {
        case DIFF_EVENT_KEY:
            if (ev->key_pressed && ev->key == 0x1B)
            {
                g_running = false;
            }
            break;

        case DIFF_EVENT_FOCUS_GAINED:
        case DIFF_EVENT_FOCUS_LOST:
            g_dirty = true;
            break;

        default:
            break;
    }
}

static void draw_content(void)
{
    if (!g_window || !g_window->backbuffer)
    {
        return;
    }

    uint32_t *fb = g_window->backbuffer;
    int w = g_window->base.width;
    int h = g_window->base.height;

    // Fill background below menubar
    for (int y = MENUBAR_HEIGHT; y < h; y++)
    {
        for (int x = 0; x < w; x++)
        {
            fb[y * w + x] = MENUBAR_BG_COLOR;
        }
    }

    // Draw text using cached font
    if (g_font && g_last_action)
    {
        int text_x = 20;
        int text_y = MENUBAR_HEIGHT + 40;
        font_draw_text(g_font, fb, w, text_x, text_y, "Last action:", 0xFF000000);
        font_draw_text(g_font, fb, w, text_x, text_y + 20, g_last_action, 0xFF0000AA);

        font_draw_text(g_font, fb, w, text_x, text_y + 60, "Click menus above to test", 0xFF404040);
        font_draw_text(g_font, fb, w, text_x, text_y + 80, "Press ESC or File->Exit to quit", 0xFF404040);
    }
}

static void repaint(void)
{
    draw_content();
    menubar_paint(&g_menubar.base);
    window_present(g_window, g_window->backbuffer);
}

int main(void)
{
    // Load font once at startup
    g_font = font_load_bdf("/system/fonts/spleen-8x16.bdf");

    g_window = window_create(100, 100, WIN_W, WIN_H, 0, "Menu Test");

    if (!g_window)
    {
        return -1;
    }

    // Initialize menu bar
    menubar_init(&g_menubar, 0, 0, WIN_W);

    // Create File menu
    int file_menu = menubar_add_menu(&g_menubar, "File");
    menu_add_item(&g_menubar, file_menu, "New", on_file_new, NULL);
    menu_add_item(&g_menubar, file_menu, "Open", on_file_open, NULL);
    menu_add_item(&g_menubar, file_menu, "Save", on_file_save, NULL);
    menu_add_separator(&g_menubar, file_menu);
    menu_add_item(&g_menubar, file_menu, "Exit", on_file_exit, NULL);

    // Create Edit menu
    int edit_menu = menubar_add_menu(&g_menubar, "Edit");
    menu_add_item(&g_menubar, edit_menu, "Undo", on_edit_undo, NULL);
    menu_add_item(&g_menubar, edit_menu, "Redo", on_edit_redo, NULL);
    menu_add_separator(&g_menubar, edit_menu);
    menu_add_item(&g_menubar, edit_menu, "Cut", on_edit_cut, NULL);
    menu_add_item(&g_menubar, edit_menu, "Copy", on_edit_copy, NULL);
    menu_add_item(&g_menubar, edit_menu, "Paste", on_edit_paste, NULL);

    // Set menubar parent
    g_menubar.base.parent = g_window;

    window_request_focus(g_window);

    // Initial paint
    repaint();

    while (g_running)
    {
        diff_event_t ev;

        while (window_poll_event(g_window, &ev))
        {
            handle_event(&ev);
        }

        if (g_dirty)
        {
            repaint();
            g_dirty = false;
        }
        else
        {
            thread_sleep_ms(10);
        }
    }

    window_destroy(g_window);

    if (g_font)
    {
        font_destroy(g_font);
    }

    return 0;
}
