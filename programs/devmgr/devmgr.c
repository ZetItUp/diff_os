// Device Manager - Lists all devices grouped by bus type

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <system/threads.h>
#include <diffwm/diffwm.h>
#include <diffgfx/draw.h>
#include <difffonts/fonts.h>
#include <device.h>

#define WIN_W 400
#define WIN_H 500
#define MAX_DEVICES 64
#define INDENT 10
#define MARGIN 10

static bool g_running = true;
static window_t *g_win = NULL;
static font_t *g_font_large = NULL;
static font_t *g_font_normal = NULL;

static device_info_t g_devices[MAX_DEVICES];
static int g_device_count = 0;

// Custom component for device list
typedef struct
{
    window_component_t base;
} device_list_component_t;

static device_list_component_t g_device_list;

static void load_devices(void)
{
    g_device_count = device_count(-1);

    if (g_device_count > MAX_DEVICES)
    {
        g_device_count = MAX_DEVICES;
    }

    for (int i = 0; i < g_device_count; ++i)
    {
        device_get_info(i, &g_devices[i]);
    }
}

static const char *get_bus_title(int bus_type)
{
    switch (bus_type)
    {
        case BUS_TYPE_ISA:
            return "ISA Devices";
        case BUS_TYPE_PCI:
            return "PCI Devices";
        case BUS_TYPE_USB:
            return "USB Devices";
        case BUS_TYPE_PS2:
            return "PS/2 Devices";
        case BUS_TYPE_VIRTUAL:
            return "Virtual Devices";
        default:
            return "Other Devices";
    }
}

static void device_list_draw(window_component_t *self)
{
    (void)self;

    if (!g_win || !g_win->backbuffer)
    {
        return;
    }

    uint32_t *fb = g_win->backbuffer;
    int pitch = g_win->base.width;

    int large_h = g_font_large ? font_height(g_font_large) : 16;
    int normal_h = g_font_normal ? font_height(g_font_normal) : 12;

    uint32_t header_color = 0xFF000000;
    uint32_t device_color = 0xFF000000;

    int y = MARGIN;

    // Track which bus types we have
    int bus_types[] = { BUS_TYPE_PS2, BUS_TYPE_ISA, BUS_TYPE_PCI, BUS_TYPE_USB, BUS_TYPE_VIRTUAL, BUS_TYPE_UNKNOWN };
    int num_bus_types = 6;

    for (int b = 0; b < num_bus_types; ++b)
    {
        int bus = bus_types[b];

        // Count devices of this bus type
        int count = 0;
        for (int i = 0; i < g_device_count; ++i)
        {
            if (g_devices[i].bus_type == bus)
            {
                count++;
            }
        }

        if (count == 0)
        {
            continue;
        }

        // Draw bus category header
        if (g_font_large)
        {
            font_draw_text(g_font_large, fb, pitch, MARGIN, y, get_bus_title(bus), header_color);
        }

        y += large_h + 4;

        // Draw devices of this bus type
        for (int i = 0; i < g_device_count; ++i)
        {
            if (g_devices[i].bus_type != bus)
            {
                continue;
            }

            if (g_font_normal)
            {
                char line[128];
                snprintf(line, sizeof(line), "%s", g_devices[i].name);
                font_draw_text(g_font_normal, fb, pitch, MARGIN + INDENT, y, line, device_color);
                y += normal_h + 2;

                // Draw description if available
                if (g_devices[i].description[0])
                {
                    snprintf(line, sizeof(line), "  %s", g_devices[i].description);
                    font_draw_text(g_font_normal, fb, pitch, MARGIN + INDENT, y, line, 0xFF404040);
                    y += normal_h + 2;
                }
            }

            // Check if we ran out of space
            if (y > WIN_H - MARGIN)
            {
                break;
            }
        }

        y += 8;

        if (y > WIN_H - MARGIN)
        {
            break;
        }
    }
}

static void device_list_init(device_list_component_t *comp, int x, int y, int width, int height)
{
    window_component_init(&comp->base, x, y, width, height);
    comp->base.draw = device_list_draw;
}

static void handle_event(const diff_event_t *ev)
{
    switch (ev->type)
    {
        case DIFF_EVENT_KEY:
            if (ev->key_pressed && ev->key == 0x1B)
            {
                g_running = false;
            }
            break;

        default:
            break;
    }
}

int main(void)
{
    // Load fonts
    g_font_large = font_load_bdf("/system/fonts/spleen-8x16.bdf");
    g_font_normal = font_load_bdf("/system/fonts/spleen-6x12.bdf");

    // Load device list
    load_devices();

    // Create window
    g_win = window_create(150, 80, WIN_W, WIN_H, 0, "Device Manager");

    if (!g_win)
    {
        return -1;
    }

    // Init and add device list component
    device_list_init(&g_device_list, 0, 0, WIN_W, WIN_H);
    window_add_component(g_win, &g_device_list.base);

    window_request_focus(g_win);

    // Initial paint
    window_paint(&g_win->base);

    while (g_running)
    {
        diff_event_t ev;

        while (window_poll_event(g_win, &ev))
        {
            handle_event(&ev);
        }

        thread_yield();
    }

    window_destroy(g_win);

    if (g_font_large)
    {
        font_destroy(g_font_large);
    }

    if (g_font_normal)
    {
        font_destroy(g_font_normal);
    }

    return 0;
}
