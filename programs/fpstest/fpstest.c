#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <diffwm/diffwm.h>
#include <diffwm/window_component.h>
#include <diffwm/window.h>
#include <diffwm/label.h>
#include <difffonts/fonts.h>
#include <diffgfx/graphics.h>
#include <syscall.h>
#include <system/threads.h>

// Simple FPS overlay test: opens a window, updates a label with the current FPS
// based on measured frame times.

static uint64_t now_ms(void)
{
    return system_time_ms();
}

int main(void)
{
    // Create window
    const int width = 320;
    const int height = 120;
    window_t *win = window_create(40, 40, width, height, 0, "FPS Test");
    if (!win)
    {
        return -1;
    }

    // Load font
    font_t *font = font_load_bdf("/system/fonts/spleen-6x12.bdf");
    if (!font)
    {
        window_destroy(win);
        return -2;
    }

    // Create label component
    label_t fps_label;
    label_init(&fps_label, 10, 40, "FPS: --");

    // Attach to window
    window_add_component(win, &fps_label.base);

    uint64_t last_ms = now_ms();
    int frame_count = 0;
    int fps = 0;
    uint64_t fps_accum_ms = 0;

    for (;;)
    {
        // Basic event pump to allow window closure via focus loss (Escape) if desired.
        diff_event_t ev;
        while (window_poll_event(win, &ev))
        {
            if (ev.type == DIFF_EVENT_KEY && ev.key_pressed && ev.key == 27) // ESC
            {
                font_destroy(font);
                window_destroy(win);
                return 0;
            }
        }

        // Update FPS once per second
        uint64_t now = now_ms();
        uint64_t dt = now - last_ms;
        last_ms = now;
        fps_accum_ms += dt;
        frame_count++;

        if (fps_accum_ms >= 1000)
        {
            fps = frame_count * 1000 / (int)fps_accum_ms;
            fps_accum_ms = 0;
            frame_count = 0;

            char buf[64];
            snprintf(buf, sizeof(buf), "FPS: %d", fps);
            label_set_text(&fps_label, buf);
        }

        // Paint
        window_paint(&win->base);

        // Small sleep to avoid pegging CPU; adjust as needed.
        thread_sleep_ms(1);
    }

    // Unreachable, but keep tidy.
    font_destroy(font);
    window_destroy(win);
    return 0;
}
