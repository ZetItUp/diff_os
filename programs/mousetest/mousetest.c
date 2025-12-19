#include <stdint.h>
#include <diffwm/diffwm.h>
#include <system/threads.h>

static void fill_window(window_t *win, uint32_t color)
{
    if (!win || !win->backbuffer)
    {
        return;
    }

    size_t n = (size_t)win->base.width * (size_t)win->base.height;
    for (size_t i = 0; i < n; ++i)
    {
        win->backbuffer[i] = color;
    }

    window_present(win, win->backbuffer);
}

int main(void)
{
    const int width = 240;
    const int height = 160;
    window_t *win = window_create(80, 80, width, height, 0, "Mouse Test");
    if (!win)
    {
        return -1;
    }

    uint32_t color = 0xFF202020;
    fill_window(win, color);

    for (;;)
    {
        int dirty = 0;
        diff_event_t ev;

        while (window_poll_event(win, &ev))
        {
            if (ev.type == DIFF_EVENT_KEY && ev.key_pressed && ev.key == 27)
            {
                window_destroy(win);
                return 0;
            }

            if (ev.type != DIFF_EVENT_MOUSE)
            {
                continue;
            }

            switch (ev.mouse_action)
            {
                case MOUSE_ACTION_DOWN:
                    color = 0xFFB03030;
                    dirty = 1;
                    break;
                case MOUSE_ACTION_UP:
                    color = 0xFFB08030;
                    dirty = 1;
                    break;
                case MOUSE_ACTION_CLICK:
                    color = 0xFF30B060;
                    dirty = 1;
                    break;
                case MOUSE_ACTION_DBLCLICK:
                    color = 0xFF3055CC;
                    dirty = 1;
                    break;
                default:
                    break;
            }
        }

        if (dirty)
        {
            fill_window(win, color);
        }
        else
        {
            thread_sleep_ms(10);
        }
    }

    return 0;
}
