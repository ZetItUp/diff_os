#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <video.h>
#include <system/threads.h>
#include <diffgfx/graphics.h>
#include <diffgfx/draw.h>

int main(void)
{
    /* Create a test window */
    int width = 320;
    int height = 200;
    window_t *win = window_create(50, 50, width, height, 0);
    if (!win)
    {
        printf("[GUI TEST] Failed to create window\n");
        return -1;
    }

    /* Allocate a local buffer for drawing */
    size_t pixels = (size_t)width * height;
    uint32_t *buf = (uint32_t *)malloc(pixels * sizeof(uint32_t));
    if (!buf)
    {
        printf("[GUI TEST] Failed to allocate buffer\n");
        window_destroy(win);
        return -2;
    }

    printf("GUI WINDOW POG\n");
    /* Fill background with a dark color */
    for (size_t i = 0; i < pixels; ++i)
    {
        buf[i] = color_rgb(30, 30, 60);
    }

    /* Draw a white border around the window */
    uint32_t border = color_rgb(255, 255, 255);
    for (int x = 0; x < width; ++x)
    {
        buf[x] = border;                       /* top */
        buf[(height - 1) * width + x] = border;/* bottom */
    }
    for (int y = 0; y < height; ++y)
    {
        buf[y * width] = border;               /* left */
        buf[y * width + (width - 1)] = border; /* right */
    }

    /* Present once */
    window_draw(win, buf);

    /* Idle so the window stays visible */
    while (1)
    {
        thread_sleep_ms(100);
    }

    free(buf);
    window_destroy(win);
    return 0;
}
