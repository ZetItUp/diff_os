#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <time.h>
#include <video.h>
#include <system/threads.h>

// Diff Graphics Library
#include <diffgfx/graphics.h>
#include <diffgfx/draw.h>

int main(void)
{
    printf("[Diff WM] Starting the Window Manager...\n");

    video_mode_info_t mode;

    if(system_video_mode_get(&mode) < 0)
    {
        printf("[Diff WM] ERROR: No VBE Mode Set!\n");

        return -1;
    }

    uint32_t pixels = mode.width * mode.height;
    uint32_t *backbuffer = malloc(pixels * sizeof(uint32_t));

    if(!backbuffer)
    {
        printf("[Diff WM] ERROR: Could not allocate backbuffer!\n");

        return -2;
    }

    window_t* window = window_create(0, 0, 100, 100, 0); 

    for (uint32_t i = 0; i < pixels; ++i)
    {
        backbuffer[i] = color_rgb(69, 67, 117);
    }

    while(1)
    {
        system_video_present(backbuffer, (int)mode.pitch, (int)mode.width, (int)mode.height);

        // Sleep to give it time to draw etc
        thread_sleep_ms(16);
    }

    free(backbuffer);

    return 0;
}
