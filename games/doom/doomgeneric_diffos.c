#include <stdint.h>
#include <stdio.h>
#include <vbe/vbe.h>
#include "doomkeys.h"
#include "m_argv.h"
#include "doomgeneric.h"

void DG_Init(void)
{
    int w = DG_WIDTH;
    int h = DG_HEIGHT;

    size_t n = (size_t)DOOMGENERIC_RESX * DOOMGENERIC_RESY;
    DG_ScreenBuffer = (pixel_t*)malloc(n * sizeof(pixel_t));

    vbe_set_video_mode(w, h, 32);

    // Hide text console overlay while the game runs
    vbe_toggle_graphics_mode();
}

void DG_DrawFrame(void)
{
    int w = DG_WIDTH;
    int h = DG_HEIGHT;
    int pitch = w * 4;

    vbe_present(DG_ScreenBuffer, pitch, w, h);
}

void DG_SleepMs(uint32_t ms)
{
    system_thread_sleep_ms((int)ms);
}

uint32_t DG_GetTicksMs(void)
{
    return system_time_ms();
}

int DG_GetKey(int *pressed, unsigned char *key)
{
    uint8_t c = 0;

    if (!pressed || !key)
    {
        return 0;
    }

    if (!system_trygetch(&c) || c == 0)
    {
        *pressed = 0;

        return 1;
    }

    *pressed = 1;
    *key = (unsigned char)c;

    return 1;
}

void DG_SetWindowTitle(const char *title)
{
    (void)title;
    // No window title in bare-metal mode
}

void DG_Finish(void)
{
    // Restore text console overlay when leaving the game
    vbe_toggle_graphics_mode();
}

int main(int argc, char **argv)
{
    printf("Starting Doom...\n");

    doomgeneric_Create(argc, argv);

    for (int i = 0;; i++)
    {
        doomgeneric_Tick();
    }

    return 0;
}

