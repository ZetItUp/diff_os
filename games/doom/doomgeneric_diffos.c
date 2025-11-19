#include <stdint.h>
#include <stdio.h>
#include <vbe/vbe.h>
#include <syscall.h>
#include <unistd.h>
#include "doomkeys.h"
#include "m_argv.h"
#include "doomgeneric.h"
#include "i_system.h"

static void DG_Finish(void);

void DG_Init(void)
{
    int w = DG_WIDTH;
    int h = DG_HEIGHT;

    size_t n = (size_t)DOOMGENERIC_RESX * DOOMGENERIC_RESY;
    DG_ScreenBuffer = (pixel_t*)malloc(n * sizeof(pixel_t));

    char exec_root[256];
    if (system_getexecroot(exec_root, sizeof(exec_root)) >= 0 && exec_root[0] != '\0')
    {
        chdir(exec_root);
    }

    vbe_set_video_mode(w, h, 32);

    // Hide text console overlay while the game runs
    vbe_toggle_graphics_mode();
    I_AtExit(DG_Finish, true);
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
    if (!pressed || !key)
    {
        return 0;
    }

    system_key_event_t ev;

    if (!system_keyboard_event_try(&ev))
    {
        return 0;
    }

    *pressed = ev.pressed ? 1 : 0;
    *key = ev.key;

    return 1;
}

void DG_SetWindowTitle(const char *title)
{
    (void)title;
    // No window title in bare-metal mode
}

int main(int argc, char **argv)
{
    printf("[DOOM-MAIN] Entry point reached! argc=%d\n", argc);
    printf("Starting Doom...\n");

    printf("[DOOM-MAIN] About to call doomgeneric_Create\n");
    doomgeneric_Create(argc, argv);
    printf("[DOOM-MAIN] doomgeneric_Create returned\n");

    for (;;)
    {
        doomgeneric_Tick();
    }

    return 0;
}

static void DG_Finish(void)
{
    // Restore text console overlay when leaving the game
    vbe_toggle_graphics_mode();
}
