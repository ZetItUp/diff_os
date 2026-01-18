#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include <diffgfx/graphics.h>
#include <diffwm/protocol.h>
#include <diffwm/diff_ipc.h>
#include "doomkeys.h"
#include "m_argv.h"
#include "doomgeneric.h"
#include "i_system.h"

static void DG_Finish(void);
static window_t *g_doom_window = NULL;

#define KEYQUEUE_SIZE 32

static unsigned short g_key_queue[KEYQUEUE_SIZE];
static unsigned int g_kq_head = 0;
static unsigned int g_kq_tail = 0;

// Track last known modifier state to detect changes
static uint8_t g_last_modifiers = 0;

static void dg_queue_push(int pressed, unsigned char key)
{
    unsigned int next = (g_kq_tail + 1u) % KEYQUEUE_SIZE;

    if (next == g_kq_head)
    {
        g_kq_head = (g_kq_head + 1u) % KEYQUEUE_SIZE;
    }

    g_key_queue[g_kq_tail] = (unsigned short)(((pressed ? 1u : 0u) << 8) | key);
    g_kq_tail = next;
}

static int dg_queue_pop(int *pressed, unsigned char *key)
{
    if (g_kq_head == g_kq_tail)
    {
        return 0;
    }

    unsigned short data = g_key_queue[g_kq_head];
    g_kq_head = (g_kq_head + 1u) % KEYQUEUE_SIZE;

    if (pressed)
    {
        *pressed = (data >> 8) & 0xFF;
    }
    if (key)
    {
        *key = (unsigned char)(data & 0xFF);
    }

    return 1;
}

static unsigned char dg_translate_key(unsigned char raw)
{
    switch (raw)
    {
        // 0x01 was a workaround for ctrl - now handled via modifiers
        case 0x01:       return 0;  // Ignore legacy ctrl key code
        case ' ':        return KEY_USE;
        case '\b':
        case 0x7f:       return KEY_BACKSPACE;
        case '\t':       return KEY_TAB;
        case '\r':
        case '\n':       return KEY_ENTER;
        case 27:         return KEY_ESCAPE;
        case '-':        return KEY_MINUS;
        case '=':        return KEY_EQUALS;
        case 0xac:       return KEY_LEFTARROW;
        case 0xae:       return KEY_RIGHTARROW;
        case 0xad:       return KEY_UPARROW;
        case 0xaf:       return KEY_DOWNARROW;
        default:         break;
    }

    if (raw >= 'A' && raw <= 'Z')
    {
        return (unsigned char)tolower(raw);
    }

    return raw;
}

static void dg_poll_keys(void)
{
    if (!g_doom_window)
    {
        return;
    }

    diff_event_t ev;

    while (window_poll_event(g_doom_window, &ev))
    {
        if (ev.type != DIFF_EVENT_KEY)
        {
            continue;
        }

        // Check for modifier state changes and generate synthetic key events
        uint8_t mods = ev.modifiers;
        uint8_t changed = mods ^ g_last_modifiers;

        if (changed & DIFF_MOD_SHIFT)
        {
            int pressed = (mods & DIFF_MOD_SHIFT) ? 1 : 0;
            dg_queue_push(pressed, KEY_RSHIFT);
        }

        if (changed & DIFF_MOD_CTRL)
        {
            int pressed = (mods & DIFF_MOD_CTRL) ? 1 : 0;
            dg_queue_push(pressed, KEY_FIRE);  // Ctrl = fire in Doom
        }

        if (changed & DIFF_MOD_ALT)
        {
            int pressed = (mods & DIFF_MOD_ALT) ? 1 : 0;
            dg_queue_push(pressed, KEY_RALT);
        }

        g_last_modifiers = mods;

        unsigned char mapped = dg_translate_key(ev.key);

        if (mapped == 0)
        {
            continue;
        }

        dg_queue_push(ev.key_pressed ? 1 : 0, mapped);
    }
}

void DG_Init(void)
{
    int w = DOOMGENERIC_RESX;
    int h = DOOMGENERIC_RESY;

    pixel_t *old_buffer = DG_ScreenBuffer;

    char exec_root[256];
    if (system_getexecroot(exec_root, sizeof(exec_root)) >= 0 && exec_root[0] != '\0')
    {
        chdir(exec_root);
    }

    // Choose a position that fits the current video mode (fallback to 10,10).
    int wx = 10;
    int wy = 10;
    video_mode_info_t mode;
    if (system_video_mode_get(&mode) == 0)
    {
        wx = (mode.width  > w) ? (int)((mode.width  - w) / 2) : 0;
        wy = (mode.height > h) ? (int)((mode.height - h) / 2) : 0;
    }

    // Create a window for Doom
    g_doom_window = window_create(wx, wy, w, h, 0, "DOOM");
    if (!g_doom_window)
    {
        printf("[DOOM] Failed to create window!\n");
        return;
    }

    if (old_buffer && old_buffer != (pixel_t *)g_doom_window->pixels)
    {
        free(old_buffer);
    }

    DG_ScreenBuffer = (pixel_t *)g_doom_window->pixels;

    // Push an initial blank frame so the WM shows the window even before the first game draw.
    memset(DG_ScreenBuffer, 0, (size_t)w * h * sizeof(pixel_t));
    window_present(g_doom_window, DG_ScreenBuffer);

    I_AtExit(DG_Finish, true);
}

void DG_DrawFrame(void)
{
    if (!g_doom_window)
    {
        return;
    }

    window_present(g_doom_window, DG_ScreenBuffer);
}

void DG_SleepMs(uint32_t ms)
{
    system_thread_sleep_ms((int)ms);
}

uint32_t DG_GetTicksMs(void)
{
    return (uint32_t)system_time_ms();
}

int DG_GetKey(int *pressed, unsigned char *key)
{
    if (!pressed || !key)
    {
        return 0;
    }

    dg_poll_keys();

    return dg_queue_pop(pressed, key);
}

void DG_SetWindowTitle(const char *title)
{
    (void)title;
    // No window title in bare-metal mode
}

int main(int argc, char **argv)
{
    printf("Starting Doom...\n");

    doomgeneric_Create(argc, argv);

    for (;;)
    {
        doomgeneric_Tick();
    }

    DG_Finish();

    return 0;
}

static void DG_Finish(void)
{
    if (g_doom_window)
    {
        window_destroy(g_doom_window);
        g_doom_window = NULL;
    }
}
