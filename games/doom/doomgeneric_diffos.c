#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <vbe/vbe.h>
#include <syscall.h>
#include <unistd.h>
#include "doomkeys.h"
#include "m_argv.h"
#include "doomgeneric.h"
#include "i_system.h"

static void DG_Finish(void);

#define KEYQUEUE_SIZE 32

static unsigned short g_key_queue[KEYQUEUE_SIZE];
static unsigned int g_kq_head = 0;
static unsigned int g_kq_tail = 0;

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
        case 0x01:       return KEY_FIRE;
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
    system_key_event_t ev;

    while (system_keyboard_event_try(&ev))
    {
        unsigned char mapped = dg_translate_key(ev.key);

        if (mapped == 0)
        {
            continue;
        }

        dg_queue_push(ev.pressed ? 1 : 0, mapped);
    }
}

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

    return 0;
}

static void DG_Finish(void)
{
    // Restore text console overlay when leaving the game
    vbe_toggle_graphics_mode();
}
