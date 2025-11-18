#include "stdint.h"
#include "interfaces.h"
#include "console.h"

#define CH_FIFO_SIZE 256

keyboard_exports_t g_keyboard = {0};

void keyboard_register(int (*read_fn)(uint8_t*), uint8_t (*block_fn)(void))
{
    g_keyboard.keyboard_read = read_fn;
    g_keyboard.keyboard_read_blocking = block_fn;

    keyboard_init();
}

static volatile uint8_t ch_fifo[CH_FIFO_SIZE];
static volatile unsigned ch_head = 0;
static volatile unsigned ch_tail = 0;

static inline int ch_empty(void)
{
    return ch_head == ch_tail;
}

static inline int ch_full(void)
{
    return ((ch_tail + 1) & (CH_FIFO_SIZE - 1)) == ch_head;
}

static inline void ch_push(uint8_t c)
{
    unsigned t = (ch_tail + 1) & (CH_FIFO_SIZE - 1);

    if (t != ch_head)
    {
        ch_fifo[ch_tail] = c;
        ch_tail = t;
    }
}

static inline int ch_pop(uint8_t *out)
{
    if (ch_empty())
    {
        return 0;
    }

    *out = ch_fifo[ch_head];
    ch_head = (ch_head + 1) & (CH_FIFO_SIZE - 1);

    return 1;
}

static uint8_t map[128] =
{
    /*00*/ 0,  27,'1','2','3','4','5','6','7','8','9','0','-','=', '\b',
    /*10*/ '\t','q','w','e','r','t','y','u','i','o','p','[',']','\n', 0,
    /*20*/ 'a','s','d','f','g','h','j','k','l',';','\'','`', 0,'\\','z','x',
    /*30*/ 'c','v','b','n','m',',','.','/', 0,   0,   0,  ' ',
};

static uint8_t shift_map[128] =
{
    /*02..0D*/ 0, 0,'!','@','#','$','%','^','&','*','(',')','_','+', 0,
    /*10..1B*/ 0, 0,'Q','W','E','R','T','Y','U','I','O','P','{','}', 0,
    /*1E..28*/ 0,'A','S','D','F','G','H','J','K','L',':','"','~', 0,
    /*2B..35*/ 0,'Z','X','C','V','B','N','M','<','>','?', 0,
};

static int shift, caps, ctrl, alt, e0;

static void keyboard_process_scancode(uint8_t sc)
{
    if (sc == 0xE0)  // Handle E0 prefix
    {
        e0 = 1;

        return;
    }

    int release = sc & 0x80;
    sc &= 0x7F;

    if (sc == 0x2A || sc == 0x36)  // Shift
    {
        shift = !release;

        return;
    }

    if (sc == 0x1D && !e0)  // Left Ctrl
    {
        ctrl = !release;

        return;
    }

    if (sc == 0x38 && !e0)  // Left Alt
    {
        alt = !release;

        return;
    }

    if (sc == 0x3A && !release)  // Caps toggle
    {
        caps ^= 1;

        return;
    }

    if (release)  // Ignore releases
    {
        e0 = 0;

        return;
    }

    if (sc == 0x0E)  // Backspace
    {
        ch_push(0x08);
        e0 = 0;

        return;
    }

    if (sc == 0x1C)  // Enter (main)
    {
        ch_push('\n');
        e0 = 0;

        return;
    }

    if (e0 && sc == 0x1C)  // Enter (keypad)
    {
        ch_push('\n');
        e0 = 0;

        return;
    }

    if (sc == 0x0F)  // Tab
    {
        ch_push('\t');
        e0 = 0;

        return;
    }

    // Handle E0-prefixed keys (arrow keys, etc.)
    if (e0)
    {
        e0 = 0;

        // Arrow keys with E0 prefix
        if (sc == 0x48)  // Up arrow
        {
            ch_push(0xad);
            return;
        }
        if (sc == 0x50)  // Down arrow
        {
            ch_push(0xaf);
            return;
        }
        if (sc == 0x4B)  // Left arrow
        {
            ch_push(0xac);
            return;
        }
        if (sc == 0x4D)  // Right arrow
        {
            ch_push(0xae);
            return;
        }
        if (sc == 0x47)  // Home
        {
            ch_push(0x80 + 0x47);
            return;
        }
        if (sc == 0x4F)  // End
        {
            ch_push(0x80 + 0x4F);
            return;
        }
        if (sc == 0x49)  // Page Up
        {
            ch_push(0x80 + 0x49);
            return;
        }
        if (sc == 0x51)  // Page Down
        {
            ch_push(0x80 + 0x51);
            return;
        }
        if (sc == 0x52)  // Insert
        {
            ch_push(0x80 + 0x52);
            return;
        }
        if (sc == 0x53)  // Delete
        {
            ch_push(0x80 + 0x53);
            return;
        }

        // Ignore other E0 keys
        return;
    }

    // Handle F-keys (send as 0x80 + scancode for Doom)
    if (sc >= 0x3B && sc <= 0x44)  // F1-F10
    {
        ch_push(0x80 + sc);
        return;
    }
    if (sc == 0x57)  // F11
    {
        ch_push(0x80 + sc);
        return;
    }
    if (sc == 0x58)  // F12
    {
        ch_push(0x80 + sc);
        return;
    }

    if (sc >= 128)
    {
        e0 = 0;

        return;
    }

    uint8_t ch = map[sc];

    if (!ch)
    {
        e0 = 0;

        return;
    }

    if (ch >= 'a' && ch <= 'z')  // Apply Caps/Shift on letters
    {
        if (shift ^ caps)
        {
            ch -= 32;
        }
    }
    else if (shift && shift_map[sc])  // Apply Shift on symbols
    {
        ch = shift_map[sc];
    }

    ch_push(ch);
    e0 = 0;
}

void keyboard_init(void)
{
    shift = 0;
    caps = 0;
    ctrl = 0;
    alt = 0;
    e0 = 0;

    ch_head = 0;
    ch_tail = 0;
}

void keyboard_drain(void)
{
    uint8_t sc;

    while (g_keyboard.keyboard_read(&sc))
    {
        keyboard_process_scancode(sc);
    }
}

uint8_t keyboard_getch(void)
{
    for (;;)
    {
        keyboard_drain();

        uint8_t c;

        if (ch_pop(&c))
        {
            return c;
        }

        asm volatile("sti; hlt");  // Sleep until next interrupt
    }
}

int keyboard_trygetch(uint8_t *out)
{
    keyboard_drain();

    uint8_t c;

    if (ch_pop(&c))
    {
        if (out)
        {
            *out = c;
        }

        return 1;
    }

    return 0;
}

