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
    // E0 prefix
    if (sc == 0xE0)
    {
        e0 = 1;

        return;
    }

    int release = sc & 0x80;
    sc &= 0x7F;

    // Modifiers
    if (sc == 0x2A || sc == 0x36) // Shift
    {
        shift = !release;

        return;
    }

    if (sc == 0x1D && !e0) // Left Ctrl
    {
        ctrl = !release;

        return;
    }

    if (sc == 0x38 && !e0) // Left Alt
    {
        alt = !release;

        return;
    }

    if (sc == 0x3A && !release) // Caps toggle
    {
        caps ^= 1;

        return;
    }

    // Ignore releases 
    if (release)
    {
        e0 = 0;

        return;
    }

    // Editing/control keys 
    if (sc == 0x0E) // Backspace
    {
        ch_push(0x08);
        e0 = 0;

        return;
    }

    if (sc == 0x1C) // Enter (main)
    {
        ch_push('\n');
        e0 = 0;

        return;
    }

    if (e0 && sc == 0x1C) // Enter (keypad, E0 1C)
    {
        ch_push('\n');
        e0 = 0;

        return;
    }

    if (sc == 0x0F) // Tab
    {
        ch_push('\t');
        e0 = 0;

        return;
    }

    // Regular characters
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

    if (ch >= 'a' && ch <= 'z')
    {
        if (shift ^ caps)
        {
            ch -= 32;
        }
    }
    else if (shift && shift_map[sc])
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

        asm volatile("sti; hlt");
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

