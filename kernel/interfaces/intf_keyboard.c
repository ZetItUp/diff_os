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

static inline unsigned ch_count(void)
{
    return (ch_tail - ch_head) & (CH_FIFO_SIZE - 1);
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

static int keyboard_try_pop_event(uint8_t *pressed, uint8_t *key)
{
    if (ch_count() < 2)
    {
        return 0;
    }

    uint8_t state = 0;
    uint8_t code = 0;
    ch_pop(&state);
    ch_pop(&code);

    if (pressed)
    {
        *pressed = state;
    }

    if (key)
    {
        *key = code;
    }

    return 1;
}

static const uint8_t map[128] =
{
    [0x01] = 27,
    [0x02] = '1',
    [0x03] = '2',
    [0x04] = '3',
    [0x05] = '4',
    [0x06] = '5',
    [0x07] = '6',
    [0x08] = '7',
    [0x09] = '8',
    [0x0A] = '9',
    [0x0B] = '0',
    [0x0C] = '-',
    [0x0D] = '=',
    [0x0E] = '\b',
    [0x0F] = '\t',
    [0x10] = 'q',
    [0x11] = 'w',
    [0x12] = 'e',
    [0x13] = 'r',
    [0x14] = 't',
    [0x15] = 'y',
    [0x16] = 'u',
    [0x17] = 'i',
    [0x18] = 'o',
    [0x19] = 'p',
    [0x1A] = '[',
    [0x1B] = ']',
    [0x1C] = '\n',
    [0x1E] = 'a',
    [0x1F] = 's',
    [0x20] = 'd',
    [0x21] = 'f',
    [0x22] = 'g',
    [0x23] = 'h',
    [0x24] = 'j',
    [0x25] = 'k',
    [0x26] = 'l',
    [0x27] = ';',
    [0x28] = '\'',
    [0x29] = '`',
    [0x2B] = '\\',
    [0x2C] = 'z',
    [0x2D] = 'x',
    [0x2E] = 'c',
    [0x2F] = 'v',
    [0x30] = 'b',
    [0x31] = 'n',
    [0x32] = 'm',
    [0x33] = ',',
    [0x34] = '.',
    [0x35] = '/',
    [0x37] = '*',
    [0x39] = ' ',
    [0x47] = '7',
    [0x48] = '8',
    [0x49] = '9',
    [0x4A] = '-',
    [0x4B] = '4',
    [0x4C] = '5',
    [0x4D] = '6',
    [0x4E] = '+',
    [0x4F] = '1',
    [0x50] = '2',
    [0x51] = '3',
    [0x52] = '0',
    [0x53] = '.',
};

static const uint8_t shift_map[128] =
{
    [0x02] = '!',
    [0x03] = '@',
    [0x04] = '#',
    [0x05] = '$',
    [0x06] = '%',
    [0x07] = '^',
    [0x08] = '&',
    [0x09] = '*',
    [0x0A] = '(',
    [0x0B] = ')',
    [0x0C] = '_',
    [0x0D] = '+',
    [0x1A] = '{',
    [0x1B] = '}',
    [0x27] = ':',
    [0x28] = '"',
    [0x29] = '~',
    [0x2B] = '|',
    [0x33] = '<',
    [0x34] = '>',
    [0x35] = '?',
};

static int shift, caps, ctrl, alt, e0, num_lock;

// Helper to push a key event (press or release) as 2 bytes
static void push_key_event(int pressed, uint8_t key)
{
    ch_push(pressed ? 1 : 0);
    ch_push(key);
}

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
        push_key_event(!release, 0x01);
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

    if (sc == 0x45 && !release)  // Num Lock toggle
    {
        num_lock ^= 1;
        e0 = 0;

        return;
    }

    if (sc == 0x0E)  // Backspace
    {
        push_key_event(!release, 0x08);
        e0 = 0;

        return;
    }

    if (sc == 0x1C)  // Enter (main or keypad with E0)
    {
        push_key_event(!release, 13);
        e0 = 0;

        return;
    }

    if (sc == 0x0F)  // Tab
    {
        push_key_event(!release, '\t');
        e0 = 0;

        return;
    }

    if (!e0 && sc == 0x37)  // Keypad *
    {
        push_key_event(!release, '*');
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
            push_key_event(!release, 0xad);
            return;
        }
        if (sc == 0x50)  // Down arrow
        {
            push_key_event(!release, 0xaf);
            return;
        }
        if (sc == 0x4B)  // Left arrow
        {
            push_key_event(!release, 0xac);
            return;
        }
        if (sc == 0x4D)  // Right arrow
        {
            push_key_event(!release, 0xae);
            return;
        }
        if (sc == 0x47)  // Home
        {
            push_key_event(!release, 0x80 + 0x47);
            return;
        }
        if (sc == 0x4F)  // End
        {
            push_key_event(!release, 0x80 + 0x4F);
            return;
        }
        if (sc == 0x49)  // Page Up
        {
            push_key_event(!release, 0x80 + 0x49);
            return;
        }
        if (sc == 0x51)  // Page Down
        {
            push_key_event(!release, 0x80 + 0x51);
            return;
        }
        if (sc == 0x52)  // Insert
        {
            push_key_event(!release, 0x80 + 0x52);
            return;
        }
        if (sc == 0x53)  // Delete
        {
            push_key_event(!release, 0x80 + 0x53);
            return;
        }
        if (sc == 0x35)  // Keypad /
        {
            push_key_event(!release, '/');
            return;
        }
        if (sc == 0x1C)  // Keypad Enter
        {
            push_key_event(!release, 13);
            return;
        }

        if (sc == 0x1D) // Right Ctrl
        {
            push_key_event(!release, 0x01);
            return;
        }

        // Ignore other E0 keys
        return;
    }

    if (sc >= 0x47 && sc <= 0x53)  // Keypad cluster
    {
        if (sc == 0x4A || sc == 0x4E)  // - and +
        {
            push_key_event(!release, sc == 0x4A ? '-' : '+');
            e0 = 0;
            return;
        }

        static const uint8_t keypad_chars[13] =
        {
            '7','8','9',0,'4','5','6',0,'1','2','3','0','.'
        };

        if (num_lock)
        {
            uint8_t sym = keypad_chars[sc - 0x47];

            if (sym)
            {
                push_key_event(!release, sym);
            }
        }
        else
        {
            static const uint8_t keypad_nav[13] =
            {
                (uint8_t)(0x80 + 0x47), 0xad, (uint8_t)(0x80 + 0x49), 0,
                0xac, 0, 0xae, 0,
                (uint8_t)(0x80 + 0x4F), 0xaf, (uint8_t)(0x80 + 0x51),
                (uint8_t)(0x80 + 0x52), (uint8_t)(0x80 + 0x53)
            };

            uint8_t nav = keypad_nav[sc - 0x47];

            if (nav)
            {
                push_key_event(!release, nav);
            }
        }

        e0 = 0;

        return;
    }

    // Handle F-keys (send as 0x80 + scancode for Doom)
    if (sc >= 0x3B && sc <= 0x44)  // F1-F10
    {
        push_key_event(!release, 0x80 + sc);
        return;
    }
    if (sc == 0x57)  // F11
    {
        push_key_event(!release, 0x80 + sc);
        return;
    }
    if (sc == 0x58)  // F12
    {
        push_key_event(!release, 0x80 + sc);
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

    push_key_event(!release, ch);
    e0 = 0;
}

void keyboard_init(void)
{
    shift = 0;
    caps = 0;
    ctrl = 0;
    alt = 0;
    e0 = 0;
    num_lock = 1;

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

int keyboard_try_get_event(keyboard_event_t *event)
{
    keyboard_drain();

    uint8_t pressed = 0;
    uint8_t key = 0;

    if (!keyboard_try_pop_event(&pressed, &key))
    {
        return 0;
    }

    if (event)
    {
        event->pressed = pressed ? 1 : 0;
        event->key = key;
    }

    return 1;
}

int keyboard_get_event(keyboard_event_t *event)
{
    keyboard_event_t tmp;

    for (;;)
    {
        if (keyboard_try_get_event(&tmp))
        {
            if (event)
            {
                *event = tmp;
            }

            return 1;
        }

        asm volatile("sti; hlt");
    }
}

uint8_t keyboard_getch(void)
{
    for (;;)
    {
        keyboard_event_t ev;

        keyboard_get_event(&ev);

        if (!ev.pressed)
        {
            continue;
        }

        return ev.key;
    }
}

int keyboard_trygetch(uint8_t *out)
{
    for (;;)
    {
        keyboard_event_t ev;

        if (!keyboard_try_get_event(&ev))
        {
            return 0;
        }

        if (!ev.pressed)
        {
            continue;
        }

        if (out)
        {
            *out = ev.key;
        }

        return 1;
    }
}
