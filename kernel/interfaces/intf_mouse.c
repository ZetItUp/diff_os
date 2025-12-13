#include "interfaces.h"

#define MOUSE_FIFO_SIZE 64

mouse_exports_t g_mouse = {0};

static volatile mouse_packet_t mouse_fifo[MOUSE_FIFO_SIZE];
static volatile unsigned mouse_head = 0;
static volatile unsigned mouse_tail = 0;

// Mouse state tracking
static volatile int g_mouse_x = 0;
static volatile int g_mouse_y = 0;
static volatile int g_mouse_max_x = 1024;  // Default, updated by WM
static volatile int g_mouse_max_y = 768;
static volatile uint8_t g_mouse_buttons = 0;       // Current button state
static volatile uint8_t g_mouse_pressed = 0;       // Buttons pressed since last check
static volatile uint8_t g_mouse_released = 0;      // Buttons released since last check

static inline int mouse_fifo_empty(void)
{
    return mouse_head == mouse_tail;
}

static inline void mouse_fifo_push(mouse_packet_t pkt)
{
    unsigned next = (mouse_tail + 1u) & (MOUSE_FIFO_SIZE - 1u);

    if (next != mouse_head)
    {
        mouse_fifo[mouse_tail] = pkt;
        mouse_tail = next;
    }
}

static inline int mouse_fifo_pop(mouse_packet_t *out)
{
    if (mouse_fifo_empty())
    {
        return 0;
    }

    if (out)
    {
        *out = mouse_fifo[mouse_head];
    }

    mouse_head = (mouse_head + 1u) & (MOUSE_FIFO_SIZE - 1u);
    return 1;
}

void mouse_register(int (*read_fn)(mouse_packet_t*), int (*read_block_fn)(mouse_packet_t*))
{
    g_mouse.mouse_read = read_fn;
    g_mouse.mouse_read_blocking = read_block_fn;
    mouse_init();
}

void mouse_init(void)
{
    mouse_head = 0;
    mouse_tail = 0;
}

// Drain packets from the driver into the kernel-side FIFO
void mouse_drain(void)
{
    if (!g_mouse.mouse_read)
    {
        return;
    }

    mouse_packet_t pkt;

    while (g_mouse.mouse_read(&pkt))
    {
        mouse_fifo_push(pkt);
    }
}

int mouse_try_get_packet(mouse_packet_t *packet)
{
    mouse_drain();

    if (!mouse_fifo_pop(packet))
    {
        return 0;
    }

    return 1;
}

int mouse_get_packet(mouse_packet_t *packet)
{
    for (;;)
    {
        if (mouse_try_get_packet(packet))
        {
            return 1;
        }

        asm volatile("sti; hlt");
    }
}

// Process all pending mouse packets and update state
void mouse_update_state(void)
{
    mouse_packet_t pkt;

    while (mouse_try_get_packet(&pkt))
    {
        // Update position with clamping
        g_mouse_x += pkt.dx;
        g_mouse_y -= pkt.dy;  // Y is inverted in PS/2

        if (g_mouse_x < 0) g_mouse_x = 0;
        if (g_mouse_y < 0) g_mouse_y = 0;
        if (g_mouse_x >= g_mouse_max_x) g_mouse_x = g_mouse_max_x - 1;
        if (g_mouse_y >= g_mouse_max_y) g_mouse_y = g_mouse_max_y - 1;

        // Track button state changes
        uint8_t old_buttons = g_mouse_buttons;
        g_mouse_buttons = pkt.buttons;

        // Pressed = buttons that are now down but weren't before
        g_mouse_pressed |= (pkt.buttons & ~old_buttons);

        // Released/clicked = buttons that were down but now aren't
        g_mouse_released |= (old_buttons & ~pkt.buttons);

    }
}

// Get mouse position (x in high 16 bits, y in low 16 bits)
int mouse_get_pos(void)
{
    mouse_update_state();
    return ((g_mouse_x & 0xFFFF) << 16) | (g_mouse_y & 0xFFFF);
}

// Set mouse position
void mouse_set_pos(int x, int y)
{
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x >= g_mouse_max_x) x = g_mouse_max_x - 1;
    if (y >= g_mouse_max_y) y = g_mouse_max_y - 1;

    g_mouse_x = x;
    g_mouse_y = y;
}

// Set mouse bounds (screen resolution)
void mouse_set_bounds(int max_x, int max_y)
{
    g_mouse_max_x = max_x;
    g_mouse_max_y = max_y;

    // Re-clamp current position
    if (g_mouse_x >= max_x) g_mouse_x = max_x - 1;
    if (g_mouse_y >= max_y) g_mouse_y = max_y - 1;
}

// Get current button state (which buttons are held down)
uint8_t mouse_get_buttons_down(void)
{
    mouse_update_state();
    return g_mouse_buttons;
}

// Get buttons pressed since last call (rising edge, clears on read)
uint8_t mouse_get_buttons_pressed(void)
{
    mouse_update_state();
    uint8_t pressed = g_mouse_pressed;
    g_mouse_pressed = 0;
    return pressed;
}

// Get buttons released/clicked since last call (falling edge, clears on read)
uint8_t mouse_get_buttons_clicked(void)
{
    mouse_update_state();
    uint8_t released = g_mouse_released;
    g_mouse_released = 0;
    return released;
}
