#include "interfaces.h"

#define MOUSE_FIFO_SIZE 64

mouse_exports_t g_mouse = {0};

static volatile mouse_packet_t mouse_fifo[MOUSE_FIFO_SIZE];
static volatile unsigned mouse_head = 0;
static volatile unsigned mouse_tail = 0;

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
