#include "drivers/ddf.h"
#include "interfaces.h"
#include "stdint.h"
#include "stddef.h"

#define PS2_DATA_PORT       0x60
#define PS2_STATUS_PORT     0x64
#define PS2_COMMAND_PORT    0x64

#define PS2_STATUS_OUT      0x01
#define PS2_STATUS_IN       0x02
#define PS2_STATUS_AUX      0x20

#define MOUSE_FIFO_SIZE     64

__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 12;

typedef mouse_packet_t ps2_mouse_packet_t;

static volatile kernel_exports_t *kernel = 0;

static volatile ps2_mouse_packet_t mouse_fifo[MOUSE_FIFO_SIZE];
static volatile unsigned mouse_head = 0;
static volatile unsigned mouse_tail = 0;

static uint8_t packet_buf[3];
static int packet_index = 0;

static inline int fifo_empty(void)
{
    return mouse_head == mouse_tail;
}

static inline void fifo_push(ps2_mouse_packet_t packet)
{
    unsigned next = (mouse_tail + 1) & (MOUSE_FIFO_SIZE - 1);

    if(next != mouse_head)
    {
        mouse_fifo[mouse_tail] = packet;
        mouse_tail = next;
    }
}

static inline int fifo_pop(ps2_mouse_packet_t *out)
{
    if(fifo_empty())
    {
        return 0;
    }

    *out = mouse_fifo[mouse_head];
    mouse_head = (mouse_head + 1) & (MOUSE_FIFO_SIZE - 1);

    return 1;
}

static int wait_input_clear(void)
{
    for(int i = 0; i < 100000; i++)
    {
        if(!(kernel->inb(PS2_STATUS_PORT) & PS2_STATUS_IN))
        {
            return 0;
        }

        kernel->io_wait();
    }  

    return -1;
}

static int wait_output_full(void)
{
    for (int i = 0; i < 100000; i++)
    {
        if (kernel->inb(PS2_STATUS_PORT) & PS2_STATUS_OUT)
        {
            return 0;
        }

        kernel->io_wait();
    }

    return -1;
}

static void flush_output_buffer(void)
{
    while(kernel->inb(PS2_STATUS_PORT) & PS2_STATUS_OUT)
    {
        (void)kernel->inb(PS2_DATA_PORT);
    }
}

// Read from the controller output buffer; optionally require AUX-originated data.
static int ps2_read_output(uint8_t *out, int require_aux)
{
    for(int i = 0; i < 100000; i++)
    {
        uint8_t status = kernel->inb(PS2_STATUS_PORT);

        if(!(status & PS2_STATUS_OUT))
        {
            kernel->io_wait();
            continue;
        }

        if(require_aux && !(status & PS2_STATUS_AUX))
        {
            // Skip keyboard/controller bytes when expecting mouse data
            (void)kernel->inb(PS2_DATA_PORT);
            kernel->io_wait();
            continue;
        }

        uint8_t data = kernel->inb(PS2_DATA_PORT);

        if(out)
        {
            *out = data;
        }

        return 0;
    }

    return -1;
}

static int mouse_write_device(uint8_t val)
{
    if(wait_input_clear() != 0)
    {
        return -1;
    }

    kernel->outb(PS2_COMMAND_PORT, 0xD4);

    if(wait_input_clear() != 0)
    {
        return -1;
    }

    kernel->outb(PS2_DATA_PORT, val);
    
    return 0;
}

static int mouse_read_response(uint8_t *out)
{
    // Some controllers may not assert AUX on ACK bytes; accept any source here.
    return ps2_read_output(out, 0);
}

static int mouse_send_cmd(uint8_t cmd)
{
    for(int attempt = 0; attempt < 3; attempt++)
    {
        if(mouse_write_device(cmd) != 0)
        {
            continue;
        }

        uint8_t response = 0;

        if(mouse_read_response(&response) != 0)
        {
            continue;
        }

        if(response == 0xFA)
        {
            return 0;
        }
        
        if(response != 0xFE)
        {
            break;
        }
    }

    return -1;
}

static int mouse_send_cmd_with_arg(uint8_t cmd, uint8_t arg)
{
    for(int attempt = 0; attempt < 3; attempt++)
    {
        if(mouse_write_device(cmd) != 0)
        {
            continue;
        }

        uint8_t response = 0;

        if(mouse_read_response(&response) != 0)
        {
            continue;
        }

        if(response == 0xFE)
        {
            continue;
        }

        if(response != 0xFA)
        {
            break;
        }

        if(mouse_write_device(arg) != 0)
        {
            continue;
        }

        if(mouse_read_response(&response) != 0)
        {
            continue;
        }

        if(response == 0xFA)
        {
            return 0;
        }

        if(response != 0xFE)
        {
            break;
        }
    }

    return -1;
}

static int mouse_hw_init(void)
{
    // Disable interrupts during init so ACK bytes aren't stolen by the IRQ handler
    uint32_t eflags;
    asm volatile("pushf; pop %0; cli" : "=r"(eflags));
    int ints_were_enabled = (eflags & (1u << 9)) != 0;

    flush_output_buffer();

    if(wait_input_clear() != 0)
    {
        return -1;
    }

    // Enable AUX port
    kernel->outb(PS2_COMMAND_PORT, 0xA8);

    if(wait_input_clear() != 0)
    {
        return -1;
    }

    // Read command byte
    kernel->outb(PS2_COMMAND_PORT, 0x20);

    uint8_t cmd_byte = 0;

    if (wait_output_full() != 0)
    {
        cmd_byte = 0x47;
    }
    else
    {
        cmd_byte = kernel->inb(PS2_DATA_PORT);
    }

    // Enable IRQ 12
    cmd_byte |= 0x02;
    // Enable mouse clock and disable translation
    cmd_byte &= (uint8_t)~0x20; // clear disable-mouse/port2 clock bit (enable AUX)

    if(wait_input_clear() != 0)
    {
        goto fail;
    }

    kernel->outb(PS2_COMMAND_PORT, 0x60);

    if(wait_input_clear() != 0)
    {
        goto fail;
    }

    kernel->outb(PS2_DATA_PORT, cmd_byte);


    flush_output_buffer();

    // Set defaults
    if(mouse_send_cmd(0xF6) != 0)
    {
        goto fail;
    }

    // Resolution (4 counts / mm)
    (void)mouse_send_cmd_with_arg(0xE8, 2);
    // Sample rate
    (void)mouse_send_cmd_with_arg(0xF3, 100);
    // Stream mode
    (void)mouse_send_cmd(0xEA);

    // Enable data reporting
    if(mouse_send_cmd(0xF4) != 0)
    {
        goto fail;
    }

    packet_index = 0;
    flush_output_buffer();

    if (ints_were_enabled) asm volatile("sti");
    return 0;

fail:
    if (ints_were_enabled) asm volatile("sti");
    return -1;
}

static void handle_packet_byte(uint8_t byte)
{
    if(packet_index == 0 && !(byte & 0x08))
    {
        // First byte must have Always-1 bit set
        return;
    }

    packet_buf[packet_index++] = byte;

    if(packet_index == 3)
    {
        packet_index = 0;

        ps2_mouse_packet_t packet;
        packet.buttons = (uint8_t)(packet_buf[0] & 0x07);
        packet.dx = (int8_t)packet_buf[1];
        packet.dy = (int8_t)packet_buf[2];

        fifo_push(packet);
    }
}

static void mouse_service(void)
{
    for(;;)
    {
        uint8_t status = kernel->inb(PS2_STATUS_PORT);

        if(!(status & PS2_STATUS_OUT))
        {
            break;
        }

        uint8_t data = kernel->inb(PS2_DATA_PORT);

        if(status & PS2_STATUS_AUX)
        {
            handle_packet_byte(data);
        }
    }
}

int ps2_mouse_read(ps2_mouse_packet_t *out)
{
    int result = 0;

    asm volatile("cli");

    if(!fifo_empty())
    {
        result = fifo_pop(out); 
    }

    asm volatile("sti");

    return result;
}

int ps2_mouse_read_blocking(ps2_mouse_packet_t *out)
{
    for(;;)
    {
        asm volatile("cli");

        if(!fifo_empty())
        {
            int ok = fifo_pop(out);
            asm volatile ("sti");

            return ok;
        }

        // TODO: Do not halt? 
        asm volatile("sti; hlt");
    }
}

__attribute__((section(".text")))
void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    if(mouse_hw_init() != 0)
    {
        kernel->printf("[DRIVER] PS2 Mouse could not be installed!\n");

        return;
    }

    if (kernel->mouse_register)
    {
        kernel->mouse_register(ps2_mouse_read, ps2_mouse_read_blocking);
    }

    mouse_service();
    kernel->pic_clear_mask(12);
    kernel->printf("[DRIVER] PS2 Mouse Installed!\n");
}

__attribute__((section(".text")))
void ddf_driver_exit(void)
{
    // Disable reporting
    (void)mouse_send_cmd(0xF5);

    kernel->pic_set_mask(12);
    kernel->printf("[DRIVER] PS2 Mouse Uninstalled!\n");
}

__attribute__((section(".text")))
void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;

    mouse_service();
}
