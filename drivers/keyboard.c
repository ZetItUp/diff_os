#include "drivers/driver.h"
#include "drivers/ddf.h"
#include "drivers/device.h"
#include "io.h"
#include "stdio.h"
#include "stddef.h"
#include "console.h"
#include "pic.h"

#define KEYBOARD_DATA    0x60   // Data port for scan codes and replies
#define KEYBOARD_COMMAND 0x64   // Command port to the controller
#define KEYBOARD_STATUS  0x64   // Status port to poll flags

#define KB_CMD_QUEUE_SIZE 9     // Small queue for PS2 commands
#define KB_FIFO_SIZE      256   // Ring buffer for scan codes

__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0; // No module IRQ since devices register their own

// Command sent to the device
typedef struct
{
    uint8_t command;  // Command byte to device
    int has_data;     // Nonzero if a data byte follows
    uint8_t data;     // Optional data byte
    int retries;      // How many resends tried
} kb_cmd_t;

// Keyboard queue states
typedef enum
{
    KBQ_IDLE,
    KBQ_SEND,
    KBQ_WAIT_ACK,     // Waiting for 0xFA or 0xFE
    KBQ_WAIT_BAT,     // Waiting for 0xAA after reset
    KBQ_ERROR
} kb_cmdq_state_t;

// Kernel export table from loader
static volatile kernel_exports_t *kernel = 0;

typedef struct ps2_keyboard_device
{
    device_t *dev;
    uint8_t irq;
    kb_cmd_t cmdq[KB_CMD_QUEUE_SIZE];
    int q_head;
    int q_count;
    kb_cmdq_state_t q_state;
    int resend_limit;
    volatile uint8_t fifo[KB_FIFO_SIZE];
    volatile unsigned head;
    volatile unsigned tail;
} ps2_keyboard_device_t;

// Device registration
static ps2_keyboard_device_t g_keyboard_devices[1];
static ps2_keyboard_device_t *g_keyboard_primary = 0;

// Check if the kb_fifo is empty
static inline int keyboard_fifo_empty(ps2_keyboard_device_t *kb)
{
    return kb->head == kb->tail;
}

// Check if the kb_fifo is full
static inline int keyboard_fifo_full(ps2_keyboard_device_t *kb)
{
    return ((kb->tail + 1) & (KB_FIFO_SIZE - 1)) == kb->head;
}

// Push one byte into FIFO
static inline void keyboard_fifo_push(ps2_keyboard_device_t *kb, uint8_t b)
{
    unsigned tail = (kb->tail + 1) & (KB_FIFO_SIZE - 1);

    if (tail != kb->head)
    {
        kb->fifo[kb->tail] = b;
        kb->tail = tail;
    }
}

// Pop one byte from FIFO
static inline uint8_t keyboard_fifo_pop(ps2_keyboard_device_t *kb)
{
    uint8_t b = 0;

    if (!keyboard_fifo_empty(kb))
    {
        b = kb->fifo[kb->head];
        kb->head = (kb->head + 1) & (KB_FIFO_SIZE - 1);
    }

    return b;
}

// Wait until input buffer is clear so we can write a command
static void wait_input(void)
{
    for (int i = 0; i < 10000; i++)
    {
        if (!(kernel->inb(KEYBOARD_STATUS) & 0x02)) // Bit1 IBF
        {
            return;
        }
    }
}

// Wait until there is output ready to read
static void wait_output(void)
{
    for (int i = 0; i < 10000; i++)
    {
        if (kernel->inb(KEYBOARD_STATUS) & 0x01) // Bit0 OBF
        {
            return;
        }
    }
}

// Read controller command byte
static uint8_t i8042_read_cmdbyte(void)
{
    wait_input();
    kernel->outb(KEYBOARD_COMMAND, 0x20); // Read command byte request
    wait_output();

    return kernel->inb(KEYBOARD_DATA);
}

// Write controller command byte
static void i8042_write_cmdbyte(uint8_t cb)
{
    wait_input();
    kernel->outb(KEYBOARD_COMMAND, 0x60); // Write command byte request
    wait_input();
    kernel->outb(KEYBOARD_DATA, cb);
}

// Send one queued command to the device
static void kbq_send_cmd(ps2_keyboard_device_t *kb, kb_cmd_t *cmd)
{
    wait_input();

    kb->q_state = KBQ_WAIT_ACK;
    kernel->outb(KEYBOARD_DATA, cmd->command);

    if (cmd->has_data)
    {
        wait_input();
        kernel->outb(KEYBOARD_DATA, cmd->data);
    }
}

// Start processing the next queued command
static void kbq_start_next(ps2_keyboard_device_t *kb)
{
    if (kb->q_count == 0)
    {
        kb->q_state = KBQ_IDLE;

        return;
    }

    kb->q_state = KBQ_SEND;
    kbq_send_cmd(kb, &kb->cmdq[kb->q_head]);
}

// Poll controller and move incoming bytes to FIFO or handle acks
static void i8042_service(ps2_keyboard_device_t *kb)
{
    while (kernel->inb(KEYBOARD_STATUS) & 0x01)
    {
        uint8_t val = kernel->inb(KEYBOARD_DATA);

        if (kb->q_state == KBQ_WAIT_ACK)
        {
            if (val == 0xFA) // ACK
            {
                if (kb->cmdq[kb->q_head].command == 0xFF) // Reset
                {
                    kb->q_state = KBQ_WAIT_BAT;
                }
                else
                {
                    kb->q_head = (kb->q_head + 1) % KB_CMD_QUEUE_SIZE;
                    kb->q_count--;
                    kb->q_state = KBQ_IDLE;
                    kbq_start_next(kb);
                }


                continue;
            }
            else if (val == 0xFE) // Resend request
            {
                kb->cmdq[kb->q_head].retries++;

                if (kb->cmdq[kb->q_head].retries < kb->resend_limit)
                {
                    kb->q_state = KBQ_SEND;
                    kbq_send_cmd(kb, &kb->cmdq[kb->q_head]);
                }
                else
                {
                    kb->q_head = (kb->q_head + 1) % KB_CMD_QUEUE_SIZE;
                    kb->q_count--;
                    kb->q_state = KBQ_ERROR;
                    kbq_start_next(kb);
                }


                continue;
            }
        }

        if (kb->q_state == KBQ_WAIT_BAT)
        {
            if (val == 0xAA) // BAT ok
            {
                kb->q_head = (kb->q_head + 1) % KB_CMD_QUEUE_SIZE;
                kb->q_count--;
                kb->q_state = KBQ_IDLE;
                kbq_start_next(kb);

                continue;
            }
        }

        if (val != 0xFA && val != 0xFE && val != 0xAA)
        {
            keyboard_fifo_push(kb, val);
        }
    }
}

// Initialize the controller and enable IRQ and scanning
static void i8042_init(void)
{
    wait_input();
    kernel->outb(KEYBOARD_COMMAND, 0xAD); // Disable keyboard port

    while (kernel->inb(KEYBOARD_STATUS) & 0x01) // Drain OBF
    {
        (void)kernel->inb(KEYBOARD_DATA);
    }

    wait_input();
    kernel->outb(KEYBOARD_COMMAND, 0xAA); // Controller self test
    wait_output();

    uint8_t res = kernel->inb(KEYBOARD_DATA);

    if (res != 0x55)
    {
        kernel->printf("[DRIVER] Keyboard self test failed %x\n", res);
    }

    wait_input();
    kernel->outb(KEYBOARD_COMMAND, 0xAE); // Enable keyboard port

    uint8_t cmd_byte = i8042_read_cmdbyte();
    cmd_byte |= 0x01; // Enable IRQ1
    cmd_byte &= (uint8_t)~0x10; // Ensure keyboard port is enabled
    i8042_write_cmdbyte(cmd_byte);

    while (kernel->inb(KEYBOARD_STATUS) & 0x01) // Drain any leftovers
    {
        (void)kernel->inb(KEYBOARD_DATA);
    }
}

// Read one byte if available
static int keyboard_read_byte_device(ps2_keyboard_device_t *kb, uint8_t *out)
{
    int res = 0;
    asm volatile("cli");

    if (!keyboard_fifo_empty(kb))
    {
        *out = keyboard_fifo_pop(kb);
        res = 1;
    }

    asm volatile("sti");

    return res;
}

// Read one byte and block until it arrives
static uint8_t keyboard_read_byte_blocking_device(ps2_keyboard_device_t *kb)
{
    for (;;)
    {
        asm volatile("cli");

        if (!keyboard_fifo_empty(kb))
        {
            uint8_t b = keyboard_fifo_pop(kb);
            asm volatile("sti");

            return b;
        }

        asm volatile("sti; hlt");
    }
}

int keyboard_read_byte(uint8_t *out)
{
    if (!g_keyboard_primary)
    {
        return 0;
    }

    return keyboard_read_byte_device(g_keyboard_primary, out);
}

uint8_t keyboard_read_byte_blocking(void)
{
    if (!g_keyboard_primary)
    {
        return 0;
    }

    return keyboard_read_byte_blocking_device(g_keyboard_primary);
}

// Device operations
static input_type_t kb_dev_get_type(device_t *dev)
{
    (void)dev;

    return INPUT_TYPE_KEYBOARD;
}

static int kb_dev_poll_available(device_t *dev)
{
    ps2_keyboard_device_t *kb = (ps2_keyboard_device_t *)dev->private_data;

    if (!kb)
    {
        return 0;
    }

    return keyboard_fifo_empty(kb) ? 0 : 1;
}

static int kb_dev_read_scancode(device_t *dev, uint8_t *out)
{
    ps2_keyboard_device_t *kb = (ps2_keyboard_device_t *)dev->private_data;


    return keyboard_read_byte_device(kb, out);
}

static uint8_t kb_dev_read_scancode_blocking(device_t *dev)
{
    ps2_keyboard_device_t *kb = (ps2_keyboard_device_t *)dev->private_data;


    return keyboard_read_byte_blocking_device(kb);
}

static input_device_t g_kb_ops =
{
    .get_type = kb_dev_get_type,
    .poll_available = kb_dev_poll_available,
    .read_scancode = kb_dev_read_scancode,
    .read_scancode_blocking = kb_dev_read_scancode_blocking,
    .set_leds = 0,
    .read_packet = 0,
    .read_packet_blocking = 0,
};

static void ps2_keyboard_irq_handler(unsigned irq, void *context);

static int ps2_keyboard_stop(device_t *dev)
{
    (void)dev;
    kernel->pic_set_mask(1); // Mask IRQ1


    return 0;
}

static void ps2_keyboard_cleanup(device_t *dev)
{
    ps2_keyboard_device_t *kb = (ps2_keyboard_device_t *)dev->private_data;

    if (!kb)
    {
        return;
    }

    kernel->irq_unregister_handler(kb->irq, ps2_keyboard_irq_handler, kb);
}

// Stop and start scanning to be safe after init
static int ps2_keyboard_enable_scanning_sync(void)
{
    wait_input();
    kernel->outb(KEYBOARD_DATA, 0xF5); // Disable scanning
    wait_output();
    (void)kernel->inb(KEYBOARD_DATA);  // Expect ACK

    wait_input();
    kernel->outb(KEYBOARD_DATA, 0xF4); // Enable scanning
    wait_output();

    uint8_t ack = kernel->inb(KEYBOARD_DATA);

    if (ack != 0xFA)
    {
        kernel->printf("[KB] Warn expected 0xFA got 0x%02x\n", ack);
    }

    return 0;
}

// Driver init called by loader
__attribute__((section(".text")))
void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;
    g_keyboard_primary = &g_keyboard_devices[0];
    g_keyboard_primary->dev = 0;
    g_keyboard_primary->irq = 1;
    g_keyboard_primary->q_head = 0;
    g_keyboard_primary->q_count = 0;
    g_keyboard_primary->q_state = KBQ_IDLE;
    g_keyboard_primary->resend_limit = 3;
    g_keyboard_primary->head = 0;
    g_keyboard_primary->tail = 0;
    i8042_init();
    ps2_keyboard_enable_scanning_sync();
    i8042_service(g_keyboard_primary); // Pull any pending bytes into FIFO
    kernel->keyboard_register(keyboard_read_byte, keyboard_read_byte_blocking);

    // Register device
    g_keyboard_primary->dev = kernel->device_register(DEVICE_CLASS_INPUT, "ps2_keyboard", &g_kb_ops);

    if (g_keyboard_primary->dev)
    {
        g_keyboard_primary->dev->bus_type = BUS_TYPE_PS2;
        g_keyboard_primary->dev->irq = 1;
        g_keyboard_primary->dev->private_data = g_keyboard_primary;
        g_keyboard_primary->dev->stop = ps2_keyboard_stop;
        g_keyboard_primary->dev->cleanup = ps2_keyboard_cleanup;
        kernel->strlcpy(g_keyboard_primary->dev->description, "PS/2 Keyboard", sizeof(g_keyboard_primary->dev->description));
    }

    kernel->irq_register_handler(1, ps2_keyboard_irq_handler, g_keyboard_primary);
    kernel->pic_clear_mask(1); // Unmask IRQ1
    kernel->printf("[DRIVER] PS2 Keyboard Driver Installed\n");
}

// Driver exit called by loader
__attribute__((section(".text")))
void ddf_driver_exit(void)
{
    if (g_keyboard_primary && g_keyboard_primary->dev)
    {
        kernel->device_unregister(g_keyboard_primary->dev);
        g_keyboard_primary->dev = 0;
    }

    g_keyboard_primary = 0;
    kernel->printf("[DRIVER] PS2 Keyboard Driver Uninstalled\n");
}

// IRQ handler
__attribute__((section(".text")))
void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}

static void ps2_keyboard_irq_handler(unsigned irq, void *context)
{
    (void)irq;

    ps2_keyboard_device_t *kb = (ps2_keyboard_device_t *)context;

    if (!kb)
    {
        return;
    }

    while (kernel->inb(KEYBOARD_STATUS) & 0x01)
    {
        uint8_t val = kernel->inb(KEYBOARD_DATA);

        if (kb->q_state == KBQ_WAIT_ACK)
        {
            if (val == 0xFA)
            {
                if (kb->cmdq[kb->q_head].command == 0xFF)
                {
                    kb->q_state = KBQ_WAIT_BAT;

                    continue;
                }
                else
                {
                    kb->q_head = (kb->q_head + 1) % KB_CMD_QUEUE_SIZE;
                    kb->q_count--;
                    kb->q_state = KBQ_IDLE;
                    kbq_start_next(kb);

                    continue;
                }
            }
            else if (val == 0xFE)
            {
                kb->cmdq[kb->q_head].retries++;

                if (kb->cmdq[kb->q_head].retries < kb->resend_limit)
                {
                    kb->q_state = KBQ_SEND;
                    kbq_send_cmd(kb, &kb->cmdq[kb->q_head]);
                }
                else
                {
                    kb->q_head = (kb->q_head + 1) % KB_CMD_QUEUE_SIZE;
                    kb->q_count--;
                    kb->q_state = KBQ_ERROR;
                    kbq_start_next(kb);
                }


                continue;
            }

            continue;
        }

        if (kb->q_state == KBQ_WAIT_BAT)
        {
            if (val == 0xAA)
            {
                kb->q_head = (kb->q_head + 1) % KB_CMD_QUEUE_SIZE;
                kb->q_count--;
                kb->q_state = KBQ_IDLE;

                for (int i = 0; i < 2; i++)
                {
                    if (kernel->inb(KEYBOARD_STATUS) & 0x01)
                    {
                        uint8_t idb = kernel->inb(KEYBOARD_DATA);
                        (void)idb; // Ignore device ID bytes for now
                    }
                }

                kbq_start_next(kb);

                continue;
            }
        }

        keyboard_fifo_push(kb, val);
    }
}
