#include "drivers/driver.h"
#include "drivers/ddf.h"
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
volatile unsigned int ddf_irq_number = 1; // IRQ1 for PS2 keyboard

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

// Command queue storage and tracking
static kb_cmd_t kb_cmdq[KB_CMD_QUEUE_SIZE] = {0};
static int kb_q_head = 0;
static int kb_q_count = 0;
static kb_cmdq_state_t kb_cmdq_state = KBQ_IDLE;
static int kb_resend_limit = 3;

// Scan code FIFO
static volatile uint8_t kb_fifo[KB_FIFO_SIZE];
static volatile unsigned kb_head = 0;
static volatile unsigned kb_tail = 0;

// Check if the kb_fifo is empty
static inline int keyboard_fifo_empty(void)
{
    return kb_head == kb_tail;
}

// Check if the kb_fifo is full
static inline int keyboard_fifo_full(void)
{
    return ((kb_tail + 1) & (KB_FIFO_SIZE - 1)) == kb_head;
}

// Push one byte into FIFO
static inline void keyboard_fifo_push(uint8_t b)
{
    unsigned tail = (kb_tail + 1) & (KB_FIFO_SIZE - 1);

    if (tail != kb_head)
    {
        kb_fifo[kb_tail] = b;
        kb_tail = tail;
    }
}

// Pop one byte from FIFO
static inline uint8_t keyboard_fifo_pop(void)
{
    uint8_t b = 0;

    if (!keyboard_fifo_empty())
    {
        b = kb_fifo[kb_head];
        kb_head = (kb_head + 1) & (KB_FIFO_SIZE - 1);
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
static void kbq_send_cmd(kb_cmd_t *cmd)
{
    wait_input();

    kb_cmdq_state = KBQ_WAIT_ACK;
    kernel->outb(KEYBOARD_DATA, cmd->command);

    if (cmd->has_data)
    {
        wait_input();
        kernel->outb(KEYBOARD_DATA, cmd->data);
    }
}

// Start processing the next queued command
static void kbq_start_next(void)
{
    if (kb_q_count == 0)
    {
        kb_cmdq_state = KBQ_IDLE;
        return;
    }

    kb_cmdq_state = KBQ_SEND;
    kbq_send_cmd(&kb_cmdq[kb_q_head]);
}

// Poll controller and move incoming bytes to FIFO or handle acks
static void i8042_service(void)
{
    while (kernel->inb(KEYBOARD_STATUS) & 0x01)
    {
        uint8_t val = kernel->inb(KEYBOARD_DATA);

        if (kb_cmdq_state == KBQ_WAIT_ACK)
        {
            if (val == 0xFA) // ACK
            {
                if (kb_cmdq[kb_q_head].command == 0xFF) // Reset
                {
                    kb_cmdq_state = KBQ_WAIT_BAT;
                }
                else
                {
                    kb_q_head = (kb_q_head + 1) % KB_CMD_QUEUE_SIZE;
                    kb_q_count--;
                    kb_cmdq_state = KBQ_IDLE;
                    kbq_start_next();
                }

                continue;
            }
            else if (val == 0xFE) // Resend request
            {
                kb_cmdq[kb_q_head].retries++;

                if (kb_cmdq[kb_q_head].retries < kb_resend_limit)
                {
                    kb_cmdq_state = KBQ_SEND;
                    kbq_send_cmd(&kb_cmdq[kb_q_head]);
                }
                else
                {
                    kb_q_head = (kb_q_head + 1) % KB_CMD_QUEUE_SIZE;
                    kb_q_count--;
                    kb_cmdq_state = KBQ_ERROR;
                    kbq_start_next();
                }

                continue;
            }
        }

        if (kb_cmdq_state == KBQ_WAIT_BAT)
        {
            if (val == 0xAA) // BAT ok
            {
                kb_q_head = (kb_q_head + 1) % KB_CMD_QUEUE_SIZE;
                kb_q_count--;
                kb_cmdq_state = KBQ_IDLE;
                kbq_start_next();
                continue;
            }
        }

        if (val != 0xFA && val != 0xFE && val != 0xAA)
        {
            keyboard_fifo_push(val);
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
    i8042_write_cmdbyte(cmd_byte);

    while (kernel->inb(KEYBOARD_STATUS) & 0x01) // Drain any leftovers
    {
        (void)kernel->inb(KEYBOARD_DATA);
    }
}

// Read one byte if available
int keyboard_read_byte(uint8_t *out)
{
    int res = 0;
    asm volatile("cli");

    if (!keyboard_fifo_empty())
    {
        *out = keyboard_fifo_pop();
        res = 1;
    }

    asm volatile("sti");
    return res;
}

// Read one byte and block until it arrives
uint8_t keyboard_read_byte_blocking(void)
{
    for (;;)
    {
        asm volatile("cli");

        if (!keyboard_fifo_empty())
        {
            uint8_t b = keyboard_fifo_pop();
            asm volatile("sti");
            return b;
        }

        asm volatile("sti; hlt");
    }
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
    i8042_init();
    ps2_keyboard_enable_scanning_sync();
    i8042_service(); // Pull any pending bytes into FIFO
    kernel->keyboard_register(keyboard_read_byte, keyboard_read_byte_blocking);
    kernel->pic_clear_mask(1); // Unmask IRQ1
    kernel->printf("[DRIVER] PS2 Keyboard Driver Installed\n");
}

// Driver exit called by loader
__attribute__((section(".text")))
void ddf_driver_exit(void)
{
    kernel->pic_set_mask(1); // Mask IRQ1
    kernel->printf("[DRIVER] PS2 Keyboard Driver Uninstalled\n");
}

// IRQ handler
__attribute__((section(".text")))
void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;

    while (kernel->inb(KEYBOARD_STATUS) & 0x01)
    {
        uint8_t val = kernel->inb(KEYBOARD_DATA);

        if (kb_cmdq_state == KBQ_WAIT_ACK)
        {
            if (val == 0xFA)
            {
                if (kb_cmdq[kb_q_head].command == 0xFF)
                {
                    kb_cmdq_state = KBQ_WAIT_BAT;
                    continue;
                }
                else
                {
                    kb_q_head = (kb_q_head + 1) % KB_CMD_QUEUE_SIZE;
                    kb_q_count--;
                    kb_cmdq_state = KBQ_IDLE;
                    kbq_start_next();
                    continue;
                }
            }
            else if (val == 0xFE)
            {
                kb_cmdq[kb_q_head].retries++;

                if (kb_cmdq[kb_q_head].retries < kb_resend_limit)
                {
                    kb_cmdq_state = KBQ_SEND;
                    kbq_send_cmd(&kb_cmdq[kb_q_head]);
                }
                else
                {
                    kb_q_head = (kb_q_head + 1) % KB_CMD_QUEUE_SIZE;
                    kb_q_count--;
                    kb_cmdq_state = KBQ_ERROR;
                    kbq_start_next();
                }

                continue;
            }

            continue;
        }

        if (kb_cmdq_state == KBQ_WAIT_BAT)
        {
            if (val == 0xAA)
            {
                kb_q_head = (kb_q_head + 1) % KB_CMD_QUEUE_SIZE;
                kb_q_count--;
                kb_cmdq_state = KBQ_IDLE;

                for (int i = 0; i < 2; i++)
                {
                    if (kernel->inb(KEYBOARD_STATUS) & 0x01)
                    {
                        uint8_t idb = kernel->inb(KEYBOARD_DATA);
                        (void)idb; // Ignore device ID bytes for now
                    }
                }

                kbq_start_next();
                continue;
            }
        }

        keyboard_fifo_push(val);
    }
}

