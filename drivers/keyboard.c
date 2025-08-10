#include "drivers/driver.h"
#include "drivers/ddf.h"
#include "io.h"
#include "stdio.h"
#include "stddef.h"
#include "console.h"
#include "pic.h"

#define KEYBOARD_DATA       0x60
#define KEYBOARD_COMMAND    0x64
#define KEYBOARD_STATUS     0x64

#define KB_CMD_QUEUE_SIZE   9

#define KB_FIFO_SIZE        256

// Driver Meta Data
// Assign which IRQ number it uses.
__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 1;

typedef struct
{
    uint8_t command;
    int has_data;
    uint8_t data;
    int retries;
} kb_cmd_t;

typedef enum
{
    KBQ_IDLE,
    KBQ_SEND,
    KBQ_WAIT_ACK,
    KBQ_WAIT_BAT,
    KBQ_ERROR
} kb_cmdq_state_t;

static kernel_exports_t *kernel = 0;

static kb_cmd_t kb_cmdq[KB_CMD_QUEUE_SIZE] = {0};
static int kb_q_head = 0;
static int kb_q_tail = 0;
static int kb_q_count = 0;
static kb_cmdq_state_t kb_cmdq_state = KBQ_IDLE;
static int kb_resend_limit = 3;

static volatile uint8_t kb_fifo[KB_FIFO_SIZE];
static volatile unsigned kb_head = 0;
static volatile unsigned kb_tail = 0;

static inline int keyboard_fifo_empty(void)
{
    return kb_head == kb_tail;
}

static inline int keyboard_fifo_full(void)
{
    return ((kb_tail + 1) & (KB_FIFO_SIZE - 1)) == kb_head;
}

static inline void keyboard_fifo_push(uint8_t b)
{
    unsigned tail = (kb_tail + 1) & (KB_FIFO_SIZE - 1);

    if(tail != kb_head)
    {
        kb_fifo[kb_tail] = b;
        kb_tail = tail;
    }
}

static inline uint8_t keyboard_fifo_pop(void)
{
    uint8_t b = 0;

    if(!keyboard_fifo_empty())
    {
        b = kb_fifo[kb_head];
        kb_head = (kb_head + 1) & (KB_FIFO_SIZE - 1);
    }

    return b;
}

static void wait_input(void)
{
    for(int i = 0; i < 10000; i++)
    {
        if (!(kernel->inb(KEYBOARD_STATUS) & 0x02))
        {
            return;
        }
    }
}

static void wait_output(void)
{
    for(int i = 0; i < 10000; i++)
    {
        if (kernel->inb(KEYBOARD_STATUS) & 0x01)
        {
            return;
        }
    }
}

// Queue 
static void kbq_send_cmd(kb_cmd_t *cmd)
{
    wait_input();
    
    kb_cmdq_state = KBQ_WAIT_ACK;
    kernel->outb(KEYBOARD_DATA, cmd->command);

    if(cmd->has_data)
    {
        wait_input();
        kernel->outb(KEYBOARD_DATA, cmd->data);
    }
}

static void kbq_start_next(void)
{
    if(kb_q_count == 0)
    {
        kb_cmdq_state = KBQ_IDLE;

        return;
    }

    kb_cmdq_state = KBQ_SEND;
    kbq_send_cmd(&kb_cmdq[kb_q_head]);
}

static int kbq_enqueue(uint8_t cmd, int has_data, uint8_t data)
{
    if(kb_q_count >= KB_CMD_QUEUE_SIZE)
    {
        return -1;
    }

    kb_cmd_t *queue = &kb_cmdq[kb_q_tail];
    queue->command = cmd;
    queue->has_data = has_data;
    queue->data = data;
    queue->retries = 0;

    kb_q_tail = (kb_q_tail + 1) % KB_CMD_QUEUE_SIZE;
    kb_q_count++;

    if(kb_cmdq_state == KBQ_IDLE)
    {
        kbq_start_next();
    }

    return 0;
}

static void i8042_init(void)
{
    // Disable keyboard
    wait_input();
    kernel->outb(KEYBOARD_COMMAND, 0xAD);

    // Flush output
    while(kernel->inb(KEYBOARD_STATUS) & 0x01)
    {
        kernel->inb(KEYBOARD_DATA);
    }

    // Controller Self-Test
    wait_input();
    kernel->outb(KEYBOARD_COMMAND, 0xAA);
    wait_output();

    uint8_t res = kernel->inb(KEYBOARD_DATA);
    if(res != 0x55)
    {
        kernel->printf("[DRIVER] Keyboard self-test failed: %x\n", res);
    }

    // Enable keyboard port
    wait_input();
    kernel->outb(KEYBOARD_COMMAND, 0xAE);
}

// System call functions
int keyboard_read_byte(uint8_t *out)
{
    int res = 0;
    asm volatile("cli");

    if(!keyboard_fifo_empty())
    {
        *out = keyboard_fifo_pop();
        
        res = 1;
    }
    asm volatile("sti");

    return res;
}

uint8_t keyboard_read_byte_blocking(void)
{
    for(;;)
    {
        asm volatile("cli");

        if(!keyboard_fifo_empty())
        {
            uint8_t b = keyboard_fifo_pop();
            asm volatile("sti");

            return b;
        }

        asm volatile("sti; hlt");
    }
}

// Driver specific functions
__attribute__((section(".text")))
void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;
    i8042_init();

    // TODO: This needs to be fixed, they can't be here...
    kbq_enqueue(0xFF, 0, 0);    // Reset/disable scanning
    kbq_enqueue(0xF4, 0, 0);    // Enable scanning
    
    kernel->pic_clear_mask(1);  // Unmask IRQ1

    kernel->keyboard_register(keyboard_read_byte, keyboard_read_byte_blocking);    
    kernel->printf("[DRIVER] PS/2 Keyboard driver installed!\n");
}

__attribute__((section(".text")))
void ddf_driver_exit(void)
{
    // Disable keyboard IRQ
    kernel->pic_set_mask(1);            // Mask IRQ1 in PIC
    kernel->printf("[DRIVER] PS/2 Keyboard driver removed successfully!\n");
}

__attribute__((section(".text")))
void ddf_driver_irq(void)
{
    while (kernel->inb(KEYBOARD_STATUS) & 0x01) 
    {
        uint8_t val = kernel->inb(KEYBOARD_DATA);

        if(kb_cmdq_state == KBQ_WAIT_ACK)
        {
            if(val == 0xFA)
            {
                if(kb_cmdq[kb_q_head].command == 0xFF)
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
            else if(val == 0xFE)
            {
                kb_cmdq[kb_q_head].retries++;
                
                if(kb_cmdq[kb_q_head].retries < kb_resend_limit)
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

        if(kb_cmdq_state == KBQ_WAIT_BAT)
        {
            if(val == 0xAA)
            {
                kb_q_head = (kb_q_head + 1) % KB_CMD_QUEUE_SIZE;
                kb_q_count--;
                kb_cmdq_state = KBQ_IDLE;
                
                for(int i = 0; i < 2; i++)
                {
                    if(kernel->inb(KEYBOARD_STATUS) & 0x01)
                    {
                        uint8_t idb = kernel->inb(KEYBOARD_DATA);
                        (void)idb;  // Drop this for now
                    }
                }

                kbq_start_next();

                continue;
            }
        }
        
        keyboard_fifo_push(val);
    }
}

