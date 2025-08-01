#include "drivers/driver.h"
#include "io.h"
#include "stdio.h"
#include "stddef.h"
#include "console.h"
#include "pic.h"

#define KEYBOARD_DATA       0x60
#define KEYBOARD_COMMAND    0x64
#define KEYBOARD_STATUS     0x64

#define KB_CMD_QUEUE_SIZE   9

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
    KBQ_ERROR
} kb_cmdq_state_t;

static kb_cmd_t kb_cmdq[KB_CMD_QUEUE_SIZE];
static int kb_q_head = 0;
static int kb_q_tail = 0;
static int kb_q_count = 0;
static kb_cmdq_state_t kb_cmdq_state = KBQ_IDLE;
static int kb_resend_limit = 3;

static void wait_input(void)
{
    for(int i = 0; i < 10000; i++)
    {
        if (!(inb(KEYBOARD_STATUS) & 0x02))
        {
            return;
        }
    }
}

static void wait_output(void)
{
    for(int i = 0; i < 10000; i++)
    {
        if (inb(KEYBOARD_STATUS) & 0x01)
        {
            return;
        }
    }
}

// Queue 
static void kbq_send_cmd(kb_cmd_t *cmd)
{
    printf("SEND cmd=%x, has_data=%d, data=%x\n", cmd->command, cmd->has_data, cmd->data);
    wait_input();
    
    kb_cmdq_state = KBQ_WAIT_ACK;
    outb(KEYBOARD_DATA, cmd->command);

    if(cmd->has_data)
    {
        wait_input();
        outb(KEYBOARD_DATA, cmd->data);
    }

    printf("kbq_send_cmd: now waiting for ack\n");
}

static void kbq_start_next(void)
{
    printf("kbq_start_next: count=%d, state=%d, head=%d, tail=%d\n", kb_q_count, kb_cmdq_state, kb_q_head, kb_q_tail);
    if(kb_q_count == 0)
    {
        kb_cmdq_state = KBQ_IDLE;
        printf("kbq_start_next: now idle\n");

        return;
    }

    kb_cmdq_state = KBQ_SEND;
    kbq_send_cmd(&kb_cmdq[kb_q_head]);
}

static int kbq_enqueue(uint8_t cmd, int has_data, uint8_t data)
{
    printf("ENQUEUE cmd=%x, has_data=%d, data=%x (state=%d)\n", cmd, has_data, data, kb_cmdq_state);

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
    outb(KEYBOARD_COMMAND, 0xAD);

    // Flush output
    while(inb(KEYBOARD_STATUS) & 0x01)
    {
        inb(KEYBOARD_DATA);
    }

    // Controller Self-Test
    wait_input();
    outb(KEYBOARD_COMMAND, 0xAA);
    wait_output();

    uint8_t res = inb(KEYBOARD_DATA);
    if(res != 0x55)
    {
        printf("[DRIVER] Keyboard self-test failed: %x\n", res);
    }

    // Enable keyboard port
    wait_input();
    outb(KEYBOARD_COMMAND, 0xAE);
}

// Driver hooks
static void keyboard_init(void)
{
    i8042_init();

    pic_clear_mask(1);          // Enable IRQ1 in PIC
    kbq_enqueue(0xFF, 0, 0);    // Reset/disable scanning
    //kbq_enqueue(0xED, 1, 0);    // Set LEDs (off)
    kbq_enqueue(0xF4, 0, 0);    // Enable scanning
                                
    printf("[DRIVER] PS/2 Keyboard driver installed!\n");
}

static void keyboard_exit(void)
{
    // Disable keyboard IRQ
    pic_set_mask(1);            // Mask IRQ1 in PIC
    printf("[DRIVER] PS/2 Keyboard driver removed successfully!\n");
}

static void keyboard_irq(void)
{
    uint8_t val = inb(KEYBOARD_DATA);

    uint8_t status = inb(0x64);
if (status & 0x01) {
    uint8_t data = inb(0x60);
    printf("IRQ1: status=%x data=%x\n", status, data);
} else {
    printf("IRQ1: status=%x (NO DATA)\n", status);
}

    // Handle command queue states
    if(kb_cmdq_state == KBQ_WAIT_ACK)
    {
        if(val == 0xFA)
        {
            // ACK
            kb_q_head = (kb_q_head + 1) % KB_CMD_QUEUE_SIZE;
            kb_q_count--;
            kb_cmdq_state = KBQ_IDLE;
            kbq_start_next();

            return;
        }
        else if(val == 0xFE)
        {
            // Resend
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

            return;
        }
        else if(val == 0xAA)
        {
            kb_cmdq_state = KBQ_IDLE;
            kbq_start_next();

            printf("[DRIVER] Keyboard Self-test OK\n");
            return;
        }
        // Fallthrough here, scancode during wait_ack = ignore
    }

    if(kb_cmdq_state == KBQ_WAIT_ACK)
    {
        return;
    }

    if (val == 0xFA || val == 0xFE)
    {
        return;
    }

    // TODO: Implement scan code state machine
    printf("[Keyboard] %x\n", val);

    pic_send_eoi(1);
}

driver_t keyboard_driver =
{
    .name = "PS/2 Keyboard",
    .irq_line = 1,               // IRQ1 is Keyboard
    .init = keyboard_init,
    .exit = keyboard_exit,
    .handle_irq = keyboard_irq
};
