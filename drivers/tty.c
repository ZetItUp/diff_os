#include "drivers/ddf.h"
#include "drivers/device.h"
#include "interfaces.h"
#include "stdint.h"
#include "stddef.h"

#define TTY_LINE_SIZE    256
#define TTY_INPUT_SIZE   1024
#define TTY_OUTPUT_SIZE  4096

// This driver does not use interrupts.
__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

// Kernel exports from loader.
static volatile kernel_exports_t *kernel = 0;

typedef struct tty_device_state
{
    device_t *dev;
    char line_buffer[TTY_LINE_SIZE];
    unsigned line_position;
    int line_ready;
    volatile char input_fifo[TTY_INPUT_SIZE];
    volatile unsigned input_head;
    volatile unsigned input_tail;
    volatile char output_fifo[TTY_OUTPUT_SIZE];
    volatile unsigned output_head;
    volatile unsigned output_tail;
    int echo_enabled;
    int canonical_mode;
} tty_device_state_t;

// Device registration
static tty_device_state_t g_tty_devices[1];
static tty_device_state_t *g_tty_primary = 0;

static inline int input_empty(tty_device_state_t *tty)
{
    return tty->input_head == tty->input_tail;
}

static inline int input_full(tty_device_state_t *tty)
{
    return ((tty->input_tail + 1) & (TTY_INPUT_SIZE - 1)) == tty->input_head;
}

static inline void input_push(tty_device_state_t *tty, char character)
{
    unsigned next_tail = (tty->input_tail + 1) & (TTY_INPUT_SIZE - 1);

    if (next_tail != tty->input_head)
    {
        tty->input_fifo[tty->input_tail] = character;
        tty->input_tail = next_tail;
    }
}

static inline int input_pop(tty_device_state_t *tty, char *out_character)
{
    if (input_empty(tty))
    {
        return 0;
    }

    *out_character = tty->input_fifo[tty->input_head];
    tty->input_head = (tty->input_head + 1) & (TTY_INPUT_SIZE - 1);

    return 1;
}

static inline unsigned input_count(tty_device_state_t *tty)
{
    return (tty->input_tail - tty->input_head) & (TTY_INPUT_SIZE - 1);
}

// Output buffer helpers.
static inline int output_empty(tty_device_state_t *tty)
{
    return tty->output_head == tty->output_tail;
}

static inline void output_push(tty_device_state_t *tty, char character)
{
    unsigned next_tail = (tty->output_tail + 1) & (TTY_OUTPUT_SIZE - 1);

    if (next_tail != tty->output_head)
    {
        tty->output_fifo[tty->output_tail] = character;
        tty->output_tail = next_tail;
    }
}

static inline int output_pop(tty_device_state_t *tty, char *out_character)
{
    if (output_empty(tty))
    {
        return 0;
    }

    *out_character = tty->output_fifo[tty->output_head];
    tty->output_head = (tty->output_head + 1) & (TTY_OUTPUT_SIZE - 1);

    return 1;
}

// Push completed line into input buffer.
static void flush_line(tty_device_state_t *tty)
{
    for (unsigned index = 0; index < tty->line_position; index++)
    {
        input_push(tty, tty->line_buffer[index]);
    }

    input_push(tty, '\n');
    tty->line_position = 0;
    tty->line_ready = 0;
}

// Process a character in canonical mode.
static void canonical_process(tty_device_state_t *tty, char character)
{
    if (character == '\n' || character == '\r')
    {
        if (tty->echo_enabled)
        {
            kernel->printf("\n");
        }

        flush_line(tty);
        tty->line_ready = 1;

        return;
    }

    if (character == '\b' || character == 127)
    {
        if (tty->line_position > 0)
        {
            tty->line_position--;

            if (tty->echo_enabled)
            {
                kernel->printf("\b \b");
            }
        }

        return;
    }

    // Ctrl+U clears the line.
    if (character == 21)
    {
        while (tty->line_position > 0)
        {
            tty->line_position--;

            if (tty->echo_enabled)
            {
                kernel->printf("\b \b");
            }
        }

        return;
    }

    // Ctrl+C sends interrupt, just echo for now.
    if (character == 3)
    {
        if (tty->echo_enabled)
        {
            kernel->printf("^C\n");
        }

        tty->line_position = 0;

        return;
    }

    // Add to line buffer if printable and space is free.
    if (character >= 32 && character < 127 && tty->line_position < TTY_LINE_SIZE - 1)
    {
        tty->line_buffer[tty->line_position++] = character;

        if (tty->echo_enabled)
        {
            char buffer[2] = {character, 0};
            kernel->printf("%s", buffer);
        }
    }
}

// Process a character in raw mode.
static void raw_process(tty_device_state_t *tty, char character)
{
    input_push(tty, character);

    if (tty->echo_enabled)
    {
        char buffer[2] = {character, 0};
        kernel->printf("%s", buffer);
    }
}

// Handle incoming character from keyboard.
static void tty_input_char_device(tty_device_state_t *tty, char character)
{
    if (!tty)
    {
        return;
    }

    if (tty->canonical_mode)
    {
        canonical_process(tty, character);
    }
    else
    {
        raw_process(tty, character);
    }
}

// Read from the TTY.
static int tty_read_device(tty_device_state_t *tty, char *buffer, unsigned count)
{
    if (!buffer || count == 0)
    {
        return 0;
    }

    if (!tty)
    {
        return 0;
    }

    unsigned read_count = 0;

    while (read_count < count)
    {
        asm volatile("cli");

        if (!input_empty(tty))
        {
            char character;
            input_pop(tty, &character);
            asm volatile("sti");
            buffer[read_count++] = character;

            // In canonical mode return on newline.
            if (tty->canonical_mode && character == '\n')
            {
                break;
            }
        }
        else
        {
            asm volatile("sti");

            if (read_count > 0)
            {
                break;
            }

            // Block waiting for input.
            asm volatile("hlt");
        }
    }


    return (int)read_count;
}

// Write to the TTY and store it for terminal programs.
// Output is not sent to the console.
static int tty_write_device(tty_device_state_t *tty, const char *buffer, unsigned count)
{
    if (!buffer)
    {
        return 0;
    }

    if (!tty)
    {
        return 0;
    }

    for (unsigned index = 0; index < count; index++)
    {
        output_push(tty, buffer[index]);
    }


    return (int)count;
}

// Read from the output buffer for terminal programs like gdterm.
static int tty_read_output_device(tty_device_state_t *tty, char *buffer, unsigned count)
{
    if (!buffer || count == 0)
    {
        return 0;
    }

    if (!tty)
    {
        return 0;
    }

    unsigned read_count = 0;

    asm volatile("cli");

    while (read_count < count && !output_empty(tty))
    {
        char character;
        output_pop(tty, &character);
        buffer[read_count++] = character;
    }

    asm volatile("sti");


    return (int)read_count;
}

// Set TTY mode.
static void tty_set_canonical_device(tty_device_state_t *tty, int enabled)
{
    if (!tty)
    {
        return;
    }

    tty->canonical_mode = enabled ? 1 : 0;
}

// Set echo mode.
static void tty_set_echo_device(tty_device_state_t *tty, int enabled)
{
    if (!tty)
    {
        return;
    }

    tty->echo_enabled = enabled ? 1 : 0;
}

// Get whether input is available.
static int tty_input_available_device(tty_device_state_t *tty)
{
    if (!tty)
    {
        return 0;
    }

    if (tty->canonical_mode)
    {
        return tty->line_ready || !input_empty(tty);
    }


    return !input_empty(tty);
}

// Kernel-level TTY hooks
static void drv_tty_input_char(char character)
{
    tty_input_char_device(g_tty_primary, character);
}

static int drv_tty_read(char *buffer, unsigned count)
{
    return tty_read_device(g_tty_primary, buffer, count);
}

static int drv_tty_write(const char *buffer, unsigned count)
{
    return tty_write_device(g_tty_primary, buffer, count);
}

static int drv_tty_read_output(char *buffer, unsigned count)
{
    return tty_read_output_device(g_tty_primary, buffer, count);
}

static void drv_tty_set_canonical(int enabled)
{
    tty_set_canonical_device(g_tty_primary, enabled);
}

static void drv_tty_set_echo(int enabled)
{
    tty_set_echo_device(g_tty_primary, enabled);
}

static int drv_tty_input_available(void)
{
    return tty_input_available_device(g_tty_primary);
}

// Device operations
static int tty_dev_read(device_t *dev, char *buffer, unsigned count)
{
    tty_device_state_t *tty = (tty_device_state_t *)dev->private_data;


    return tty_read_device(tty, buffer, count);
}

static int tty_dev_write(device_t *dev, const char *buffer, unsigned count)
{
    tty_device_state_t *tty = (tty_device_state_t *)dev->private_data;


    return tty_write_device(tty, buffer, count);
}

static void tty_dev_input_char(device_t *dev, char c)
{
    tty_device_state_t *tty = (tty_device_state_t *)dev->private_data;
    tty_input_char_device(tty, c);
}

static int tty_dev_input_available(device_t *dev)
{
    tty_device_state_t *tty = (tty_device_state_t *)dev->private_data;


    return tty_input_available_device(tty);
}

static void tty_dev_set_canonical(device_t *dev, int enabled)
{
    tty_device_state_t *tty = (tty_device_state_t *)dev->private_data;
    tty_set_canonical_device(tty, enabled);
}

static void tty_dev_set_echo(device_t *dev, int enabled)
{
    tty_device_state_t *tty = (tty_device_state_t *)dev->private_data;
    tty_set_echo_device(tty, enabled);
}

static int tty_dev_get_canonical(device_t *dev)
{
    tty_device_state_t *tty = (tty_device_state_t *)dev->private_data;


    return tty ? tty->canonical_mode : 0;
}

static int tty_dev_get_echo(device_t *dev)
{
    tty_device_state_t *tty = (tty_device_state_t *)dev->private_data;


    return tty ? tty->echo_enabled : 0;
}

static int tty_dev_read_output(device_t *dev, char *buffer, unsigned count)
{
    tty_device_state_t *tty = (tty_device_state_t *)dev->private_data;


    return tty_read_output_device(tty, buffer, count);
}

static tty_device_t g_tty_ops =
{
    .read = tty_dev_read,
    .write = tty_dev_write,
    .input_char = tty_dev_input_char,
    .input_available = tty_dev_input_available,
    .set_canonical = tty_dev_set_canonical,
    .set_echo = tty_dev_set_echo,
    .get_canonical = tty_dev_get_canonical,
    .get_echo = tty_dev_get_echo,
    .read_output = tty_dev_read_output,
};

// Driver init called by loader.
__attribute__((section(".text")))
void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    // Reset state.
    g_tty_primary = &g_tty_devices[0];
    g_tty_primary->dev = 0;
    g_tty_primary->line_position = 0;
    g_tty_primary->line_ready = 0;
    g_tty_primary->input_head = 0;
    g_tty_primary->input_tail = 0;
    g_tty_primary->output_head = 0;
    g_tty_primary->output_tail = 0;
    g_tty_primary->echo_enabled = 1;
    g_tty_primary->canonical_mode = 1;

    // Register the TTY driver in the kernel.
    if (kernel->tty_register)
    {
        kernel->tty_register(drv_tty_read, drv_tty_write, drv_tty_input_char,
                             drv_tty_set_canonical, drv_tty_set_echo,
                             drv_tty_input_available, drv_tty_read_output);
    }

    // Register device
    g_tty_primary->dev = kernel->device_register(DEVICE_CLASS_TTY, "tty0", &g_tty_ops);

    if (g_tty_primary->dev)
    {
        g_tty_primary->dev->bus_type = BUS_TYPE_VIRTUAL;
        g_tty_primary->dev->private_data = g_tty_primary;
        kernel->strlcpy(g_tty_primary->dev->description, "Virtual TTY", sizeof(g_tty_primary->dev->description));
    }

    kernel->printf("[DRIVER] TTY Driver Installed\n");
}

// Driver exit called by loader.
__attribute__((section(".text")))
void ddf_driver_exit(void)
{
    if (g_tty_primary && g_tty_primary->dev)
    {
        kernel->device_unregister(g_tty_primary->dev);
        g_tty_primary->dev = 0;
    }

    g_tty_primary = 0;
    kernel->printf("[DRIVER] TTY Driver Uninstalled\n");
}

// IRQ handler, not used.
__attribute__((section(".text")))
void ddf_driver_irq(unsigned irq_number, void *context)
{
    (void)irq_number;
    (void)context;
}
