#include "drivers/ddf.h"
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

// Line buffer for canonical input.
static char line_buffer[TTY_LINE_SIZE];
static unsigned line_position = 0;
static int line_ready = 0;

// Input ring buffer.
static volatile char input_fifo[TTY_INPUT_SIZE];
static volatile unsigned input_head = 0;
static volatile unsigned input_tail = 0;

// Output ring buffer for gdterm to read captured output.
static volatile char output_fifo[TTY_OUTPUT_SIZE];
static volatile unsigned output_head = 0;
static volatile unsigned output_tail = 0;

// TTY flags.
static int echo_enabled = 1;
static int canonical_mode = 1;

static inline int input_empty(void)
{
    return input_head == input_tail;
}

static inline int input_full(void)
{
    return ((input_tail + 1) & (TTY_INPUT_SIZE - 1)) == input_head;
}

static inline void input_push(char character)
{
    unsigned next_tail = (input_tail + 1) & (TTY_INPUT_SIZE - 1);

    if (next_tail != input_head)
    {
        input_fifo[input_tail] = character;
        input_tail = next_tail;
    }
}

static inline int input_pop(char *out_character)
{
    if (input_empty())
    {
        return 0;
    }

    *out_character = input_fifo[input_head];
    input_head = (input_head + 1) & (TTY_INPUT_SIZE - 1);

    return 1;
}

static inline unsigned input_count(void)
{
    return (input_tail - input_head) & (TTY_INPUT_SIZE - 1);
}

// Output buffer helpers.
static inline int output_empty(void)
{
    return output_head == output_tail;
}

static inline void output_push(char character)
{
    unsigned next_tail = (output_tail + 1) & (TTY_OUTPUT_SIZE - 1);

    if (next_tail != output_head)
    {
        output_fifo[output_tail] = character;
        output_tail = next_tail;
    }
}

static inline int output_pop(char *out_character)
{
    if (output_empty())
    {
        return 0;
    }

    *out_character = output_fifo[output_head];
    output_head = (output_head + 1) & (TTY_OUTPUT_SIZE - 1);

    return 1;
}

// Push completed line into input buffer.
static void flush_line(void)
{
    for (unsigned index = 0; index < line_position; index++)
    {
        input_push(line_buffer[index]);
    }

    input_push('\n');
    line_position = 0;
    line_ready = 0;
}

// Process a character in canonical mode.
static void canonical_process(char character)
{
    if (character == '\n' || character == '\r')
    {
        if (echo_enabled)
        {
            kernel->printf("\n");
        }

        flush_line();
        line_ready = 1;

        return;
    }

    if (character == '\b' || character == 127)
    {
        if (line_position > 0)
        {
            line_position--;

            if (echo_enabled)
            {
                kernel->printf("\b \b");
            }
        }

        return;
    }

    // Ctrl+U clears the line.
    if (character == 21)
    {
        while (line_position > 0)
        {
            line_position--;

            if (echo_enabled)
            {
                kernel->printf("\b \b");
            }
        }

        return;
    }

    // Ctrl+C sends interrupt, just echo for now.
    if (character == 3)
    {
        if (echo_enabled)
        {
            kernel->printf("^C\n");
        }

        line_position = 0;

        return;
    }

    // Add to line buffer if printable and space is free.
    if (character >= 32 && character < 127 && line_position < TTY_LINE_SIZE - 1)
    {
        line_buffer[line_position++] = character;

        if (echo_enabled)
        {
            char buffer[2] = {character, 0};
            kernel->printf("%s", buffer);
        }
    }
}

// Process a character in raw mode.
static void raw_process(char character)
{
    input_push(character);

    if (echo_enabled)
    {
        char buffer[2] = {character, 0};
        kernel->printf("%s", buffer);
    }
}

// Handle incoming character from keyboard.
static void drv_tty_input_char(char character)
{
    if (canonical_mode)
    {
        canonical_process(character);
    }
    else
    {
        raw_process(character);
    }
}

// Read from the TTY.
static int drv_tty_read(char *buffer, unsigned count)
{
    if (!buffer || count == 0)
    {
        return 0;
    }

    unsigned read_count = 0;

    while (read_count < count)
    {
        asm volatile("cli");

        if (!input_empty())
        {
            char character;
            input_pop(&character);
            asm volatile("sti");
            buffer[read_count++] = character;

            // In canonical mode return on newline.
            if (canonical_mode && character == '\n')
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
static int drv_tty_write(const char *buffer, unsigned count)
{
    if (!buffer)
    {
        return 0;
    }

    for (unsigned index = 0; index < count; index++)
    {
        output_push(buffer[index]);
    }

    return (int)count;
}

// Read from the output buffer for terminal programs like gdterm.
static int drv_tty_read_output(char *buffer, unsigned count)
{
    if (!buffer || count == 0)
    {
        return 0;
    }

    unsigned read_count = 0;

    asm volatile("cli");

    while (read_count < count && !output_empty())
    {
        char character;
        output_pop(&character);
        buffer[read_count++] = character;
    }

    asm volatile("sti");

    return (int)read_count;
}

// Set TTY mode.
static void drv_tty_set_canonical(int enabled)
{
    canonical_mode = enabled ? 1 : 0;
}

// Set echo mode.
static void drv_tty_set_echo(int enabled)
{
    echo_enabled = enabled ? 1 : 0;
}

// Get whether input is available.
static int drv_tty_input_available(void)
{
    if (canonical_mode)
    {
        return line_ready || !input_empty();
    }

    return !input_empty();
}

// Driver init called by loader.
__attribute__((section(".text")))
void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    // Reset state.
    line_position = 0;
    line_ready = 0;
    input_head = 0;
    input_tail = 0;
    output_head = 0;
    output_tail = 0;
    echo_enabled = 1;
    canonical_mode = 1;

    // Register the TTY driver in the kernel.
    if (kernel->tty_register)
    {
        kernel->tty_register(drv_tty_read, drv_tty_write, drv_tty_input_char,
                             drv_tty_set_canonical, drv_tty_set_echo,
                             drv_tty_input_available, drv_tty_read_output);
    }

    kernel->printf("[DRIVER] TTY Driver Installed\n");
}

// Driver exit called by loader.
__attribute__((section(".text")))
void ddf_driver_exit(void)
{
    kernel->printf("[DRIVER] TTY Driver Uninstalled\n");
}

// IRQ handler, not used.
__attribute__((section(".text")))
void ddf_driver_irq(unsigned irq_number, void *context)
{
    (void)irq_number;
    (void)context;
}
