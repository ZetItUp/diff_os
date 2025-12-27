#include "stdint.h"
#include "stddef.h"
#include "interfaces.h"
#include "console.h"

tty_exports_t g_tty = {0};

void tty_register(
    int (*read_fn)(char*, unsigned),
    int (*write_fn)(const char*, unsigned),
    void (*input_fn)(char),
    void (*set_canonical_fn)(int),
    void (*set_echo_fn)(int),
    int (*available_fn)(void),
    int (*read_output_fn)(char*, unsigned)
)
{
    g_tty.tty_read = read_fn;
    g_tty.tty_write = write_fn;
    g_tty.tty_input_char = input_fn;
    g_tty.tty_set_canonical = set_canonical_fn;
    g_tty.tty_set_echo = set_echo_fn;
    g_tty.tty_input_available = available_fn;
    g_tty.tty_read_output = read_output_fn;
}

int tty_read(char *buf, unsigned count)
{
    if (!g_tty.tty_read)
    {
        return -1;
    }

    return g_tty.tty_read(buf, count);
}

int tty_write(const char *buf, unsigned count)
{
    if (!g_tty.tty_write)
    {
        return -1;
    }

    return g_tty.tty_write(buf, count);
}

void tty_input_char(char c)
{
    if (g_tty.tty_input_char)
    {
        g_tty.tty_input_char(c);
    }
}

void tty_set_canonical(int enabled)
{
    if (g_tty.tty_set_canonical)
    {
        g_tty.tty_set_canonical(enabled);
    }
}

void tty_set_echo(int enabled)
{
    if (g_tty.tty_set_echo)
    {
        g_tty.tty_set_echo(enabled);
    }
}

int tty_input_available(void)
{
    if (!g_tty.tty_input_available)
    {
        return 0;
    }

    return g_tty.tty_input_available();
}

int tty_read_output(char *buf, unsigned count)
{
    if (!g_tty.tty_read_output)
    {
        return 0;
    }

    return g_tty.tty_read_output(buf, count);
}
