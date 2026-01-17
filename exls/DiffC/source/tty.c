#include <tty.h>
#include <syscall.h>
#include <string.h>

int tty_read(char *buf, size_t count)
{
    if (!buf || count == 0)
    {
        return 0;
    }

    return system_tty_read(buf, (uint32_t)count);
}

int tty_write(const char *buf, size_t count)
{
    if (!buf || count == 0)
    {
        return 0;
    }

    return system_tty_write(buf, (uint32_t)count);
}

char *tty_gets(char *buf, size_t size)
{
    if (!buf || size == 0)
    {
        return NULL;
    }

    int n = tty_read(buf, size - 1);

    if (n <= 0)
    {
        return NULL;
    }

    buf[n] = '\0';

    return buf;
}

int tty_puts(const char *str)
{
    if (!str)
    {
        return -1;
    }

    size_t len = strlen(str);

    return tty_write(str, len);
}

int tty_device_count(void)
{
    return system_tty_device_count();
}

int tty_set_device(int id)
{
    return system_tty_set_device(id);
}

int tty_get_device(void)
{
    return system_tty_get_device();
}

int tty_allocate_device(void)
{
    return system_tty_allocate_device();
}
