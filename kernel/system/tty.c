// tty.c - simple ring-buffer tty endpoints for user stdout/stderr

#include "system/tty.h"
#include "system/process.h"
#include "system/usercopy.h"
#include "heap.h"
#include "string.h"
#include "console.h"
#include "serial.h"

static inline uint32_t tty_count(const tty_t *t)
{
    return t->head - t->tail;
}

tty_t *tty_create(void)
{
    tty_t *t = (tty_t *)kmalloc(sizeof(tty_t));

    if (!t)
    {
        return NULL;
    }

    memset(t, 0, sizeof(*t));
    spinlock_init(&t->lock);
    t->refcount = 1;

    return t;
}

void tty_add_ref(tty_t *t)
{
    if (!t)
    {
        return;
    }

    uint32_t flags;
    spin_lock_irqsave(&t->lock, &flags);
    t->refcount++;
    spin_unlock_irqrestore(&t->lock, flags);
}

void tty_destroy(tty_t *t)
{
    if (!t)
    {
        return;
    }

    uint32_t flags;
    spin_lock_irqsave(&t->lock, &flags);
    t->refcount--;
    int count = t->refcount;
    spin_unlock_irqrestore(&t->lock, flags);

    if (count <= 0)
    {
        kfree(t);
    }
}

void tty_putc(int ch)
{
    process_t *p = process_current();

    if (p && p->tty_out)
    {
        char c = (char)ch;

        if (tty_write(p->tty_out, &c, 1) > 0)
        {
            return;
        }
    }

    putch((char)ch & 0xFF);
}

int tty_write(tty_t *t, const void *buf, size_t len)
{
    if (!t || !buf || len == 0)
    {
        return 0;
    }

    const uint8_t *p = (const uint8_t *)buf;
    process_t *writer = process_current();
    uint8_t attr = writer ? writer->tty_attr : 0x07;
    uint32_t flags;
    spin_lock_irqsave(&t->lock, &flags);

    uint32_t written = 0;
    while (written < len && tty_count(t) < (TTY_BUF_SIZE - 1u))
    {
        uint32_t idx = t->head & TTY_BUF_MASK;
        t->buf[idx] = p[written];
        t->colors[idx] = attr;
        t->head++;
        written++;
    }

    spin_unlock_irqrestore(&t->lock, flags);

#ifdef DIFF_DEBUG
    // Print to serial debug output when debugging is enabled
    for (uint32_t i = 0; i < written; i++)
    {
        char c = (char)p[i];
        if (c == '\n')
        {
            serial_putc('\r');
        }
        serial_putc(c);
    }
#endif

    return (int)written;
}

static int tty_read_internal(tty_t *t, void *buf, uint8_t *colors, size_t len)
{
    if (!t || !buf || len == 0)
    {
        return 0;
    }

    uint8_t *p = (uint8_t *)buf;
    uint32_t flags;
    spin_lock_irqsave(&t->lock, &flags);

    uint32_t read = 0;
    while (read < len && t->tail != t->head)
    {
        p[read] = t->buf[t->tail & TTY_BUF_MASK];
        if (colors)
        {
            colors[read] = t->colors[t->tail & TTY_BUF_MASK];
        }
        t->tail++;
        read++;
    }

    spin_unlock_irqrestore(&t->lock, flags);
    return (int)read;
}

int tty_read(tty_t *t, void *buf, size_t len)
{
    return tty_read_internal(t, buf, NULL, len);
}

// -----------------------------------------------------------------------------
// Syscall helpers for user buffers (current process only)
// -----------------------------------------------------------------------------
int system_tty_write_user(const void *user_buf, uint32_t len)
{
    if (!user_buf || len == 0)
    {
        return 0;
    }

    process_t *p = process_current();
    if (!p || !p->tty_out)
    {
        return -1;
    }

    uint32_t chunk = (len > TTY_BUF_SIZE) ? TTY_BUF_SIZE : len;
    uint8_t *kbuf = (uint8_t *)kmalloc(chunk);
    if (!kbuf)
    {
        return -1;
    }

    if (copy_from_user(kbuf, user_buf, chunk) != 0)
    {
        kfree(kbuf);
        return -1;
    }

    int wrote = tty_write(p->tty_out, kbuf, chunk);
    kfree(kbuf);
    return wrote;
}

int system_tty_read_user(void *user_buf, uint32_t len, int mode, void *color_buf)
{
    if (!user_buf || len == 0)
    {
        return 0;
    }

    process_t *p = process_current();
    if (!p)
    {
        return -1;
    }

    uint32_t chunk = (len > TTY_BUF_SIZE) ? TTY_BUF_SIZE : len;
    uint8_t *kbuf = (uint8_t *)kmalloc(chunk);
    if (!kbuf)
    {
        return -1;
    }

    tty_t *target = NULL;

    if (mode == TTY_READ_MODE_OUTPUT && p->tty_out)
    {
        target = p->tty_out;
    }

    if (!target)
    {
        target = p->tty_in;
    }

    if (!target)
    {
        kfree(kbuf);
        return -1;
    }

    int need_colors = color_buf && mode == TTY_READ_MODE_OUTPUT;
    uint8_t *attr_buf = NULL;

    if (need_colors)
    {
        attr_buf = (uint8_t *)kmalloc(chunk);
        if (!attr_buf)
        {
            kfree(kbuf);
            return -1;
        }
    }

    int rd = tty_read_internal(target, kbuf, attr_buf, chunk);
    if (rd > 0)
    {
        if (copy_to_user(user_buf, kbuf, (size_t)rd) != 0)
        {
            rd = -1;
        }
        else if (need_colors)
        {
            if (copy_to_user(color_buf, attr_buf, (size_t)rd) != 0)
            {
                rd = -1;
            }
        }
    }

    if (attr_buf)
    {
        kfree(attr_buf);
    }
    kfree(kbuf);
    return rd;
}
