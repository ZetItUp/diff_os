#pragma once

#include "stdint.h"
#include "stddef.h"
#include "system/spinlock.h"

#define TTY_BUF_SIZE 4096u
#define TTY_BUF_MASK (TTY_BUF_SIZE - 1u)

typedef struct tty
{
    uint8_t    buf[TTY_BUF_SIZE];
    uint32_t   head;
    uint32_t   tail;
    spinlock_t lock;
} tty_t;

tty_t *tty_create(void);
void   tty_destroy(tty_t *t);
int    tty_write(tty_t *t, const void *buf, size_t len);
int    tty_read(tty_t *t, void *buf, size_t len);

// Syscall helpers for user buffers
int system_tty_write_user(const void *user_buf, uint32_t len);
int system_tty_read_user(void *user_buf, uint32_t len);
