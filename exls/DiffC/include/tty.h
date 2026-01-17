#pragma once

#include <stddef.h>

// Read from TTY (blocking in canonical mode until newline)
int tty_read(char *buf, size_t count);

// Write to TTY
int tty_write(const char *buf, size_t count);

// Read a line from TTY (includes newline, null-terminated)
char *tty_gets(char *buf, size_t size);

// Write a string to TTY
int tty_puts(const char *str);

// Number of TTY devices provided by the kernel
int tty_device_count(void);

// Set the active TTY for the calling process
int tty_set_device(int id);

// Get the currently-selected TTY for the calling process
int tty_get_device(void);

// Allocate a fresh TTY whenever possible
int tty_allocate_device(void);
