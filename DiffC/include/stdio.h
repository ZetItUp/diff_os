#pragma once
#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DIFFC_HAS_SSIZE_T
#define DIFFC_HAS_SSIZE_T
typedef long ssize_t;   // POSIX typedef
#endif

int putchar(int c);
int puts(const char *s);

/* Non-standard helper kept for compatibility */
void print(const char *s);

int printf(const char *fmt, ...);
int vprintf(const char *fmt, va_list ap);

int snprintf(char *dst, size_t size, const char *fmt, ...);
int vsnprintf(char *dst, size_t size, const char *fmt, va_list ap);

int read_line(char *buf, size_t size);
ssize_t getline(char **lineptr, size_t *size);

#ifdef __cplusplus
}
#endif

