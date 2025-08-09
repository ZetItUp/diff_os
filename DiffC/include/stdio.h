#pragma once
#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int putchar(int c);
int puts(const char *s);

/* Non-standard helper kept for compatibility */
void print(const char *s);

int printf(const char *fmt, ...);
int vprintf(const char *fmt, va_list ap);

int snprintf(char *dst, size_t size, const char *fmt, ...);
int vsnprintf(char *dst, size_t size, const char *fmt, va_list ap);

#ifdef __cplusplus
}
#endif

