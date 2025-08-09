#ifndef STDIO_H
#define STDIO_H

#include "stdarg.h"
#include "stddef.h"

char *strstr(const char *haystack, const char *needle);
void vprintf(const char *fmt, va_list args);
void printf(const char *fmt, ...);
int snprintf(char *str, size_t size, const char *format, ...);


#endif
