#ifndef STDIO_H
#define STDIO_H

#include "stdarg.h"

void vprintf(const char *fmt, va_list args);
void printf(const char *fmt, ...);

#endif
