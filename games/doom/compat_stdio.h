#pragma once

// Ta in riktiga prototyper först så att makron inte stör dem.
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>

// __compat_* deklarationer – implementeras i compat_fprintf.c
int __compat_vfprintf(void *stream, const char *fmt, va_list ap);
int __compat_fprintf(void *stream, const char *fmt, ...);
int __compat_fputs(const char *s, void *stream);
int __compat_fputc(int c, void *stream);

// Säkerställ att inga tidigare definitioner ligger kvar
#undef vfprintf
#undef fprintf
#undef fputs
#undef fputc

// Mappa alla anrop i koden till våra kompatibla varianter.
// OBS: stream används inte – vi skriver till konsolen via printf.
#define vfprintf(stream, fmt, ap) __compat_vfprintf((void*)(uintptr_t)(stream), (fmt), (ap))
#define fprintf(stream, ...)      __compat_fprintf((void*)(uintptr_t)(stream), __VA_ARGS__)
#define fputs(s, stream)          __compat_fputs((s), (void*)(uintptr_t)(stream))
#define fputc(c, stream)          __compat_fputc((c), (void*)(uintptr_t)(stream))

