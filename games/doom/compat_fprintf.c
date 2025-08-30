#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// -include compat_stdio.h gör att makron är aktiva här också,
// så slå av dem innan vi definierar funktionerna:
#ifdef vfprintf
#undef vfprintf
#endif
#ifdef fprintf
#undef fprintf
#endif
#ifdef fputs
#undef fputs
#endif
#ifdef fputc
#undef fputc
#endif

// Dessa symboler finns redan i din miljö
extern int printf(const char *fmt, ...);
extern int vsnprintf(char *str, size_t size, const char *fmt, va_list ap);

int __compat_vfprintf(void *stream, const char *fmt, va_list ap)
{
    (void)stream;
    char buf[1024];

    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    if (n < 0) return n;

    // Klipp vid buffertgräns om det behövs
    if (n >= (int)sizeof buf) {
        buf[sizeof buf - 1] = '\0';
        n = (int)sizeof buf - 1;
    }

    printf("%s", buf);
    return n;
}

int __compat_fprintf(void *stream, const char *fmt, ...)
{
    (void)stream;
    va_list ap;
    va_start(ap, fmt);
    int r = __compat_vfprintf(stream, fmt, ap);
    va_end(ap);
    return r;
}

int __compat_fputs(const char *s, void *stream)
{
    (void)stream;
    printf("%s", s);   // ingen newline
    return 0;
}

int __compat_fputc(int c, void *stream)
{
    (void)stream;
    char b[2] = { (char)c, 0 };
    printf("%s", b);
    return (unsigned char)c;
}

