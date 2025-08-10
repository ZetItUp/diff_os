// DiffC EXL: printf.c
// Minimal, robust printf/snprintf utan asm, för i386 freestanding.

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include "syscall.h"   // system_putchar/system_print om du vill, men vi kör teckenvis

#ifndef va_copy
#  ifdef __va_copy
#    define va_copy(dest, src) __va_copy(dest, src)
#  else
#    define va_copy(dest, src) ((dest) = (src))   /* sista utvägen */
#  endif
#endif

// ---- små helpers ----
static void putch_sink(int ch, void *ctx) {
    (void)ctx;
    system_putchar((char)ch);
}

struct bufctx { char *buf; size_t cap; size_t len; };
static void buf_sink(int ch, void *ctx) {
    struct bufctx *b = (struct bufctx*)ctx;
    if (b->len + 1 < b->cap) {          // lämna plats för '\0'
        b->buf[b->len] = (char)ch;
    }
    b->len++;
}

static void out_repeat(void (*sink)(int,void*), void *ctx, char c, int n) {
    for (int i=0;i<n;i++) sink(c, ctx);
}

static int utoa_rev(uint32_t v, unsigned base, char *tmp, int upper) {
    static const char lo[] = "0123456789abcdef";
    static const char up[] = "0123456789ABCDEF";
    const char *digits = upper ? up : lo;
    int i = 0;
    if (v == 0) { tmp[i++] = '0'; return i; }
    while (v) { tmp[i++] = digits[v % base]; v /= base; }
    return i;
}

static void out_uint(void (*sink)(int,void*), void *ctx,
                     uint32_t v, unsigned base, int width, int pad0, int upper, int prefix)
{
    char tmp[32];
    int n = utoa_rev(v, base, tmp, upper);
    int extra = 0;
    if (prefix && base == 16) extra = 2;     // "0x"
    int pad = (width > (n+extra)) ? (width - (n+extra)) : 0;

    if (!pad0) out_repeat(sink, ctx, ' ', pad);
    if (prefix && base == 16) { sink('0', ctx); sink(upper?'X':'x', ctx); }
    if (pad0) out_repeat(sink, ctx, '0', pad);
    while (n--) sink(tmp[n], ctx);
}

static void out_int(void (*sink)(int,void*), void *ctx, int32_t v, int width, int pad0)
{
    uint32_t u = (v < 0) ? (uint32_t)(-v) : (uint32_t)v;
    int neg = (v < 0);
    char tmp[32];
    int n = utoa_rev(u, 10, tmp, 0);
    int pad = (width > (n + (neg?1:0))) ? (width - (n + (neg?1:0))) : 0;

    if (!pad0) out_repeat(sink, ctx, ' ', pad);
    if (neg) sink('-', ctx);
    if (pad0) out_repeat(sink, ctx, '0', pad);
    while (n--) sink(tmp[n], ctx);
}

static int vcbprintf(void (*sink)(int,void*), void *ctx, const char *fmt, va_list ap)
{
    int out = 0;
    for (const char *p = fmt; *p; ++p) {
        if (*p != '%') { sink(*p, ctx); out++; continue; }

        // parse: % [0] [width] [specifier]
        p++;
        int pad0 = 0, width = 0, upper = 0;
        enum { LEN_NONE, LEN_H, LEN_L, LEN_Z } len = LEN_NONE;

        if (*p == '0') { pad0 = 1; p++; }
        while (*p >= '0' && *p <= '9') { width = width*10 + (*p - '0'); p++; }
        if (*p == 'h') { len = LEN_H; p++; }
        else if (*p == 'l') { len = LEN_L; p++; }
        else if (*p == 'z') { len = LEN_Z; p++; }
        char sp = *p ? *p : '\0';

        switch (sp) {
            case '%': sink('%', ctx); out++; break;
            case 'c': {
                int ch = va_arg(ap, int);
                sink(ch, ctx); out++;
                break;
            }
            case 's': {
                const char *s = va_arg(ap, const char*);
                if (!s) s = "(null)";
                // width/padding vänsterjusterad som standard (ingen '-')
                int len = 0; const char *t = s;
                while (*t++) len++;
                if (width > len) { out_repeat(sink, ctx, ' ', width - len); out += (width - len); }
                for (; *s; ++s) { sink(*s, ctx); out++; }
                break;
            }
            case 'd':
            case 'i': {
                int32_t v;
                if (len == LEN_L || len == LEN_Z)     v = (int32_t)va_arg(ap, long);
                else                                   v = va_arg(ap, int);
                struct { void (*fn)(int,void*); void* ctx; int *cnt; } w = { sink, ctx, &out };
                void wc(int ch, void *cctx){ struct { void (*fn)(int,void*); void* ctx; int *cnt; }*w=(void*)cctx; w->fn(ch,w->ctx); (*w->cnt)++; }
                out_int((void(*)(int,void*))wc, &w, v, width, pad0);
                break;
                }
            case 'u':
            case 'x':
            case 'X': 
                {
                    uint32_t v;
                    if (len == LEN_L || len == LEN_Z)     v = (uint32_t)va_arg(ap, unsigned long);
                    else                                   v = va_arg(ap, unsigned int);
                    upper = (sp == 'X');
                    struct { void (*fn)(int,void*); void* ctx; int *cnt; } w = { sink, ctx, &out };
                    void wc(int ch, void *cctx){ struct { void (*fn)(int,void*); void* ctx; int *cnt; }*w=(void*)cctx; w->fn(ch,w->ctx); (*w->cnt)++; }
                    out_uint((void(*)(int,void*))wc, &w, v, (sp=='u')?10:16, width, pad0, upper, 0);
                    break;
                }
            case 'p': {
                uintptr_t v = (uintptr_t)va_arg(ap, void*);
                struct { void (*fn)(int,void*); void* ctx; int *cnt; } w = { sink, ctx, &out };
                void wc(int ch, void *cctx){ struct { void (*fn)(int,void*); void* ctx; int *cnt; }*w=(void*)cctx; w->fn(ch,w->ctx); (*w->cnt)++; }
                sink('0', ctx); sink('x', ctx); out += 2;
                out_uint((void(*)(int,void*))wc, &w, (uint32_t)v, 16, (width>2)?(width-2):0, 1, 0, 0);
                break;
            }
            default:
                // okänd spec → skriv bokstavligen
                sink('%', ctx); sink(sp, ctx); out += 2;
                break;
        }
    }
    return out;
}

// ---- publika API:n ----
int vprintf(const char *fmt, va_list ap) {
    va_list cp; va_copy(cp, ap);
    int n = vcbprintf(putch_sink, NULL, fmt, cp);
    return n;
}

int printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vcbprintf(putch_sink, NULL, fmt, ap);
    va_end(ap);
    return n;
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap) {
    struct bufctx b = { buf, size, 0 };
    va_list cp; va_copy(cp, ap);
    int n = vcbprintf(buf_sink, &b, fmt, cp);
    va_end(cp);
    size_t pos = (b.len < b.cap) ? b.len : (b.cap - 1);
    b.buf[pos] = '\0';
    return n;
}

int snprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return n;
}

int puts(const char *s) {
    if (!s) s = "(null)";
    while (*s) system_putchar(*s++);
    system_putchar('\n');
    return 0;
}

int putchar(int c) {
    system_putchar((char)c);
    return (unsigned char)c;
}

