#include <diffc_internal.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <syscall.h>
#include <ctype.h>
#include <limits.h>

#ifndef va_copy
#  ifdef __va_copy
#    define va_copy(dest, src) __va_copy(dest, src)
#  else
#    define va_copy(dest, src) ((dest) = (src))
#  endif
#endif

/* ====== Memory Safety Helpers ====== */
#define USERSPACE_MIN 0x40000000
#define USERSPACE_MAX 0xC0000000

struct filesink 
{
    FILE *f;
    char buf[256];
    size_t len;
};

static inline int is_valid_userspace_ptr(const void *p, size_t len)
{
    uint32_t addr = (uint32_t)p;
    return (addr >= USERSPACE_MIN) && 
           (addr + len >= addr) &&  // Check for overflow
           (addr + len <= USERSPACE_MAX);
}

static inline const char *safe_str(const char *s)
{
    return is_valid_userspace_ptr(s, 1) ? s : "(null)";
}

static FILE *coerce_stream(FILE *stream, FILE *tmp_out, int want_write)
{
    /* Är det redan ett giltigt userspace-objekt? */
    if (is_valid_userspace_ptr(stream, sizeof(FILE))) {
        return stream;
    }

    /* Annars, tolka värdet som ett fd (t.ex. 0/1/2) */
    int fd = (int)(uintptr_t)stream;
    tmp_out->file_descriptor = fd;
    tmp_out->flags = FILE_CAN_READ | FILE_CAN_WRITE; /* enkel default */
    tmp_out->error = 0;
    tmp_out->eof   = 0;
    tmp_out->ungot = -1;

    if (want_write && !(tmp_out->flags & FILE_CAN_WRITE)) {
        tmp_out->flags |= FILE_CAN_WRITE;
    }

    return tmp_out;
}

static void file_putch(int ch, void *ctx)
{
    struct filesink *s = (struct filesink*)ctx;
    
    if (s->len < sizeof(s->buf)) 
    {
        s->buf[s->len++] = (char)ch;
    }
    
    if (s->len == sizeof(s->buf)) 
    {
        (void)fwrite(s->buf, 1, s->len, s->f);
        s->len = 0;
    }
}

/* ====== FILE-handling ====== */
static FILE _stdin = {0, FILE_CAN_READ, 0, 0, -1};
static FILE _stdout = {1, FILE_CAN_WRITE, 0, 0, -1};
static FILE _stderr = {2, FILE_CAN_WRITE, 0, 0, -1};

FILE *stdin = &_stdin;
FILE *stdout = &_stdout;
FILE *stderr = &_stderr;

/* ====== File Operations ====== */
static int mode_to_oflags(const char *mode, int *f_flags_out)
{
    if (!mode || !mode[0]) return -1;

    int of = 0;
    int f = 0;
    char m0 = mode[0];
    const char *plus = strchr(mode, '+');

    if (m0 == 'r') {
        of = plus ? O_RDWR : O_RDONLY;
        f = plus ? (FILE_CAN_READ|FILE_CAN_WRITE) : FILE_CAN_READ;
    }
    else if (m0 == 'w') {
        of = plus ? (O_RDWR|O_CREAT|O_TRUNC) : (O_WRONLY|O_CREAT|O_TRUNC);
        f = plus ? (FILE_CAN_READ|FILE_CAN_WRITE) : FILE_CAN_WRITE;
    }
    else if (m0 == 'a') {
        of = plus ? (O_RDWR|O_CREAT|O_APPEND) : (O_WRONLY|O_CREAT|O_APPEND);
        f = plus ? (FILE_CAN_READ|FILE_CAN_WRITE) : FILE_CAN_WRITE;
    }
    else {
        return -1;
    }

    if (f_flags_out) *f_flags_out = f;
    return of;
}

FILE *fopen(const char *path, const char *mode)
{
    if (!is_valid_userspace_ptr(path, 1) || !is_valid_userspace_ptr(mode, 1))
        return NULL;

    int f_flags = 0;
    int o_flags = mode_to_oflags(mode, &f_flags);
    if (o_flags < 0) return NULL;

    int fd = system_open(path, o_flags, 0644);
    if (fd < 0) return NULL;

    FILE *file = (FILE*)malloc(sizeof(FILE));
    if (!file) {
        system_close(fd);
        return NULL;
    }

    file->file_descriptor = fd;
    file->flags = f_flags;
    file->error = 0;
    file->eof = 0;
    file->ungot = -1;

    return file;
}

int fclose(FILE *file)
{
    if (!file) return -1;

    int rc = system_close(file->file_descriptor);
    free(file);
    return rc < 0 ? -1 : 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *file)
{
    if (!file || !ptr || !size || !nmemb) return 0;
    if (!(file->flags & FILE_CAN_READ)) {
        file->error = 1;
        return 0;
    }

    // 32-bit overflow check
    uint32_t total;
    if (__builtin_umul_overflow(size, nmemb, &total)) {
        file->error = 1;
        return 0;
    }

    uint8_t *dst = (uint8_t*)ptr;
    size_t done = 0;

    if (file->ungot >= 0 && done < total) {
        dst[done++] = (uint8_t)file->ungot;
        file->ungot = -1;
    }

    while (done < total) {
        int32_t r = system_read(file->file_descriptor, dst + done, total - done);
        if (r <= 0) {
            if (r == 0) file->eof = 1;
            else file->error = 1;
            break;
        }
        done += r;
    }

    return done / size;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *file)
{
    if (!file || !ptr || !size || !nmemb) return 0;
    if (!(file->flags & FILE_CAN_WRITE)) {
        file->error = 1;
        return 0;
    }

    // 32-bit overflow check
    uint32_t total;
    if (__builtin_umul_overflow(size, nmemb, &total)) {
        file->error = 1;
        return 0;
    }

    const uint8_t *src = (const uint8_t*)ptr;
    size_t done = 0;

    while (done < total) {
        int32_t w = system_write(file->file_descriptor, src + done, total - done);
        if (w <= 0) {
            file->error = 1;
            break;
        }
        done += w;
    }

    return done / size;
}

struct bufctx {
    char *buf;
    size_t cap;
    size_t len;
};

static void putch_sink(int ch, void *ctx) {
    (void)ctx;
    system_putchar((char)ch);
}

static void buf_sink(int ch, void *ctx) {
    struct bufctx *b = (struct bufctx*)ctx;
    if (b->len < b->cap) {
        b->buf[b->len] = (char)ch;
    }
    b->len++;
}

static int vcbprintf(void (*sink)(int, void*), void *ctx, const char *fmt, va_list ap)
{
    if (!is_valid_userspace_ptr(fmt, 1))
    {
        return -1;
    }

    int out = 0;
    const char *p = fmt;

    while (*p)
    {
        if (*p != '%')
        {
            sink(*p++, ctx);
            out++;
            continue;
        }

        p++; /* skip '%' */

        /* ---- parse flags ---- */
        int left = 0;
        int pad0 = 0;
        int alternate = 0;

        while (*p == '-' || *p == '0' || *p == '#')
        {
            if (*p == '-') { left = 1; }
            else if (*p == '0') { pad0 = 1; }
            else { alternate = 1; }
            p++;
        }
        if (left) { pad0 = 0; } /* '-' disables '0' */

        /* ---- parse width ---- */
        int width = 0;
        while (*p >= '0' && *p <= '9')
        {
            width = width * 10 + (*p++ - '0');
        }

        /* ---- length (only 'l' for 32-bit) ---- */
        int is_long = 0;
        if (*p == 'l')
        {
            is_long = 1;
            p++;
        }

        if (!*p)
        {
            break;
        }

        /* ---- specifier ---- */
        char spec = *p++;
        switch (spec)
        {
            case '%':
            {
                sink('%', ctx);
                out++;

                break;
            }

            case 'c':
            {
                int c = va_arg(ap, int);
                sink(c, ctx);
                out++;

                break;
            }

            case 's':
            {
                const char *s = va_arg(ap, const char*);
                s = safe_str(s);

                int slen = 0;
                const char *q = s;
                while (*q++) { slen++; }

                int pad = (width > slen) ? (width - slen) : 0;

                if (!left)
                {
                    while (pad--) { sink(' ', ctx); out++; }
                    while (*s) { sink(*s++, ctx); out++; }
                }
                else
                {
                    while (*s) { sink(*s++, ctx); out++; }
                    while (pad--) { sink(' ', ctx); out++; }
                }

                break;
            }

            case 'd':
            case 'i':
            {
                int32_t val = is_long ? va_arg(ap, int32_t) : va_arg(ap, int);
                char buf[12];
                int neg = (val < 0);
                uint32_t u = neg ? (uint32_t)(-val) : (uint32_t)val;

                int i = 0;
                do
                {
                    buf[i++] = (char)('0' + (u % 10));
                    u /= 10;
                }
                while (u);

                int need = i + (neg ? 1 : 0);
                int pad = (width > need) ? (width - need) : 0;

                if (!left)
                {
                    if (!pad0) { while (pad--) { sink(' ', ctx); out++; } }
                    if (neg) { sink('-', ctx); out++; }
                    if (pad0) { while (pad--) { sink('0', ctx); out++; } }
                    while (--i >= 0) { sink(buf[i], ctx); out++; }
                }
                else
                {
                    if (neg) { sink('-', ctx); out++; }
                    while (--i >= 0) { sink(buf[i], ctx); out++; }
                    while (pad--) { sink(' ', ctx); out++; }
                }

                break;
            }

            case 'u':
            case 'x':
            case 'X':
            case 'o':
            {
                uint32_t val = is_long ? va_arg(ap, uint32_t) : va_arg(ap, unsigned int);
                unsigned base = (spec == 'o') ? 8 : (spec == 'u') ? 10 : 16;
                const char *digits = (spec == 'X') ? "0123456789ABCDEF" : "0123456789abcdef";

                char buf[12];
                int i = 0;

                do
                {
                    buf[i++] = digits[val % base];
                    val /= base;
                }
                while (val);

                int prefix_len = (alternate && base == 16) ? 2 : 0; /* "0x" / "0X" */
                int need = i + prefix_len;
                int pad = (width > need) ? (width - need) : 0;

                if (!left)
                {
                    if (!pad0) { while (pad--) { sink(' ', ctx); out++; } }
                    if (prefix_len)
                    {
                        sink('0', ctx);
                        sink(spec, ctx); /* 'x' or 'X' */
                        out += 2;
                    }
                    if (pad0) { while (pad--) { sink('0', ctx); out++; } }
                    while (--i >= 0) { sink(buf[i], ctx); out++; }
                }
                else
                {
                    if (prefix_len)
                    {
                        sink('0', ctx);
                        sink(spec, ctx);
                        out += 2;
                    }
                    while (--i >= 0) { sink(buf[i], ctx); out++; }
                    while (pad--) { sink(' ', ctx); out++; }
                }

                break;
            }

            case 'p':
            {
                /* print as 0x + lowercase hex, width pads the hex digits (not the 0x) with zeros */
                uint32_t v = (uint32_t)va_arg(ap, void*);
                char buf[8];
                int i = 0;

                do
                {
                    buf[i++] = "0123456789abcdef"[v & 0xF];
                    v >>= 4;
                }
                while (v);

                /* minimum 1 nibble, pad with zeros to requested width (width counts digits only) */
                int pad = (width > i) ? (width - i) : 0;

                sink('0', ctx);
                sink('x', ctx);
                out += 2;

                while (pad--) { sink('0', ctx); out++; }
                while (--i >= 0) { sink(buf[i], ctx); out++; }

                break;
            }

            default:
            {
                /* unknown specifier: print it verbatim */
                sink('%', ctx);
                sink(spec, ctx);
                out += 2;

                break;
            }
        }
    }

    return out;
}


int printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vprintf(fmt, ap);
    va_end(ap);
    return ret;
}

int vprintf(const char *fmt, va_list ap)
{
    if (!is_valid_userspace_ptr(fmt, 1)) return -1;
    return vcbprintf(putch_sink, NULL, fmt, ap);
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
    if (!buf || !size || !is_valid_userspace_ptr(fmt, 1)) return -1;
    
    struct bufctx b = {buf, size, 0};
    int ret = vcbprintf(buf_sink, &b, fmt, ap);
    
    if (b.len < size) buf[b.len] = '\0';
    else if (size > 0) buf[size-1] = '\0';
    
    return ret;
}

int snprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return ret;
}

int puts(const char *s)
{
    s = safe_str(s);
    int len = 0;
    
    while (*s) {
        system_putchar(*s++);
        len++;
    }
    system_putchar('\n');
    return len + 1;
}

int putchar(int c)
{
    system_putchar((char)c);
    return (unsigned char)c;
}

/* ====== Additional FILE operations ====== */
int fseek(FILE *file, long offset, int whence)
{
    if (!file) return -1;
    
    int ret = system_lseek(file->file_descriptor, offset, whence);
    if (ret < 0) {
        file->error = 1;
        return -1;
    }
    
    file->eof = 0;
    file->ungot = -1;
    return 0;
}

long ftell(FILE *file)
{
    if (!file) return -1;
    return system_lseek(file->file_descriptor, 0, SEEK_CUR);
}

void rewind(FILE *file)
{
    if (file) {
        fseek(file, 0, SEEK_SET);
        file->error = 0;
        file->eof = 0;
    }
}

int fgetc(FILE *file)
{
    if (!file) return -1;
    
    if (file->ungot >= 0) {
        int c = file->ungot;
        file->ungot = -1;
        return c;
    }
    
    unsigned char c;
    return (fread(&c, 1, 1, file) == 1) ? c : -1;
}

int ungetc(int c, FILE *file)
{
    if (!file || c == EOF || file->ungot != -1) return EOF;
    
    file->ungot = (unsigned char)c;
    file->eof = 0;
    return c;
}

int fputc(int c, FILE *file)
{
    FILE tmp;
    file = coerce_stream(file, &tmp, /*want_write=*/1);

    unsigned char ch = (unsigned char)c;

    return (fwrite(&ch, 1, 1, file) == 1) ? c : EOF;
}

char *fgets(char *s, int size, FILE *file)
{
    if (!s || size <= 1 || !file) return NULL;
    
    int i = 0;
    while (i < size - 1) {
        int c = fgetc(file);
        if (c == EOF) break;
        
        s[i++] = (char)c;
        if (c == '\n') break;
    }
    
    if (i == 0) return NULL;
    
    s[i] = '\0';
    return s;
}

int fputs(const char *s, FILE *file)
{
    if (!s) return EOF;

    FILE tmp;
    file = coerce_stream(file, &tmp, /*want_write=*/1);

    size_t len = strlen(s);
    return (fwrite(s, 1, len, file) == len) ? 0 : EOF;
}

int feof(FILE *file)
{
    return file ? file->eof : 0;
}

int ferror(FILE *file)
{
    return file ? file->error : 0;
}

void clearerr(FILE *file)
{
    if (file) {
        file->error = 0;
        file->eof = 0;
    }
}

int fflush(FILE *file)
{
    (void)file;
    return 0; // No buffering in this implementation
}

int remove(const char *path)
{
    // TODO: Implement
    (void)path;

    return 0;
}

int rename(const char *oldpath, const char *newpath)
{
    // TODO: Implement
    (void)oldpath;
    (void)newpath;

    return 0;
}


int sscanf(const char *str, const char *fmt, ...)
{
    const char *p = str;
    const char *f = fmt;
    int asgn = 0;
    int nread = 0;

    va_list ap;
    va_start(ap, fmt);

    while (*f)
    {
        if (isspace((unsigned char)*f))
        {
            while (isspace((unsigned char)*f))
            {
                f++;
            }

            while (isspace((unsigned char)*p))
            {
                p++;
                nread++;
            }

            continue;
        }

        if (*f != '%')
        {
            if (*p != *f)
            {
                break;
            }

            p++;
            f++;
            nread++;

            continue;
        }

        f++;

        int suppress = 0;
        int width = 0;
        int lflag = 0;

        if (*f == '*')
        {
            suppress = 1;
            f++;
        }

        while (*f >= '0' && *f <= '9')
        {
            width = width * 10 + (*f - '0');
            f++;
        }

        if (*f == 'h')
        {
            lflag = -1;
            f++;

            if (*f == 'h')
            {
                f++;
            }
        }
        else if (*f == 'l')
        {
            lflag = 1;
            f++;

            if (*f == 'l')
            {
                lflag = 2;
                f++;
            }
        }

        int c = *f++;

        if (c == 0)
        {
            break;
        }

        if (c != 'c' && c != '[' && c != 'n' && c != '%')
        {
            while (isspace((unsigned char)*p))
            {
                p++;
                nread++;
            }
        }

        if (c == '%')
        {
            if (*p != '%')
            {
                break;
            }

            p++;
            nread++;

            continue;
        }

        if (c == 'n')
        {
            if (!suppress)
            {
                int *outn = va_arg(ap, int *);
                *outn = nread;
            }

            continue;
        }

        if (c == 'c')
        {
            int cnt = width ? width : 1;

            if (!suppress)
            {
                char *outc = va_arg(ap, char *);

                for (int i = 0; i < cnt; i++)
                {
                    if (*p == 0)
                    {
                        va_end(ap);

                        return asgn ? asgn : -1;
                    }

                    outc[i] = *p++;
                    nread++;
                }
            }
            else
            {
                for (int i = 0; i < cnt; i++)
                {
                    if (*p == 0)
                    {
                        va_end(ap);

                        return asgn ? asgn : -1;
                    }

                    p++;
                    nread++;
                }
            }

            asgn++;

            continue;
        }

        if (c == 's')
        {
            int cnt = 0;

            if (!width)
            {
                width = 0x7fffffff;
            }

            const char *start = p;

            while (*p && !isspace((unsigned char)*p) && cnt < width)
            {
                p++;
                cnt++;
            }

            if (cnt == 0)
            {
                va_end(ap);

                return asgn ? asgn : -1;
            }

            if (!suppress)
            {
                char *outs = va_arg(ap, char *);

                for (int i = 0; i < cnt; i++)
                {
                    outs[i] = start[i];
                }

                outs[cnt] = '\0';
                asgn++;
            }

            nread += cnt;

            continue;
        }

        if (c == 'd' || c == 'u' || c == 'x' || c == 'X' || c == 'o' || c == 'i' || c == 'p')
        {
            int base = 10;

            if (c == 'u')
            {
                base = 10;
            }
            else if (c == 'x' || c == 'X' || c == 'p')
            {
                base = 16;
            }
            else if (c == 'o')
            {
                base = 8;
            }
            else if (c == 'i')
            {
                base = 0;
            }

            char tmp[128];
            const char *start = p;
            const char *src = p;
            char *endp = (char *)p;

            if (width)
            {
                int k = 0;

                while (src[k] && k < width && k < (int)sizeof(tmp) - 1)
                {
                    tmp[k] = src[k];
                    k++;
                }

                tmp[k] = '\0';
                src = tmp;
            }

            if (c == 'u' || c == 'x' || c == 'X' || c == 'o' || c == 'p')
            {
                unsigned long long v = strtoull(src, &endp, base);

                if (endp == src)
                {
                    va_end(ap);

                    return asgn ? asgn : -1;
                }

                if (!suppress)
                {
                    if (c == 'p')
                    {
                        void **outp = va_arg(ap, void **);
                        *outp = (void *)(uintptr_t)v;
                    }
                    else if (lflag == 2)
                    {
                        unsigned long long *ou = va_arg(ap, unsigned long long *);
                        *ou = v;
                    }
                    else if (lflag == 1)
                    {
                        unsigned long *ou = va_arg(ap, unsigned long *);
                        *ou = (unsigned long)v;
                    }
                    else if (lflag == -1)
                    {
                        unsigned short *ou = va_arg(ap, unsigned short *);
                        *ou = (unsigned short)v;
                    }
                    else
                    {
                        unsigned int *ou = va_arg(ap, unsigned int *);
                        *ou = (unsigned int)v;
                    }

                    asgn++;
                }
            }
            else
            {
                long long v = strtoll(src, &endp, base);

                if (endp == src)
                {
                    va_end(ap);

                    return asgn ? asgn : -1;
                }

                if (!suppress)
                {
                    if (lflag == 2)
                    {
                        long long *oi = va_arg(ap, long long *);
                        *oi = v;
                    }
                    else if (lflag == 1)
                    {
                        long *oi = va_arg(ap, long *);
                        *oi = (long)v;
                    }
                    else if (lflag == -1)
                    {
                        short *oi = va_arg(ap, short *);
                        *oi = (short)v;
                    }
                    else
                    {
                        int *oi = va_arg(ap, int *);
                        *oi = (int)v;
                    }

                    asgn++;
                }
            }

            if (width)
            {
                p = start + (endp - (char *)src);
            }
            else
            {
                p = endp;
            }

            nread = (int)(p - str);

            continue;
        }

        if (c == 'f')
        {
            char tmp[128];
            const char *start = p;
            const char *src = p;
            char *endp = (char *)p;

            if (width)
            {
                int k = 0;

                while (src[k] && k < width && k < (int)sizeof(tmp) - 1)
                {
                    tmp[k] = src[k];
                    k++;
                }

                tmp[k] = '\0';
                src = tmp;
            }

            double dv = strtod(src, &endp);

            if (endp == src)
            {
                va_end(ap);

                return asgn ? asgn : -1;
            }

            if (!suppress)
            {
                if (lflag == 1)
                {
                    double *od = va_arg(ap, double *);
                    *od = dv;
                }
                else
                {
                    float *of = va_arg(ap, float *);
                    *of = (float)dv;
                }

                asgn++;
            }

            if (width)
            {
                p = start + (endp - (char *)src);
            }
            else
            {
                p = endp;
            }

            nread = (int)(p - str);

            continue;
        }

        break;
    }

    va_end(ap);

    return asgn;
}

int fprintf(FILE *stream, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vfprintf(stream, fmt, ap);
    va_end(ap);
    return r;
}

int vfprintf(FILE *stream, const char *fmt, va_list ap)
{
    if (!is_valid_userspace_ptr(fmt, 1)) {
        return -1;
    }

    FILE tmp;
    struct filesink sink;
    sink.f = coerce_stream(stream, &tmp, /*want_write=*/1);
    sink.len = 0;

    int out = vcbprintf(file_putch, &sink, fmt, ap);

    if (sink.len) {
        (void)fwrite(sink.buf, 1, sink.len, sink.f);
        sink.len = 0;
    }

    return out;
}
