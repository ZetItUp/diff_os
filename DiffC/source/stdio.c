#include <diffc_internal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <syscall.h>

#ifndef va_copy
#  ifdef __va_copy
#    define va_copy(dest, src) __va_copy(dest, src)
#  else
#    define va_copy(dest, src) ((dest) = (src))   /* sista utvägen */
#  endif
#endif

// File Handling
static FILE _stdin =
{
    .file_descriptor = 0,
    .flags = FILE_CAN_READ,
    .error = 0,
    .eof = 0,
    .ungot = -1
};

static FILE _stdout = 
{ 
    .file_descriptor = 1, 
    .flags = FILE_CAN_WRITE,
    .error=0,
    .eof=0,
    .ungot=-1 
};

static FILE _stderr = 
{ 
    .file_descriptor = 2, 
    .flags = FILE_CAN_WRITE,
    .error=0,
    .eof=0,
    .ungot=-1 
};

FILE *stdin = &_stdin;
FILE *stdout = &_stdout;
FILE *stderr = &_stderr;

// Parse mode
static int mode_to_oflags(const char *mode, int *f_flags_out)
{
    // "r", "w", "a", "r+", "w+", "a+"
    int of = 0;
    int f  = 0;

    if (!mode || !mode[0])
    {
        return -1;
    }

    char m0 = mode[0];
    int plus = (strchr(mode, '+') != NULL);

    switch (m0) 
    {
        case 'r':
            of = plus ? O_RDWR : O_RDONLY;
            f  = plus ? (FILE_CAN_READ | FILE_CAN_WRITE) : FILE_CAN_READ;
            break;
        case 'w':
            of = plus ? (O_RDWR | O_CREAT | O_TRUNC) : (O_WRONLY | O_CREAT | O_TRUNC);
            f  = plus ? (FILE_CAN_READ | FILE_CAN_WRITE) : FILE_CAN_WRITE;
            break;
        case 'a':
            of = plus ? (O_RDWR | O_CREAT | O_APPEND) : (O_WRONLY | O_CREAT | O_APPEND);
            f  = plus ? (FILE_CAN_READ | FILE_CAN_WRITE) : FILE_CAN_WRITE;
            break;
        default:
            return -1;
    }
    
    if (f_flags_out)
    {
        *f_flags_out = f;
    }
    
    return of;
}

FILE *fopen(const char *path, const char *mode)
{
    int f_flags = 0;
    int o_flags = mode_to_oflags(mode, &f_flags);

    if(o_flags < 0)
    {
        return NULL;
    }

    int file_desc = system_open(path, o_flags, 0644);
    if(file_desc < 0)
    {
        return NULL;
    }

    FILE *file = (FILE*)malloc(sizeof(FILE));

    if(!file)
    {
        system_close(file_desc);

        return NULL;
    }

    file->file_descriptor = file_desc;
    file->flags = f_flags;
    file->error = 0;
    file->eof = 0;
    file->ungot = -1;

    return file;
}

int fclose(FILE *file)
{
    if(!file)
    {
        return -1;
    }

    int rc = 0;

    if(system_close(file->file_descriptor) < 0)
    {
        rc = -1;
    }

    return rc;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *file)
{
    if(!file || !ptr || size == 0 || nmemb == 0)
    {
        return 0;
    }

    if(!(file->flags & FILE_CAN_READ))
    {
        file->error = 1;
        
        return 0;
    }

    unsigned char *dst = (unsigned char*)ptr;
    size_t total = size * nmemb;
    size_t done = 0;

    if(file->ungot >= 0 && total > 0)
    {
        *dst++ = (unsigned char)file->ungot;
        file->ungot = -1;
        done = 1;
    }

    while(done < total)
    {
        long read = system_read(file->file_descriptor, dst + done, (unsigned long)(total - done));

        if(read == 0)
        {
            file->eof = 1;
            break;
        }

        if(read < 0)
        {
            file->error = 1;
            break;
        }

        done += (size_t)read;
    }

    return size ? (done / size) : 0;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *file)
{
    if(!file || !ptr || size == 0 || nmemb == 0)
    {
        return 0;
    }

    if(!(file->flags & FILE_CAN_WRITE))
    {
        file->error = 1;

        return 0;
    }

    const unsigned char *src = (const unsigned char*)ptr;
    size_t total = size * nmemb;
    size_t done = 0;

    while(done < total)
    {
        long write = system_write(file->file_descriptor, src + done, (unsigned long)(total - done));

        if(write <= 0)
        {
            file->error = 1;
            break;
        }

        done += (size_t)write;
    }

    return size ? (done / size) : 0;
}

int fseek(FILE *file, long offset, int whence)
{
    if(!file)
    {
        return -1;
    }

    long read = system_lseek(file->file_descriptor, offset, whence);

    if(read < 0)
    {
        file->error = 1;
        
        return -1;
    }

    file->eof = 0;
    file->ungot = -1;

    return 0;
} 

long ftell(FILE *file)
{
    if(!file)
    {
        return -1;
    }

    long read = system_lseek(file->file_descriptor, 0, SEEK_CUR);

    if(read < 0)
    {
        file->error = 1;

        return -1;
    }

    return read;
}

void rewind(FILE *file)
{
    if(!file)
    {
        return;
    }

    (void)fseek(file, 0, SEEK_SET);
    file->error = 0;
    file->eof = 0;
}   

int fflush(FILE *file)
{
    // TODO: Handle buffers
    (void)file;

    return 0;
}

int feof(FILE *file)
{
    return file ? file->eof : 0;
}

int ferror(FILE *file)
{
    return file ? file->error : 1;
}

void clearerr(FILE *file)
{
    if(file)
    {
        file->error = 0;
        file->eof = 0;
    }
}

int fgetc(FILE *file)
{
    if(!file)
    {
        return -1;
    }

    if(file->ungot >= 0)
    {
        int c = file->ungot;
        file->ungot = -1;

        return c;
    }

    unsigned char ch;
    size_t read = fread(&ch, 1, 1, file);

    return (read == 1) ? (int)ch : -1;
}

int ungetc(int ch, FILE *file)
{
    if(!file || ch < 0 || file->ungot >= 0)
    {
        return -1;
    }

    file->ungot = (unsigned char)ch;
    file->eof = 0;

    return ch;
}

int fputc(int ch, FILE *file)
{
    unsigned char c = (unsigned char)ch;

    return (fwrite(&c, 1, 1, file) == 1) ? ch : -1;
}

char *fgets(char *str, int size, FILE *file)
{
    if(!str || size <= 0 || !file)
    {
        return NULL;
    }

    int i = 0;

    for(;i < size - 1; ++i)
    {
        int c = fgetc(file);

        if(c < 0)
        {
            break;
        }

        str[i] = (char)c;

        if(c == '\n')
        {
            i++;
            break;
        }
    }

    if(i == 0)
    {
        return NULL;
    }

    str[i] = '\0';

    return str;
}

int fputs(const char *str, FILE *file)
{
    size_t len = str ? strlen(str) : 0;

    return (fwrite(str, 1, len, file) == len) ? (int)len : -1;
}

// Printing
static void putch_sink(int ch, void *ctx) 
{
    (void)ctx;
    system_putchar((char)ch);
}

struct bufctx 
{ 
    char *buf; 
    size_t cap; 
    size_t len; 
};

static void buf_sink(int ch, void *ctx) 
{
    struct bufctx *b = (struct bufctx*)ctx;

    if (b->len + 1 < b->cap) 
    {
        b->buf[b->len] = (char)ch;
    }
    
    b->len++;
}

static void out_repeat(void (*sink)(int,void*), void *ctx, char c, int n) 
{
    for (int i=0;i<n;i++)
    {
        sink(c, ctx);
    }
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

