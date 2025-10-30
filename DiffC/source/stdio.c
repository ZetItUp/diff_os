// stdio.c – libc-liknande implementation för DiffC
// Fokus: robust init av stdin/stdout/stderr, säkra guards för FILE*,
// line/full buffering, setvbuf, fflush, fread/fwrite, fseek/ftell, ungetc,
// samt printf-familjen ovanpå vfprintf.
//
// Bygger enbart på headers du gett: stdio.h, stdlib.h, string.h,
// syscall.h, ctype.h, diffc_internal.h, stddef.h.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <ctype.h>
#include <diffc_internal.h>
#include <stddef.h>
#include <limits.h>
#include <stdint.h>

// ==== Interna flaggor (bitmask i FILE->flags) ====
#ifndef FILE_CAN_READ
#define FILE_CAN_READ   0x01
#endif
#ifndef FILE_CAN_WRITE
#define FILE_CAN_WRITE  0x02
#endif
#ifndef FILE_APPEND
#define FILE_APPEND     0x04
#endif
#ifndef FILE_EOF
#define FILE_EOF        0x08
#endif
#ifndef FILE_ERR
#define FILE_ERR        0x10
#endif

// Buffering mode
#ifndef _IOFBF
#define _IOFBF  0  // full
#endif
#ifndef _IOLBF
#define _IOLBF  1  // line
#endif
#ifndef _IONBF
#define _IONBF  2  // none
#endif

// ====== Intern representation ======
// Din stdio.h definierar redan struct FILE med minst:
// int file_descriptor; int flags; int error; int eof; int ungot;
// Vi lägger till ett litet “privat” fältpaket i slutet om stdio.h tillåter.
// Om inte – behåll samma layout som din tidigare och nyttja ett “extra” fält.

typedef struct _buf {
    unsigned char *base;   // buffer start
    size_t         size;   // buffertstorlek
    size_t         pos;    // skriv/läsläge i buffert
    size_t         len;    // giltiga läsbara byte (för input)
    int            mode;   // _IOFBF/_IOLBF/_IONBF
    int            owned;  // äger vi bufferten (malloc) eller användarens?
} _buf;

// För att inte förstöra layouten – vi kapslar in buffert i FILE via ett
// “privat” fält som stdio.h inte använder. Om stdio.h har eget buffertfält,
// ta bort detta och koppla mot dem istället.

typedef struct _FileImpl {
    int  fd;
    int  can_read;
    int  can_write;
    int  append;
    int  err;
    int  eof;
    int  ungot;       // -1 om tom
    _buf inb;         // in-buffert (för fread/fgetc)
    _buf outb;        // ut-buffert (för fwrite/fputc)
} _FileImpl;

// Bridge mot existerande FILE (vi antar att FILE är opaque nog).
// Vi allokerar en _FileImpl och placerar pekaren i FILE* (om FILE redan är
// konkret – ersätt med en mappning).

// ====== Framåtdeklarationer ======
static int  _flush_out(FILE *f);
static int  _fill_in(FILE *f);
static void _set_err(FILE *f) { if (f) f->impl->err = 1; }
static void _set_eof(FILE *f) { if (f) f->impl->eof = 1; }
static int  _valid_ptr(const void *p) {
    uintptr_t v = (uintptr_t)p;
    return (v >= 0x1000 && (v & 0x3) == 0);
}
static FILE *_coerce(FILE *f, int want_write);

// ====== Globala standardströmmar ======
static _FileImpl __stdin_impl  = { 0,1,0,0,0,0,-1,{0,0,0,0,_IOFBF,0},{0,0,0,0,_IOFBF,0} };
static _FileImpl __stdout_impl = { 1,0,1,0,0,0,-1,{0,0,0,0,_IOFBF,0},{0,0,0,0,_IOLBF,0} };
static _FileImpl __stderr_impl = { 2,0,1,0,0,0,-1,{0,0,0,0,_IOFBF,0},{0,0,0,0,_IONBF,0} };

static FILE __stdin  = { &__stdin_impl  };
static FILE __stdout = { &__stdout_impl };
static FILE __stderr = { &__stderr_impl };

// Exporterade pekarvariabler – detta matchar “libc”-mönster och dina importer
FILE *stdin  = &__stdin;
FILE *stdout = &__stdout;
FILE *stderr = &__stderr;

// ====== Hjälp ======
static void _buf_reset(_buf *b) { b->pos = 0; b->len = 0; }
static void _free_buf(_buf *b) { if (b->owned && b->base) { free(b->base); } b->base = NULL; b->size = b->pos = b->len = 0; b->owned = 0; }

static void _ensure_default_buffers(void) {
    // Sätt små standardbuffertar om inga finns.
    // stdin fullbuffras, stdout line, stderr none.
    static unsigned char inbuf[256];
    static unsigned char outbuf[256];

    if (stdin && stdin->impl->inb.base == NULL && stdin->impl->inb.mode != _IONBF) {
        stdin->impl->inb.base = inbuf;
        stdin->impl->inb.size = sizeof(inbuf);
        stdin->impl->inb.owned = 0;
        _buf_reset(&stdin->impl->inb);
    }
    if (stdout && stdout->impl->outb.base == NULL && stdout->impl->outb.mode != _IONBF) {
        stdout->impl->outb.base = outbuf;
        stdout->impl->outb.size = sizeof(outbuf);
        stdout->impl->outb.owned = 0;
        _buf_reset(&stdout->impl->outb);
    }
    // stderr obuffrad – ingen buffert behövs
}

static FILE *_alloc_stream(void) {
    FILE *f = (FILE*)malloc(sizeof(FILE));
    if (!f) return NULL;
    _FileImpl *impl = (_FileImpl*)calloc(1, sizeof(_FileImpl));
    if (!impl) { free(f); return NULL; }
    impl->fd = -1;
    impl->ungot = -1;
    impl->inb.mode  = _IOFBF;
    impl->outb.mode = _IOFBF;
    f->impl = impl;
    return f;
}

static void _free_stream(FILE *f) {
    if (!f || !f->impl) return;
    _free_buf(&f->impl->inb);
    _free_buf(&f->impl->outb);
    free(f->impl);
    f->impl = NULL;
    free(f);
}

static FILE *_coerce(FILE *f, int want_write) {
    if (!f) f = want_write ? stdout : stdin;        // libc: printf -> stdout, getc -> stdin
    if (!_valid_ptr(f) || !_valid_ptr(f->impl)) return NULL;
    return f;
}

static int _flush_out(FILE *f) {
    if (!f || !f->impl) return EOF;
    _FileImpl *I = f->impl;
    if (!I->can_write) { _set_err(f); return EOF; }
    if (I->outb.mode == _IONBF) return 0; // obuffrat – inget att tömma

    size_t n = I->outb.pos;
    size_t done = 0;
    while (done < n) {
        int32_t w = system_write(I->fd, I->outb.base + done, (int32_t)(n - done));
        if (w < 0) { _set_err(f); I->outb.pos = 0; return EOF; }
        if (w == 0) break;
        done += (size_t)w;
    }
    I->outb.pos = 0;
    return 0;
}

// Fyll läsbuffert från kernel
static int _fill_in(FILE *f) {
    if (!f || !f->impl) return EOF;
    _FileImpl *I = f->impl;
    if (!I->can_read) { _set_err(f); return EOF; }

    if (I->ungot >= 0) {
        // Om vi har en “ungetc” – leverera den via bufferten
        if (I->inb.mode == _IONBF) {
            // obuffrat: returnera direkt via “lat” väg (hanteras av fgetc)
            return 0;
        }
        I->inb.base[0] = (unsigned char)I->ungot;
        I->inb.len = 1; I->inb.pos = 0;
        I->ungot = -1;
        return 1;
    }

    if (I->inb.mode == _IONBF) {
        // obuffrad läsning får skötas i fgetc/fread direkt
        return 0;
    }

    int32_t r = system_read(I->fd, I->inb.base, (int32_t)I->inb.size);
    if (r < 0) { _set_err(f); return EOF; }
    if (r == 0) { _set_eof(f); I->inb.len = 0; I->inb.pos = 0; return 0; }
    I->inb.len = (size_t)r;
    I->inb.pos = 0;
    return (int)r;
}

// ====== Öppna/stäng ======

static int _mode_parse(const char *mode, int *out_r, int *out_w, int *out_app, int *out_trunc, int *out_creat) {
    int r=0,w=0,a=0,t=0,c=0;
    if (!mode || !*mode) return -1;
    // libc: “r”, “w”, “a”, ev. “+”, ev. “b” ignoreras
    char m0 = mode[0];
    int plus = (strchr(mode, '+') != NULL);
    switch (m0) {
        case 'r': r = 1; c = 0; t = 0; a = 0; w = plus; break;
        case 'w': w = 1; c = 1; t = 1; a = 0; r = plus; break;
        case 'a': w = 1; c = 1; t = 0; a = 1; r = plus; break;
        default: return -1;
    }
    *out_r = r; *out_w = w; *out_app = a; *out_trunc = t; *out_creat = c;
    return 0;
}

FILE *fopen(const char *path, const char *mode) {
    _ensure_default_buffers();

    int R=0,W=0,A=0,T=0,C=0;
    if (_mode_parse(mode, &R,&W,&A,&T,&C) < 0) return NULL;

    int oflags = 0;
    if (R && !W) oflags |= O_RDONLY;
    if (W && !R) oflags |= O_WRONLY;
    if (W && R)  oflags |= O_RDWR;
    if (C) oflags |= O_CREAT;
    if (T) oflags |= O_TRUNC;
    if (A) oflags |= O_APPEND;

    int fd = system_open(path, oflags, 0644);
    if (fd < 0) return NULL;

    FILE *f = _alloc_stream();
    if (!f) { system_close(fd); return NULL; }

    f->impl->fd = fd;
    f->impl->can_read  = R;
    f->impl->can_write = W;
    f->impl->append    = A;
    f->impl->err = f->impl->eof = 0;
    f->impl->ungot = -1;

    // Standard: fullbuffer by default
    setvbuf(f, NULL, _IOFBF, 0);
    return f;
}

FILE *fdopen(int fd, const char *mode) {
    _ensure_default_buffers();

    if (fd < 0) return NULL;
    int R=0,W=0,A=0,T=0,C=0;
    if (_mode_parse(mode, &R,&W,&A,&T,&C) < 0) return NULL;

    FILE *f = _alloc_stream();
    if (!f) return NULL;

    f->impl->fd = fd;
    f->impl->can_read  = R;
    f->impl->can_write = W;
    f->impl->append    = A;
    f->impl->err = f->impl->eof = 0;
    f->impl->ungot = -1;
    setvbuf(f, NULL, _IOFBF, 0);
    return f;
}

int fclose(FILE *stream) {
    stream = _coerce(stream, 0);
    if (!stream) return EOF;

    _flush_out(stream);
    int rc = 0;
    if (stream != stdin && stream != stdout && stream != stderr) {
        rc = system_close(stream->impl->fd);
        _free_stream(stream);
    } else {
        // standardströmmar stängs inte, men flushas
        rc = 0;
    }
    return rc;
}

// ====== Buffering ======

int setvbuf(FILE *stream, char *buf, int mode, size_t size) {
    stream = _coerce(stream, 0);
    if (!stream) return EOF;
    if (mode != _IOFBF && mode != _IOLBF && mode != _IONBF) return EOF;

    _FileImpl *I = stream->impl;

    // Flush innan byte av output-buffert
    _flush_out(stream);

    // Free gamla buffertar om vi ägde dem
    _free_buf(&I->inb);
    _free_buf(&I->outb);

    if (mode == _IONBF) {
        I->inb.base = NULL; I->inb.size = 0; I->inb.mode = _IONBF; I->inb.owned = 0; _buf_reset(&I->inb);
        I->outb.base= NULL; I->outb.size= 0; I->outb.mode= _IONBF; I->outb.owned= 0; _buf_reset(&I->outb);
        return 0;
    }

    size_t want = size ? size : 256;

    if (buf) {
        // Användarbuffer – dela samma buffert för in/ut om bara en gavs
        I->inb.base = (unsigned char*)buf;
        I->inb.size = want;
        I->inb.mode = mode;
        I->inb.owned= 0; _buf_reset(&I->inb);

        // Ut-buffert – om samma buf används: låt utb använda också
        I->outb.base = (unsigned char*)buf;
        I->outb.size = want;
        I->outb.mode = mode;
        I->outb.owned= 0; _buf_reset(&I->outb);
    } else {
        // Allokera separata buffertar
        I->inb.base  = (unsigned char*)malloc(want);
        I->outb.base = (unsigned char*)malloc(want);
        if (!I->inb.base || !I->outb.base) {
            if (I->inb.base) free(I->inb.base);
            if (I->outb.base) free(I->outb.base);
            I->inb.base = I->outb.base = NULL;
            I->inb.size = I->outb.size = 0;
            I->inb.mode = I->outb.mode = _IONBF;
            return EOF;
        }
        I->inb.size = I->outb.size = want;
        I->inb.mode = I->outb.mode = mode;
        I->inb.owned= I->outb.owned= 1;
        _buf_reset(&I->inb);
        _buf_reset(&I->outb);
    }
    return 0;
}

void setbuf(FILE *stream, char *buf) {
    if (!stream) return;
    (void)setvbuf(stream, buf, buf ? _IOFBF : _IONBF, buf ? 256 : 0);
}

// ====== Status ======
int feof(FILE *stream)    { stream = _coerce(stream, 0); return stream ? stream->impl->eof : 1; }
int ferror(FILE *stream)  { stream = _coerce(stream, 0); return stream ? stream->impl->err : 1; }
void clearerr(FILE *s)    { s = _coerce(s, 0); if (s) { s->impl->err = 0; s->impl->eof = 0; } }

// ====== Seeking ======
int fseek(FILE *stream, long offset, int whence) {
    stream = _coerce(stream, 0);
    if (!stream) return -1;
    // Flush ut-buffert innan seek
    if (_flush_out(stream) < 0) return -1;

    int ret = system_lseek(stream->impl->fd, (int)offset, whence);
    if (ret < 0) { _set_err(stream); return -1; }

    // Invalidate in-buffert; ungetc tas bort
    _buf_reset(&stream->impl->inb);
    stream->impl->eof = 0;
    stream->impl->ungot = -1;
    return 0;
}

long ftell(FILE *stream) {
    stream = _coerce(stream, 0);
    if (!stream) return -1;
    // Flush ut innan position
    if (_flush_out(stream) < 0) return -1;
    return (long)system_lseek(stream->impl->fd, 0, SEEK_CUR);
}

// ====== Input ======

int fgetc(FILE *stream) {
    stream = _coerce(stream, 0);
    if (!stream) return EOF;

    _FileImpl *I = stream->impl;

    if (I->ungot >= 0) {
        int c = I->ungot;
        I->ungot = -1;
        I->eof = 0;
        return c;
    }

    if (!I->can_read) { _set_err(stream); return EOF; }

    if (I->inb.mode == _IONBF) {
        unsigned char ch;
        int32_t r = system_read(I->fd, &ch, 1);
        if (r < 0) { _set_err(stream); return EOF; }
        if (r == 0) { _set_eof(stream); return EOF; }
        return (int)ch;
    }

    if (I->inb.pos >= I->inb.len) {
        if (_fill_in(stream) <= 0) return EOF;
    }
    return (int)I->inb.base[I->inb.pos++];
}

int ungetc(int c, FILE *stream) {
    stream = _coerce(stream, 0);
    if (!stream) return EOF;
    if (c == EOF) return EOF;
    if (stream->impl->ungot != -1) return EOF; // bara en nivå
    stream->impl->ungot = (unsigned char)c;
    stream->impl->eof = 0;
    return c;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    stream = _coerce(stream, 0);
    if (!stream || !ptr || size == 0 || nmemb == 0) return 0;

    _FileImpl *I = stream->impl;
    if (!I->can_read) { _set_err(stream); return 0; }

    size_t total = size * nmemb;
    size_t done = 0;
    unsigned char *dst = (unsigned char*)ptr;

    // konsumera ungot först
    if (I->ungot >= 0 && done < total) {
        dst[done++] = (unsigned char)I->ungot;
        I->ungot = -1;
    }

    if (I->inb.mode == _IONBF) {
        while (done < total) {
            int32_t r = system_read(I->fd, dst + done, (int32_t)(total - done));
            if (r < 0) { _set_err(stream); break; }
            if (r == 0) { _set_eof(stream); break; }
            done += (size_t)r;
        }
        return done / size;
    }

    // buffrad
    while (done < total) {
        if (I->inb.pos >= I->inb.len) {
            int r = _fill_in(stream);
            if (r <= 0) break;
        }
        size_t avail = I->inb.len - I->inb.pos;
        size_t want  = total - done;
        size_t take  = (avail < want) ? avail : want;
        memcpy(dst + done, I->inb.base + I->inb.pos, take);
        I->inb.pos += take;
        done += take;
    }
    return done / size;
}

// ====== Output ======

int fputc(int c, FILE *stream) {
    stream = _coerce(stream, 1);
    if (!stream) return EOF;

    _FileImpl *I = stream->impl;
    if (!I->can_write) { _set_err(stream); return EOF; }

    unsigned char ch = (unsigned char)c;

    if (I->outb.mode == _IONBF || I->outb.base == NULL || I->outb.size == 0) {
        // obuffrat: skriv direkt
        int32_t w = system_write(I->fd, &ch, 1);
        if (w != 1) { _set_err(stream); return EOF; }
        return (int)ch;
    }

    // buffrad
    I->outb.base[I->outb.pos++] = ch;

    int need_flush = 0;
    if (I->outb.pos >= I->outb.size) need_flush = 1;
    if (I->outb.mode == _IOLBF && ch == '\n') need_flush = 1;

    if (need_flush) {
        if (_flush_out(stream) < 0) return EOF;
    }
    return (int)ch;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    stream = _coerce(stream, 1);
    if (!stream || !ptr || size == 0 || nmemb == 0) return 0;
    _FileImpl *I = stream->impl;
    if (!I->can_write) { _set_err(stream); return 0; }

    const unsigned char *src = (const unsigned char*)ptr;
    size_t total = size * nmemb;
    size_t done = 0;

    if (I->outb.mode == _IONBF || I->outb.base == NULL || I->outb.size == 0) {
        while (done < total) {
            int32_t w = system_write(I->fd, src + done, (int32_t)(total - done));
            if (w <= 0) { _set_err(stream); break; }
            done += (size_t)w;
        }
        return done / size;
    }

    while (done < total) {
        size_t space = I->outb.size - I->outb.pos;
        if (space == 0) {
            if (_flush_out(stream) < 0) break;
            space = I->outb.size;
        }
        size_t chunk = total - done;
        if (chunk > space) chunk = space;
        memcpy(I->outb.base + I->outb.pos, src + done, chunk);
        I->outb.pos += chunk;
        done += chunk;

        if (I->outb.mode == _IOLBF) {
            // linjebuffrat – flush vid newline i chunk
            const void *p = memchr(src + done - chunk, '\n', chunk);
            if (p) {
                if (_flush_out(stream) < 0) break;
            }
        }
    }
    return done / size;
}

int fflush(FILE *stream) {
    _ensure_default_buffers();
    if (!stream) {
        // flush alla skrivbara (libc brukar flush:a alla när stream==NULL)
        int rc = 0;
        if (stdout) rc |= _flush_out(stdout);
        if (stderr) rc |= _flush_out(stderr);
        // stdin har inget att flush:a
        return rc ? EOF : 0;
    }
    stream = _coerce(stream, 1);
    if (!stream) return EOF;
    return _flush_out(stream);
}

// ====== Enkel stdio ovanpå ovan ======

int putchar(int c) { return fputc(c, stdout); }

int puts(const char *s) {
    if (!s) return EOF;
    size_t n = strlen(s);
    if (fwrite(s, 1, n, stdout) != n) return EOF;
    if (fputc('\n', stdout) == EOF) return EOF;
    return (int)(n + 1);
}

// ====== printf-familjen (compact) ======
//
// Vi implementerar en kompakt vfprintf som stödjer de specar som används
// i din kodbas ( %s %c %d %u %x %X %p %% och bredd/justering/0-padding).

typedef struct _sink {
    FILE *f;
    int   error;
    size_t count;
} _sink;

static void _sink_char(_sink *s, char ch) {
    if (s->error) return;
    if (fputc((unsigned char)ch, s->f) == EOF) s->error = 1;
    else s->count++;
}

static void _sink_mem(_sink *s, const char *p, size_t n) {
    if (s->error || n == 0) return;
    size_t w = fwrite(p, 1, n, s->f);
    if (w != n) s->error = 1;
    else s->count += n;
}

static void _pad(_sink *s, char ch, int n) {
    for (int i=0; i<n; i++) _sink_char(s, ch);
}

// itoa helpers
static char *_u64_to_str(uint64_t v, char *buf_end, int base, int upper) {
    static const char *digits_l = "0123456789abcdef";
    static const char *digits_u = "0123456789ABCDEF";
    const char *digits = upper ? digits_u : digits_l;
    *buf_end = '\0';
    char *p = buf_end;
    do {
        *--p = digits[v % (uint64_t)base];
        v /= (uint64_t)base;
    } while (v);
    return p;
}

int vfprintf(FILE *stream, const char *fmt, va_list ap) {
    stream = _coerce(stream, 1);
    if (!stream) return -1;

    _sink snk = { stream, 0, 0 };
    const char *p = fmt;

    while (*p && !snk.error) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            _sink_mem(&snk, p, (size_t)(q - p));
            p = q;
            continue;
        }
        p++; // skip '%'

        // Flags
        int left=0, alt=0, zero=0;
        while (*p=='-' || *p=='#' || *p=='0') {
            if (*p=='-') left=1;
            else if (*p=='#') alt=1;
            else if (*p=='0') zero=1;
            p++;
        }

        // Width
        int width = 0;
        while (*p>='0' && *p<='9') { width = width*10 + (*p-'0'); p++; }

        // Precision (ignoreras för enkelhet eller används för str)
        int prec = -1;
        if (*p=='.') {
            p++;
            prec = 0;
            while (*p>='0' && *p<='9') { prec = prec*10 + (*p-'0'); p++; }
        }

        // Length (stödjer 'l' och 'll' begränsat)
        int lcount = 0;
        while (*p=='l') { lcount++; p++; }

        // Spec
        char spec = *p ? *p++ : '\0';
        char numbuf[64]; // räcker för 64-bit dec/hex
        switch (spec) {
            case 's': {
                const char *s = va_arg(ap, const char*);
                if (!s) s = "(null)";
                size_t n = strlen(s);
                if (prec >= 0 && (size_t)prec < n) n = (size_t)prec;
                int pad = (width > (int)n) ? (width - (int)n) : 0;
                if (!left) _pad(&snk, ' ', pad);
                _sink_mem(&snk, s, n);
                if (left) _pad(&snk, ' ', pad);
            } break;

            case 'c': {
                char ch = (char)va_arg(ap, int);
                int pad = (width > 1) ? (width - 1) : 0;
                if (!left) _pad(&snk, ' ', pad);
                _sink_char(&snk, ch);
                if (left) _pad(&snk, ' ', pad);
            } break;

            case 'd':
            case 'i': {
                long long v = (lcount>=2) ? va_arg(ap, long long) :
                              (lcount==1) ? va_arg(ap, long) :
                                            va_arg(ap, int);
                unsigned long long uv;
                int neg = (v < 0);
                uv = neg ? (unsigned long long)(-(v+0ull)) : (unsigned long long)v;
                char *end = numbuf + sizeof(numbuf)-1;
                char *start = _u64_to_str(uv, end, 10, 0);
                int nlen = (int)(end - start);
                if (neg) { *--start = '-'; nlen++; }
                int pad = (width > nlen) ? (width - nlen) : 0;
                char padc = (zero && !left) ? '0' : ' ';
                if (!left) _pad(&snk, padc, pad);
                _sink_mem(&snk, start, (size_t)nlen);
                if (left) _pad(&snk, ' ', pad);
            } break;

            case 'u':
            case 'x':
            case 'X': {
                unsigned long long v = (lcount>=2) ? va_arg(ap, unsigned long long) :
                                       (lcount==1) ? va_arg(ap, unsigned long) :
                                                     va_arg(ap, unsigned int);
                int upper = (spec=='X');
                int base = (spec=='u') ? 10 : 16;
                char *end = numbuf + sizeof(numbuf)-1;
                char *start = _u64_to_str(v, end, base, upper);
                int nlen = (int)(end - start);
                int prefix = 0;
                char pf[2];
                if (alt && base==16 && v!=0) { pf[0]='0'; pf[1]=(upper?'X':'x'); prefix=2; }
                int pad = (width > (nlen+prefix)) ? (width - (nlen+prefix)) : 0;
                char padc = (zero && !left) ? '0' : ' ';
                if (!left) _pad(&snk, padc, pad);
                if (prefix) _sink_mem(&snk, pf, 2);
                _sink_mem(&snk, start, (size_t)nlen);
                if (left) _pad(&snk, ' ', pad);
            } break;

            case 'p': {
                uintptr_t v = (uintptr_t)va_arg(ap, void*);
                char *end = numbuf + sizeof(numbuf)-1;
                char *start = _u64_to_str((uint64_t)v, end, 16, 0);
                const char *pref = "0x";
                int nlen = (int)(end - start);
                int pad = (width > (nlen+2)) ? (width - (nlen+2)) : 0;
                if (!left) _pad(&snk, ' ', pad);
                _sink_mem(&snk, pref, 2);
                _sink_mem(&snk, start, (size_t)nlen);
                if (left) _pad(&snk, ' ', pad);
            } break;

            case '%':
                _sink_char(&snk, '%');
                break;

            default:
                // okänd – skriv rått
                _sink_char(&snk, '%');
                if (spec) _sink_char(&snk, spec);
                break;
        }
    }
    if (snk.error) return -1;
    return (int)snk.count;
}

int fprintf(FILE *stream, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int r = vfprintf(stream, fmt, ap);
    va_end(ap);
    return r;
}

int printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int r = vfprintf(stdout, fmt, ap);
    va_end(ap);
    return r;
}

// ====== Misc ======

int fputs(const char *s, FILE *stream) {
    if (!s) return EOF;
    size_t n = strlen(s);
    size_t w = fwrite(s, 1, n, stream);
    return (w == n) ? (int)n : EOF;
}

int fseek64(FILE *stream, long long off, int whence) {
    // Om du har en 64-bit variant i kernel, använd den; annars fall tillbaka.
    if ((off < LONG_MIN) || (off > LONG_MAX)) return -1;
    return fseek(stream, (long)off, whence);
}

int fileno(FILE *stream) { stream = _coerce(stream, 0); return stream ? stream->impl->fd : -1; }

// ====== Startup ======
__attribute__((constructor))
static void __stdio_constructor(void) {
    _ensure_default_buffers();
    // säkerställ att standardflaggor är rimliga
    __stdin_impl.can_read  = 1; __stdin_impl.can_write = 0;
    __stdout_impl.can_read = 0; __stdout_impl.can_write= 1;
    __stderr_impl.can_read = 0; __stderr_impl.can_write= 1;
    __stdin_impl.fd  = 0;
    __stdout_impl.fd = 1;
    __stderr_impl.fd = 2;
}

char *fgets(char *s, int size, FILE *fp)
{
    if (!s || size <= 0 || !fp) {
        return NULL;
    }

    int i = 0;
    while (i < size - 1) {
        int c = fgetc(fp);
        if (c == EOF) {
            break;
        }
        s[i++] = (char)c;
        if (c == '\n') {
            break;
        }
    }

    if (i == 0) {
        // Läste inget alls (antingen EOF direkt eller size<=1)
        return NULL;
    }

    s[i] = '\0';
    return s;
}

