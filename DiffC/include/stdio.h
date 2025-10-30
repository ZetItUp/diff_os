#pragma once

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

/* Standard return for EOF */
#ifndef EOF
#define EOF (-1)
#endif

/* open(2)-flaggor – behåll dina värden */
#ifndef O_RDONLY
#define O_RDONLY        0x0000
#define O_WRONLY        0x0001
#define O_RDWR          0x0002
#define O_CREAT         0x0100
#define O_TRUNC         0x0200
#define O_APPEND        0x0400
#endif

/* seek(2)-konstanter */
#ifndef SEEK_SET
#define SEEK_SET        0
#define SEEK_CUR        1
#define SEEK_END        2
#endif

/* Buffering-lägen (libc-stil) */
#ifndef _IOFBF
#define _IOFBF  0   /* full buffered */
#endif
#ifndef _IOLBF
#define _IOLBF  1   /* line buffered */
#endif
#ifndef _IONBF
#define _IONBF  2   /* unbuffered */
#endif

/* Framåtdeklaration av intern implementation (dold i stdio.c) */
struct _FileImpl;

/* OPAK FILE – matchar stdio.c (pekar på _FileImpl) */
typedef struct FILE {
    struct _FileImpl *impl;
} FILE;

/* Standardströmmar (pekare till statiska objekt i stdio.c) */
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

/* File operations */
FILE   *fopen(const char *path, const char *mode);
FILE   *fdopen(int fd, const char *mode);     /* tillagd: matchar stdio.c */
int     fclose(FILE *fp);
size_t  fread(void *ptr, size_t size, size_t nmemb, FILE *fp);
size_t  fwrite(const void *ptr, size_t size, size_t nmemb, FILE *fp);
int     fseek(FILE *fp, long offset, int whence);
long    ftell(FILE *fp);
void    rewind(FILE *fp);                      /* kan vara no-op om ej använd */
int     fflush(FILE *fp);
int     fileno(FILE *fp);                      /* tillagd: matchar stdio.c */

int     remove(const char *path);
int     rename(const char *oldpath, const char *newpath);

/* Buffering-kontroll (libc-stil) */
int     setvbuf(FILE *stream, char *buf, int mode, size_t size);
void    setbuf(FILE *stream, char *buf);

/* Character I/O */
int     fgetc(FILE *fp);
int     getc(FILE *fp);
int     getchar(void);
int     ungetc(int c, FILE *fp);
int     fputc(int c, FILE *fp);
int     putc(int c, FILE *fp);
int     putchar(int c);
int     puts(const char *s);

/* String I/O */
char   *fgets(char *s, int size, FILE *fp);
int     fputs(const char *s, FILE *fp);
int     sscanf(const char *str, const char *fmt, ...);

/* Error handling */
int     feof(FILE *fp);
int     ferror(FILE *fp);
void    clearerr(FILE *fp);

/* Formatted I/O */
int     printf(const char *fmt, ...);
int     vprintf(const char *fmt, va_list ap);
int     sprintf(char *str, const char *fmt, ...);
int     vsprintf(char *str, const char *fmt, va_list ap);
int     snprintf(char *str, size_t size, const char *fmt, ...);
int     vsnprintf(char *str, size_t size, const char *fmt, va_list ap);
int     fprintf(FILE *fp, const char *fmt, ...);
int     vfprintf(FILE *fp, const char *fmt, va_list ap);

/* POSIX-lik getline (implementeras i din getline.c) */
ssize_t getline(char **lineptr, size_t *n);

