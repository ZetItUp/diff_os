#pragma once 

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

#define EOF (-1)

#define FILE_CAN_READ  0x01
#define FILE_CAN_WRITE 0x02

typedef struct FILE
{
    int file_descriptor;
    int flags;
    int error;
    int eof;
    int ungot;
} FILE;

#ifndef O_RDONLY
#define O_RDONLY        0x0000
#define O_WRONLY        0x0001
#define O_RDWR          0x0002
#define O_CREAT         0x0100
#define O_TRUNC         0x0200
#define O_APPEND        0x0400
#endif

#ifndef SEEK_SET
#define SEEK_SET        0
#define SEEK_CUR        1
#define SEEK_END        2
#endif

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

/* File operations */
FILE *fopen(const char *path, const char *mode);
int fclose(FILE *fp);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *fp);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *fp);
int fseek(FILE *fp, long offset, int whence);
long ftell(FILE *fp);
void rewind(FILE *fp);
int fflush(FILE *fp);

/* Character I/O */
int fgetc(FILE *fp);
int getc(FILE *fp);
int getchar(void);
int ungetc(int c, FILE *fp);
int fputc(int c, FILE *fp);
int putc(int c, FILE *fp);
int putchar(int c);

/* String I/O */
char *fgets(char *s, int size, FILE *fp);
int fputs(const char *s, FILE *fp);

/* Error handling */
int feof(FILE *fp);
int ferror(FILE *fp);
void clearerr(FILE *fp);

/* Formatted I/O */
int printf(const char *fmt, ...);
int vprintf(const char *fmt, va_list ap);
int sprintf(char *str, const char *fmt, ...);
int vsprintf(char *str, const char *fmt, va_list ap);
int snprintf(char *str, size_t size, const char *fmt, ...);
int vsnprintf(char *str, size_t size, const char *fmt, va_list ap);
int fprintf(FILE *fp, const char *fmt, ...);
int vfprintf(FILE *fp, const char *fmt, va_list ap);
ssize_t getline(char **lineptr, size_t *n);
