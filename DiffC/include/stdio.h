#pragma once
#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DIFFC_HAS_SSIZE_T
#define DIFFC_HAS_SSIZE_T
typedef long ssize_t;   // POSIX typedef
#endif

typedef struct FILE FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

FILE *fopen(const char *path, const char *mode);
int fclose(FILE *fp);

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *fp);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *fp);

int fseek(FILE *fp, long offset, int whence);
long ftell(FILE *fp);
void rewind(FILE *fp);

int fflush(FILE *fp);           
int feof(FILE *fp);
int ferror(FILE *fp);
void clearerr(FILE *fp);

int fgetc(FILE *fp);
int ungetc(int c, FILE *fp);
int fputc(int c, FILE *fp);

char *fgets(char *s, int size, FILE *fp);
int fputs(const char *s, FILE *fp);

int putchar(int c);
int puts(const char *s);

/* Non-standard helper kept for compatibility */
void print(const char *s);

int printf(const char *fmt, ...);
int vprintf(const char *fmt, va_list ap);

int snprintf(char *dst, size_t size, const char *fmt, ...);
int vsnprintf(char *dst, size_t size, const char *fmt, va_list ap);

int read_line(char *buf, size_t size);
ssize_t getline(char **lineptr, size_t *size);

#ifdef __cplusplus
}
#endif

