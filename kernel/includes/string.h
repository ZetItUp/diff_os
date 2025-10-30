#ifndef STRING_H
#define STRING_H

#include "stdint.h"
#include "stddef.h"

void *memchr(const void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *dest, int c, size_t n);
size_t strlen(const char *s);
size_t strnlen(const char *s, size_t maxlen);
char *strcpy(char *dest, const char *src);                  // legacy, unsafe
char *strchr(const char *s, int c);
char *strncpy(char *dest, const char *src, size_t n);
char *strcat(char *dest, const char *src);                  // legacy, unsafe
char *strncat(char *dest, const char *src, size_t n);        // legacy, unsafe
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strdup(const char *s);
char *strtok_r(char *str, const char *delim, char **saveptr);
char *strtok(char *str, const char *delim);
size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);
char *utoa_s(unsigned int value, char *str, size_t size, int base);
char *itoa_s(int value, char *str, size_t size, int base);
char *utohex(unsigned int value, char *str, size_t size, int uppercase);


#endif
