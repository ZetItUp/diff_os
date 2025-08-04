#ifndef STRING_H
#define STRING_H

#include "stdint.h"
#include "stddef.h"

size_t strlen(const char *s);
size_t strcspn(const char *s, const char *reject);
size_t strspn(const char *s, const char *accept);
char *strtok_r(char *str, const char *delim, char **saveptr);
int strncmp(const char *s1, const char *s2, unsigned int n);
int strcmp(const char *s1, const char *s2);
char *strcat(char *dst, const char *src);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dest, const char *src, unsigned int n);
char *strtok(char *str, const char *delim);
char *strchr(const char *str, char c);

void itoa(int value, char *str, int base);

void *memset(void *dest, int value, size_t count);

#endif
