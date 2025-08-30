#pragma once

#include <stdint.h>
#include <stddef.h>

int strcasecmp(const char *s1, const char *s2);
int strncasecmp(const char *s1, const char *s2, size_t n);

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
char *strdup(const char *s);
char *strrchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);

void *memset(void *dest, int value, size_t count);
void *memcpy(void *dest, const void *src, unsigned int n);
void *memmove(void *dst, const void *src, size_t n);
