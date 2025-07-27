#ifndef STRING_H
#define STRING_H

#include "stdint.h"

int strncmp(const char *s1, const char *s2, unsigned int n);
char *strncpy(char *dest, const char *src, unsigned int n);
char *strtok(char *str, const char *delim);
char *strchr(const char *str, char c);

void itoa(int value, char *str, int base);

#endif
