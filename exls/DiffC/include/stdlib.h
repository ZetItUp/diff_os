#pragma once

#include <stddef.h>
#include <stdint.h>

void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));

int system(const char *cmd);
void exit(int code);

int atoi(const char *s);
void itoa(int value, char *str, int base);
void utoa(unsigned int val, char* buf, int base);
void utohex(uintptr_t val, char* buf, int outlen);

int abs(int x);
double fabs(double x);
float fabsf(float x);
long double fabsl(long double x);
double atof(const char *s);

long strtol(const char *nptr, char **endptr, int base);
unsigned long strtoul(const char *nptr, char **endptr, int base);
long long strtoll(const char *nptr, char **endptr, int base);
unsigned long long strtoull(const char *nptr, char **endptr, int base);
double strtod(const char *nptr, char **endptr);

void *realloc(void *ptr, size_t size);
void *calloc(size_t count, size_t size);
void *malloc(size_t size);
void free(void *ptr);

