#pragma once

#include <stddef.h>
#include <stdint.h>

void exit(int code);
void itoa(int value, char *str, int base);
void utoa(unsigned int val, char* buf, int base);
void utohex(uintptr_t val, char* buf, int outlen);
