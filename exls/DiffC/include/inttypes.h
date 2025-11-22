#pragma once

#include <stdint.h>

typedef struct imaxdiv_t
{
    intmax_t quot;
    intmax_t rem;
} imaxdiv_t;

intmax_t  strtoimax(const char *nptr, char **endptr, int base);
uintmax_t strtoumax(const char *nptr, char **endptr, int base);
imaxdiv_t imaxdiv(intmax_t numer, intmax_t denom);

