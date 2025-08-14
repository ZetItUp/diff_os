#include <ctype.h>

int isspace(int c)
{
    unsigned char uc = (unsigned char)c;

    return uc == ' ' || uc == '\f' || uc == '\n' || uc == '\r' || uc == '\t' || uc == '\v';
}
