#include <ctype.h>

int isspace(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

int isdigit(int c)
{
    return c >= '0' && c <= '9';
}

int isxdigit(int c)
{
    if (c >= '0' && c <= '9')
    {
        return 1;
    }

    if (c >= 'a' && c <= 'f')
    {
        return 1;
    }

    if (c >= 'A' && c <= 'F')
    {
        return 1;
    }

    return 0;
}

__attribute__((noinline)) int tolower(int c)
{
    // Zero-extend the input parameter to avoid garbage in upper bytes
    c = c & 0xFF;

    if (c >= 'A' && c <= 'Z')
    {
        return (c - 'A' + 'a');
    }

    return c;
}

int toupper(int c)
{
    if (c >= 'a' && c <= 'z')
    {
        return c - 'a' + 'A';
    }

    return c;
}

