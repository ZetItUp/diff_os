#include <stdlib.h>
#include <syscall.h>

void exit(int code)
{
    system_exit(code);
}

int system(const char *cmd)
{
    // TODO: Implement this
    (void)cmd;

    return -1;
}

int abs(int x)
{
    return (x < 0) ? -x : x;
}

void itoa(int value, char *str, int base)
{
    char *p = str;
    int is_negative = 0;

    if(value == 0)
    {
        *p++ = '0';
        *p = '\0';

        return;
    }

    if(value < 0 && base == 10)
    {
        is_negative = 1;
        value = -value;
    }

    while(value)
    {
        int digit = value % base;

        *p++ = (digit < 10) ? '0' + digit : 'a' + (digit - 10);
        value /= base;
    }

    if(is_negative)
    {
        *p++ = '-';
    }

    *p = '\0';

    for(char *start = str, *end = p - 1; start < end; start++, end--)
    {
        char tmp = *start;
        *start = *end;
        *end = tmp;
    }
}

void utoa(unsigned int val, char* buf, int base)
{
    char tmp[32];
    int i = 0;
 
    if (val == 0)
    {
        tmp[i++] = '0';
    }
    else 
    {
        while (val > 0) 
        {
            int digit = val % base;
            
            tmp[i++] = digit < 10 ? ('0' + digit) : ('a' + digit - 10);
            val /= base;
        }
    }

    int len = i;
    
    for (int j = 0; j < len; j++)
    {
        buf[j] = tmp[len - j - 1];
    }
    buf[len] = 0;
}

void utohex(uintptr_t val, char* buf, int outlen)
{
    int digits = (outlen > 8) ? 8 : 2;
 
    for (int i = digits-1; i >= 0; --i) 
    {
        int shift = 4*i;
        buf[digits-1-i] = "0123456789ABCDEF"[(val >> shift) & 0xF];
    }
 
    buf[digits] = 0;
}

// Return non-negative magnitude
double fabs(double x)
{
    // Return non-negative magnitude

    return x < 0.0 ? -x : x;
}

// Return non-negative magnitude
float fabsf(float x)
{
    // Return non-negative magnitude

    return x < 0.0f ? -x : x;
}

// Return non-negative magnitude
long double fabsl(long double x)
{
    // Return non-negative magnitude

    return x < 0.0L ? -x : x;
}

static unsigned int g_rand_state = 1;

void srand(unsigned int seed)
{
    g_rand_state = seed ? seed : 1u;
}

int rand(void)
{
    g_rand_state = g_rand_state * 1103515245u + 12345u;
    return (int)((g_rand_state >> 16) & 0x7FFF);
}
