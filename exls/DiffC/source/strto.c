#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>

static int xval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'z') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'Z') return 10 + (c - 'A');
    
    return -1;
}

static int base_ok(int base)
{
    return base == 0 || (base >= 2 && base <= 36);
}

long long strtoll(const char *nptr, char **endptr, int base)
{
    const char *s = nptr;
    int neg = 0;

    if (!base_ok(base))
    {
        if (endptr) *endptr = (char *)nptr;
        
        return 0;
    }

    while (isspace(*s))
    {
        s++;
    }

    if (*s == '+' || *s == '-')
    {
        neg = (*s == '-');
        s++;
    }

    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        base = 16;
        s += 2;
    }
    else if (base == 0)
    {
        base = (s[0] == '0') ? 8 : 10;
    }

    unsigned long long acc = 0;
    int any = 0;

    for (;;)
    {
        int d = xval(*s);

        if (d < 0 || d >= base)
        {
            break;
        }

        acc = acc * (unsigned)base + (unsigned)d;
        s++;
        any = 1;
    }

    if (!any)
    {
        if (endptr) *endptr = (char *)nptr;
        
        return 0;
    }

    if (endptr) *endptr = (char *)s;

    if (neg)
    {
        if (acc > (unsigned long long)0x8000000000000000ULL)
        {
            return (long long)0x8000000000000000LL;
        }

        return -(long long)acc;
    }

    if (acc > (unsigned long long)0x7fffffffffffffffULL)
    {
        return (long long)0x7fffffffffffffffLL;
    }

    return (long long)acc;
}

unsigned long long strtoull(const char *nptr, char **endptr, int base)
{
    const char *s = nptr;

    if (!base_ok(base))
    {
        if (endptr) *endptr = (char *)nptr;
        
        return 0;
    }

    while (isspace(*s))
    {
        s++;
    }

    int neg = 0;

    if (*s == '+' || *s == '-')
    {
        neg = (*s == '-');
        s++;
    }

    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        base = 16;
        s += 2;
    }
    else if (base == 0)
    {
        base = (s[0] == '0') ? 8 : 10;
    }

    unsigned long long acc = 0;
    int any = 0;

    for (;;)
    {
        int d = xval(*s);

        if (d < 0 || d >= base)
        {
            break;
        }

        acc = acc * (unsigned)base + (unsigned)d;
        s++;
        any = 1;
    }

    if (!any)
    {
        if (endptr) *endptr = (char *)nptr;
        
        return 0;
    }

    if (endptr) *endptr = (char *)s;

    if (neg)
    {
        acc = (unsigned long long)(-(long long)acc);
    }

    return acc;
}

long strtol(const char *nptr, char **endptr, int base)
{
    long long v = strtoll(nptr, endptr, base);
    
    return (long)v;
}

unsigned long strtoul(const char *nptr, char **endptr, int base)
{
    unsigned long long v = strtoull(nptr, endptr, base);
    
    return (unsigned long)v;
}

double strtod(const char *nptr, char **endptr)
{
    const char *s = nptr;
    int neg = 0;

    while (isspace(*s))
    {
        s++;
    }

    if (*s == '+' || *s == '-')
    {
        neg = (*s == '-');
        s++;
    }

    int any = 0;
    double val = 0.0;

    while (isdigit(*s))
    {
        val = val * 10.0 + (double)(*s - '0');
        s++;
        any = 1;
    }

    if (*s == '.')
    {
        s++;

        double place = 0.1;

        while (isdigit(*s))
        {
            val += (double)(*s - '0') * place;
            place *= 0.1;
            s++;
            any = 1;
        }
    }

    if (!any)
    {
        if (endptr) *endptr = (char *)nptr;
        
        return 0.0;
    }

    int exp_sign = 1;
    int exp_val = 0;

    if (tolower(*s) == 'e')
    {
        const char *e = s + 1;

        if (*e == '+' || *e == '-')
        {
            exp_sign = (*e == '-') ? -1 : 1;
            e++;
        }

        if (isdigit(*e))
        {
            s = e;

            while (isdigit(*s))
            {
                exp_val = exp_val * 10 + (*s - '0');
                s++;
            }

            int n = exp_sign * exp_val;

            if (n > 0)
            {
                while (n--)
                {
                    val *= 10.0;
                }
            }
            else if (n < 0)
            {
                while (n++)
                {
                    val *= 0.1;
                }
            }
        }
    }

    if (endptr) *endptr = (char *)s;

    if (neg)
    {
        val = -val;
    }

    return val;
}

int atoi(const char *s)
{
    return (int)strtol(s, 0, 10);
}

double atof(const char *s)
{
    return strtod(s, 0);
}

