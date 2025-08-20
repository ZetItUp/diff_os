#include <stdint.h>

static unsigned long long udivmod64(unsigned long long n,
                                    unsigned long long d,
                                    unsigned long long* rem)
{
    if (d == 0ull)
    {
        if (rem) { *rem = 0ull; }
        return 0ull;
    }

    unsigned long long q = 0ull;
    unsigned long long r = 0ull;

    for (int i = 63; i >= 0; --i)
    {
        r = (r << 1) | ((n >> i) & 1ull);
        if (r >= d)
        {
            r -= d;
            q |= (1ull << i);
        }
    }

    if (rem) { *rem = r; }
    return q;
}

unsigned long long __udivmoddi4(unsigned long long n,
                                unsigned long long d,
                                unsigned long long* rem)
{
    return udivmod64(n, d, rem);
}

unsigned long long __udivdi3(unsigned long long n,
                             unsigned long long d)
{
    unsigned long long r;
    return udivmod64(n, d, &r);
}

unsigned long long __umoddi3(unsigned long long n,
                             unsigned long long d)
{
    unsigned long long r;
    (void)udivmod64(n, d, &r);
    return r;
}

long long __divdi3(long long a, long long b)
{
    int neg = ((a < 0) ^ (b < 0));
    unsigned long long ua = (a < 0) ? (unsigned long long)(-a) : (unsigned long long)a;
    unsigned long long ub = (b < 0) ? (unsigned long long)(-b) : (unsigned long long)b;

    unsigned long long r;
    unsigned long long q = udivmod64(ua, ub, &r);

    return neg ? -(long long)q : (long long)q;
}

long long __moddi3(long long a, long long b)
{
    int neg = (a < 0);
    unsigned long long ua = (a < 0) ? (unsigned long long)(-a) : (unsigned long long)a;
    unsigned long long ub = (b < 0) ? (unsigned long long)(-b) : (unsigned long long)b;

    unsigned long long r;
    (void)udivmod64(ua, ub, &r);

    long long res = (long long)r;
    return neg ? -res : res;
}

