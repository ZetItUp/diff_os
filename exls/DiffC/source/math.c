#include <math.h>

static double atan_poly(double x)
{
    double x2 = x * x;
    double poly = (((((-0.0752896400 * x2 + 0.1065626393) * x2 - 0.1420889944) * x2
        + 0.1999355085) * x2 - 0.3333314528) * x2 + 1.0);

    return x * poly;
}

double atan(double x)
{
    const double pi_over_2 = 1.57079632679489661923;
    const double pi_over_4 = 0.78539816339744830962;
    const double tan_pi_over_8 = 0.41421356237309504880;
    double result = 0.0;
    int sign = 1;

    if(x < 0.0)
    {
        sign = -1;
        x = -x;
    }

    if(x > 1.0)
    {
        result = pi_over_2 - atan_poly(1.0 / x);
    }
    else if(x > tan_pi_over_8)
    {
        result = pi_over_4 + atan_poly((x - 1.0) / (x + 1.0));
    }
    else
    {
        result = atan_poly(x);
    }

    return sign * result;
}

double atan2(double y, double x)
{
    const double pi = 3.14159265358979323846;
    const double pi_over_2 = 1.57079632679489661923;

    if(x > 0.0)
    {
        return atan(y / x);
    }

    if(x < 0.0 && y >= 0.0)
    {
        return atan(y / x) + pi;
    }

    if(x < 0.0 && y < 0.0)
    {
        return atan(y / x) - pi;
    }

    if(x == 0.0 && y > 0.0)
    {
        return pi_over_2;
    }

    if(x == 0.0 && y < 0.0)
    {
        return -pi_over_2;
    }

    if(x < 0.0 && y == 0.0)
    {
        return pi;
    }

    return 0.0;
}

double ceil(double x)
{
    long long trunc = (long long)x;

    if((double)trunc == x)
    {

        return x;
    }

    if(x > 0.0)
    {

        return (double)(trunc + 1);
    }

    return (double)trunc;
}

double floor(double x)
{
    long long trunc = (long long)x;

    if((double)trunc == x)
    {

        return x;
    }

    if(x < 0.0)
    {

        return (double)(trunc - 1);
    }

    return (double)trunc;
}

static double wrap_pi(double x)
{
    const double two_pi = 6.28318530717958647692;
    const double pi = 3.14159265358979323846;
    long long k = (long long)(x / two_pi);

    x -= (double)k * two_pi;

    if(x > pi)
    {
        x -= two_pi;
    }
    else if(x < -pi)
    {
        x += two_pi;
    }

    return x;
}

static double sin_poly(double x)
{
    double x2 = x * x;
    double poly = 1.0 + x2 * (-(1.0 / 6.0)
        + x2 * ((1.0 / 120.0)
        + x2 * (-(1.0 / 5040.0)
        + x2 * ((1.0 / 362880.0)
        + x2 * (-(1.0 / 39916800.0)
        + x2 * (1.0 / 6227020800.0))))));

    return x * poly;
}

static double cos_poly(double x)
{
    double x2 = x * x;
    double poly = 1.0 + x2 * (-(1.0 / 2.0)
        + x2 * ((1.0 / 24.0)
        + x2 * (-(1.0 / 720.0)
        + x2 * ((1.0 / 40320.0)
        + x2 * (-(1.0 / 3628800.0)
        + x2 * (1.0 / 479001600.0))))));

    return poly;
}

double sin(double x)
{
    const double pi_over_2 = 1.57079632679489661923;
    const double pi = 3.14159265358979323846;
    double y = wrap_pi(x);

    if(y > pi_over_2)
    {
        y = pi - y;
    }
    else if(y < -pi_over_2)
    {
        y = -pi - y;
    }

    return sin_poly(y);
}

double cos(double x)
{
    const double pi_over_2 = 1.57079632679489661923;
    const double pi = 3.14159265358979323846;
    double y = wrap_pi(x);
    int sign = 1;

    if(y > pi_over_2)
    {
        y = pi - y;
        sign = -1;
    }
    else if(y < -pi_over_2)
    {
        y = -pi - y;
        sign = -1;
    }

    return sign * cos_poly(y);
}

double tan(double x)
{
    const double large_value = 1.0e308;
    double sin_value = sin(x);
    double cos_value = cos(x);

    if(cos_value == 0.0)
    {

        return (sin_value >= 0.0) ? large_value : -large_value;
    }

    return sin_value / cos_value;
}

double exp(double x)
{
    const double ln2 = 0.69314718055994530942;
    double scaled = x / ln2;
    long long exponent = (long long)floor(scaled);
    double remainder = x - ((double)exponent * ln2);
    double remainder2 = remainder * remainder;
    double remainder3 = remainder2 * remainder;
    double remainder4 = remainder2 * remainder2;
    double remainder5 = remainder4 * remainder;
    double poly = 1.0 + remainder + remainder2 * 0.5 + remainder3 * (1.0 / 6.0)
        + remainder4 * (1.0 / 24.0) + remainder5 * (1.0 / 120.0);
    double scale = 1.0;
    long long shift = exponent;
    double base = 2.0;

    if(shift < 0)
    {
        shift = -shift;
        base = 0.5;
    }

    while(shift > 0)
    {
        if((shift & 1) != 0)
        {
            scale *= base;
        }

        base *= base;
        shift >>= 1;
    }

    return scale * poly;
}

double log(double x)
{
    const double ln2 = 0.69314718055994530942;
    double value = x;
    int exponent = 0;
    double y;
    double y2;
    double term;
    double result;

    if(value <= 0.0)
    {

        return 0.0;
    }

    while(value > 2.0)
    {
        value *= 0.5;
        exponent++;
    }

    while(value < 0.5)
    {
        value *= 2.0;
        exponent--;
    }

    y = (value - 1.0) / (value + 1.0);
    y2 = y * y;
    term = y;
    result = term;

    term *= y2;
    result += term / 3.0;
    term *= y2;
    result += term / 5.0;
    term *= y2;
    result += term / 7.0;
    term *= y2;
    result += term / 9.0;

    result *= 2.0;
    result += (double)exponent * ln2;

    return result;
}

double pow(double x, double y)
{
    long long integer_power = (long long)y;
    double diff = y - (double)integer_power;
    double diff_abs = diff < 0.0 ? -diff : diff;
    double result = 1.0;
    double base = x;
    long long power = integer_power;

    if(x == 0.0)
    {
        if(y > 0.0)
        {

            return 0.0;
        }

        return 1.0;
    }

    if(x < 0.0)
    {
        if(diff_abs < 1.0e-10)
        {
            if(power < 0)
            {
                base = 1.0 / base;
                power = -power;
            }

            while(power > 0)
            {
                if((power & 1) != 0)
                {
                    result *= base;
                }

                base *= base;
                power >>= 1;
            }

            return result;
        }

        return 0.0;
    }

    if(diff_abs < 1.0e-10)
    {
        if(power < 0)
        {
            base = 1.0 / base;
            power = -power;
        }

        while(power > 0)
        {
            if((power & 1) != 0)
            {
                result *= base;
            }

            base *= base;
            power >>= 1;
        }

        return result;
    }

    return exp(y * log(x));
}

double sqrt(double x)
{
    if(x <= 0.0)
    {

        return 0.0;
    }

    double guess = x;

    if(guess < 1.0)
    {
        guess = 1.0;
    }

    for(int i = 0; i < 16; i++)
    {
        guess = 0.5 * (guess + x / guess);
    }

    return guess;
}
