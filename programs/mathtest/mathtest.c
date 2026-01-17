// mathtest.c - Compact math function tests
#include <stdio.h>
#include <math.h>

static int passed = 0;
static int failed = 0;

static int check(const char *name, double got, double expect, double tol)
{
    double diff = got - expect;
    if (diff < 0) diff = -diff;
    int ok = (diff <= tol);
    if (ok) { passed++; printf("OK  "); }
    else    { failed++; printf("ERR "); }
    printf("%s: got=%.6f exp=%.6f\n", name, got, expect);
    return ok;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("=== Math Test ===\n");

    // sqrt
    check("sqrt(4)", sqrt(4.0), 2.0, 0.0001);
    check("sqrt(2)", sqrt(2.0), 1.414214, 0.0001);
    check("sqrt(100)", sqrt(100.0), 10.0, 0.0001);

    // sin
    check("sin(0)", sin(0.0), 0.0, 0.0001);
    check("sin(pi/2)", sin(M_PI/2), 1.0, 0.0001);
    check("sin(pi)", sin(M_PI), 0.0, 0.0001);
    check("sin(-pi/2)", sin(-M_PI/2), -1.0, 0.0001);

    // cos
    check("cos(0)", cos(0.0), 1.0, 0.0001);
    check("cos(pi/2)", cos(M_PI/2), 0.0, 0.0001);
    check("cos(pi)", cos(M_PI), -1.0, 0.0001);

    // tan
    check("tan(0)", tan(0.0), 0.0, 0.0001);
    check("tan(pi/4)", tan(M_PI/4), 1.0, 0.0001);

    // atan
    check("atan(0)", atan(0.0), 0.0, 0.0001);
    check("atan(1)", atan(1.0), M_PI/4, 0.0001);
    check("atan(-1)", atan(-1.0), -M_PI/4, 0.0001);

    // atan2
    check("atan2(1,1)", atan2(1.0, 1.0), M_PI/4, 0.0001);
    check("atan2(1,0)", atan2(1.0, 0.0), M_PI/2, 0.0001);
    check("atan2(-1,0)", atan2(-1.0, 0.0), -M_PI/2, 0.0001);

    // exp
    check("exp(0)", exp(0.0), 1.0, 0.0001);
    check("exp(1)", exp(1.0), 2.718282, 0.001);
    check("exp(2)", exp(2.0), 7.389056, 0.001);
    check("exp(-1)", exp(-1.0), 0.367879, 0.001);

    // log
    check("log(1)", log(1.0), 0.0, 0.0001);
    check("log(e)", log(2.718282), 1.0, 0.001);
    check("log(10)", log(10.0), 2.302585, 0.001);

    // pow
    check("pow(2,3)", pow(2.0, 3.0), 8.0, 0.0001);
    check("pow(2,0.5)", pow(2.0, 0.5), 1.414214, 0.001);
    check("pow(10,2)", pow(10.0, 2.0), 100.0, 0.0001);
    check("pow(2,-1)", pow(2.0, -1.0), 0.5, 0.0001);

    // floor
    check("floor(2.7)", floor(2.7), 2.0, 0.0001);
    check("floor(-2.7)", floor(-2.7), -3.0, 0.0001);
    check("floor(5.0)", floor(5.0), 5.0, 0.0001);

    // ceil
    check("ceil(2.3)", ceil(2.3), 3.0, 0.0001);
    check("ceil(-2.3)", ceil(-2.3), -2.0, 0.0001);
    check("ceil(5.0)", ceil(5.0), 5.0, 0.0001);

    // fabs
    check("fabs(-5.5)", fabs(-5.5), 5.5, 0.0001);
    check("fabs(3.3)", fabs(3.3), 3.3, 0.0001);

    printf("=== %d pass, %d fail ===\n", passed, failed);
    return failed;
}
