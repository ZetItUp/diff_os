// floattest.c - Simple floating point math test
#include <stdio.h>

int main(int argc, char **argv)
{
    printf("=== Floating Point Test ===\n\n");

    // Basic operations
    float a = 3.14159f;
    float b = 2.71828f;
    printf("Basic operations:\n");
    printf("  a = %f\n", (double)a);
    printf("  b = %f\n", (double)b);
    printf("  a + b = %f (expect ~5.859)\n", (double)(a + b));
    printf("  a - b = %f (expect ~0.423)\n", (double)(a - b));
    printf("  a * b = %f (expect ~8.539)\n", (double)(a * b));
    printf("  a / b = %f (expect ~1.155)\n", (double)(a / b));

    // Negative numbers
    printf("\nNegative numbers:\n");
    float neg = -123.456f;
    printf("  neg = %f\n", (double)neg);
    printf("  neg * 2 = %f (expect -246.912)\n", (double)(neg * 2.0f));
    printf("  neg + 200 = %f (expect 76.544)\n", (double)(neg + 200.0f));
    printf("  neg * neg = %f (expect ~15241.38)\n", (double)(neg * neg));

    // Large numbers
    printf("\nLarge numbers:\n");
    float big = 1234567.0f;
    float big2 = 9876543.0f;
    printf("  big = %f\n", (double)big);
    printf("  big2 = %f\n", (double)big2);
    printf("  big + big2 = %f (expect 11111110)\n", (double)(big + big2));
    printf("  big * 1000 = %f (expect 1234567000)\n", (double)(big * 1000.0f));

    // Very large numbers
    printf("\nVery large numbers:\n");
    float huge = 1.0e30f;
    float huge2 = 2.5e30f;
    printf("  huge = %e\n", (double)huge);
    printf("  huge2 = %e\n", (double)huge2);
    printf("  huge + huge2 = %e (expect 3.5e30)\n", (double)(huge + huge2));
    printf("  huge * 2 = %e (expect 2.0e30)\n", (double)(huge * 2.0f));

    // Small numbers
    printf("\nSmall numbers:\n");
    float tiny = 0.000001f;
    float tiny2 = 0.000002f;
    printf("  tiny = %e\n", (double)tiny);
    printf("  tiny2 = %e\n", (double)tiny2);
    printf("  tiny + tiny2 = %e (expect 3.0e-6)\n", (double)(tiny + tiny2));
    printf("  tiny * 1000000 = %f (expect 1.0)\n", (double)(tiny * 1000000.0f));

    // Mixed signs and magnitudes
    printf("\nMixed operations:\n");
    float x = -99999.5f;
    float y = 100000.5f;
    printf("  x = %f\n", (double)x);
    printf("  y = %f\n", (double)y);
    printf("  x + y = %f (expect 1.0)\n", (double)(x + y));
    printf("  x * y = %e (expect ~-1.0e10)\n", (double)(x * y));

    // Double precision test
    printf("\nDouble precision:\n");
    double da = 3.141592653589793;
    double db = 2.718281828459045;
    printf("  da = %.15f\n", da);
    printf("  db = %.15f\n", db);
    printf("  da * db = %.15f\n", da * db);
    printf("  (expect ~8.539734222673566)\n");

    // Verify specific known results
    printf("\n=== Verification ===\n");
    int passed = 0;
    int failed = 0;

    // Test 1: 2 + 2 = 4
    float r1 = 2.0f + 2.0f;
    if (r1 > 3.99f && r1 < 4.01f)
    {
        printf("PASS: 2 + 2 = %f\n", (double)r1);
        passed++;
    }
    else
    {
        printf("FAIL: 2 + 2 = %f (expected 4)\n", (double)r1);
        failed++;
    }

    // Test 2: 10 / 4 = 2.5
    float r2 = 10.0f / 4.0f;
    if (r2 > 2.49f && r2 < 2.51f)
    {
        printf("PASS: 10 / 4 = %f\n", (double)r2);
        passed++;
    }
    else
    {
        printf("FAIL: 10 / 4 = %f (expected 2.5)\n", (double)r2);
        failed++;
    }

    // Test 3: -5 * -5 = 25
    float r3 = -5.0f * -5.0f;
    if (r3 > 24.99f && r3 < 25.01f)
    {
        printf("PASS: -5 * -5 = %f\n", (double)r3);
        passed++;
    }
    else
    {
        printf("FAIL: -5 * -5 = %f (expected 25)\n", (double)r3);
        failed++;
    }

    // Test 4: Large subtraction
    float r4 = 1000000.0f - 999999.0f;
    if (r4 > 0.99f && r4 < 1.01f)
    {
        printf("PASS: 1000000 - 999999 = %f\n", (double)r4);
        passed++;
    }
    else
    {
        printf("FAIL: 1000000 - 999999 = %f (expected 1)\n", (double)r4);
        failed++;
    }

    // Test 5: Negative division
    float r5 = -100.0f / 4.0f;
    if (r5 > -25.01f && r5 < -24.99f)
    {
        printf("PASS: -100 / 4 = %f\n", (double)r5);
        passed++;
    }
    else
    {
        printf("FAIL: -100 / 4 = %f (expected -25)\n", (double)r5);
        failed++;
    }

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);

    return failed;
}
