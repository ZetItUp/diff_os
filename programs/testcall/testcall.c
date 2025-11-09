#include <stdio.h>
#include <ctype.h>

int test_tolower_loop(const char *s1, const char *s2, int n)
{
    for (; n > 0; --n)
    {
        unsigned char c1 = tolower((unsigned char)*s1++);
        unsigned char c2 = tolower((unsigned char)*s2++);

        printf("  c1=%c (%d), c2=%c (%d)\n", c1, c1, c2, c2);

        if (c1 != c2)
        {
            return (int)c1 - (int)c2;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    char test1[] = "IMPXA1";
    char test2[] = "IMPXA1";

    printf("Testing: %s vs %s\n", test1, test2);
    int result = test_tolower_loop(test1, test2, 6);
    printf("Result: %d (should be 0)\n", result);

    return 0;
}
