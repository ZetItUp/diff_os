#include <stdio.h>
#include <ctype.h>

// This mimics what strncasecmp does
int test_tolower_in_func(const char *s1, const char *s2, int n)
{
    unsigned char c1, c2;

    for (; n > 0; --n)
    {
        c1 = tolower((unsigned char)*s1++);
        c2 = tolower((unsigned char)*s2++);

        printf("  c1=%c (%d), c2=%c (%d), equal=%s\n",
               c1, c1, c2, c2, (c1 == c2) ? "yes" : "no");

        if (c1 != c2)
        {
            return (int)c1 - (int)c2;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    printf("Testing tolower inside function:\n");

    char test1[8] = "IMPXA1";
    char test2[8] = "IMPXA1";

    int result = test_tolower_in_func(test1, test2, 6);
    printf("Result: %d (should be 0)\n", result);

    return 0;
}
