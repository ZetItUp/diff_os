#include <stdio.h>
#include <ctype.h>

int main(int argc, char **argv)
{
    printf("Testing tolower function:\n");
    printf("tolower('A') = '%c' (%d)\n", tolower('A'), tolower('A'));
    printf("tolower('I') = '%c' (%d)\n", tolower('I'), tolower('I'));
    printf("tolower('M') = '%c' (%d)\n", tolower('M'), tolower('M'));
    printf("tolower('a') = '%c' (%d)\n", tolower('a'), tolower('a'));
    printf("tolower('i') = '%c' (%d)\n", tolower('i'), tolower('i'));
    printf("tolower('m') = '%c' (%d)\n", tolower('m'), tolower('m'));

    unsigned char c1 = tolower('I');
    unsigned char c2 = tolower('i');
    printf("\nComparing 'I' and 'i' after tolower:\n");
    printf("c1 = %c (%d), c2 = %c (%d)\n", c1, c1, c2, c2);
    printf("c1 == c2: %s\n", (c1 == c2) ? "true" : "false");
    printf("c1 - c2 = %d\n", (int)c1 - (int)c2);

    return 0;
}
