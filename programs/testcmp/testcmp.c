#include <stdio.h>
#include <string.h>

int main() {
    char s1[8] = "POSSA1";
    char s2[8] = "IMPXA1";
    
    printf("Testing strncasecmp:\n");
    printf("Comparing 'POSSA1' vs 'IMPXA1' (8 chars): %d\n", strncasecmp(s1, s2, 8));
    printf("Comparing 'POSSA1' vs 'POSSA1' (8 chars): %d\n", strncasecmp(s1, s1, 8));
    
    // Test with shorter strings
    char short1[4] = "ABC";
    char short2[4] = "XYZ";
    printf("Comparing 'ABC' vs 'XYZ' (8 chars): %d\n", strncasecmp(short1, short2, 8));
    
    return 0;
}
