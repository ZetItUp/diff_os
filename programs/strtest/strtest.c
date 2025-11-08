#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Test cases specifically for WAD lump name comparisons
int main(int argc, char **argv)
{
    printf("=== Testing DiffC strncasecmp implementation ===\n\n");

    // Test 1: Basic different strings (what Doom does)
    printf("Test 1 - Different lump names:\n");
    int res1 = strncasecmp("IMPXA1", "POSSA1", 8);
    printf("  strncasecmp('IMPXA1', 'POSSA1', 8) = %d %s\n", res1, res1 == 0 ? "MATCH!" : "no match");

    // Test 2: Same lump names
    printf("\nTest 2 - Identical lump names:\n");
    int res2 = strncasecmp("IMPXA1", "IMPXA1", 8);
    printf("  strncasecmp('IMPXA1', 'IMPXA1', 8) = %d %s\n", res2, res2 == 0 ? "MATCH!" : "no match");

    // Test 3: Case insensitive
    printf("\nTest 3 - Case insensitive:\n");
    int res3 = strncasecmp("IMPXA1", "impxa1", 8);
    printf("  strncasecmp('IMPXA1', 'impxa1', 8) = %d %s\n", res3, res3 == 0 ? "MATCH!" : "no match");

    // Test 4: Simulating 8-byte lump names (no null terminator)
    printf("\nTest 4 - 8-byte lump names without null terminator:\n");
    char lump1[9] = "IMPXA1XX";  // 8 bytes, last 2 will be ignored
    char lump2[9] = "POSSA1YY";  // 8 bytes, different
    char lump3[9] = "IMPXA1ZZ";  // 8 bytes, first 6 match lump1

    int res4a = strncasecmp(lump1, lump2, 8);
    printf("  strncasecmp('IMPXA1XX', 'POSSA1YY', 8) = %d %s\n", res4a, res4a == 0 ? "MATCH!" : "no match");

    int res4b = strncasecmp(lump1, lump3, 8);
    printf("  strncasecmp('IMPXA1XX', 'IMPXA1ZZ', 8) = %d %s\n", res4b, res4b == 0 ? "MATCH!" : "no match");

    // Test 5: Short string vs long (what happens when comparing 4-char name)
    printf("\nTest 5 - Short vs long string:\n");
    int res5 = strncasecmp("IMPX", "IMPXA1", 8);
    printf("  strncasecmp('IMPX', 'IMPXA1', 8) = %d %s\n", res5, res5 == 0 ? "MATCH!" : "no match");

    // Test 6: Check tolower/toupper
    printf("\nTest 6 - Testing tolower/toupper:\n");
    printf("  tolower('A') = '%c' (expect 'a')\n", tolower('A'));
    printf("  tolower('a') = '%c' (expect 'a')\n", tolower('a'));
    printf("  tolower('Z') = '%c' (expect 'z')\n", tolower('Z'));
    printf("  tolower('1') = '%c' (expect '1')\n", tolower('1'));
    printf("  toupper('a') = '%c' (expect 'A')\n", toupper('a'));
    printf("  toupper('A') = '%c' (expect 'A')\n", toupper('A'));
    printf("  toupper('z') = '%c' (expect 'Z')\n", toupper('z'));

    // Test 7: Edge case - comparing with null bytes in the middle
    printf("\nTest 7 - Null byte in middle:\n");
    char nullstr1[9] = "IMP\0A1XX";
    char nullstr2[9] = "IMP\0B1YY";
    int res7 = strncasecmp(nullstr1, nullstr2, 8);
    printf("  strncasecmp('IMP\\0A1XX', 'IMP\\0B1YY', 8) = %d %s\n", res7, res7 == 0 ? "MATCH!" : "no match");

    // Test 8: The actual Doom lump comparisons that should NOT match
    printf("\nTest 8 - Actual Doom lump comparisons:\n");
    int res8a = strncasecmp("POSSA1", "IMPXA1", 8);
    printf("  strncasecmp('POSSA1', 'IMPXA1', 8) = %d %s\n", res8a, res8a == 0 ? "MATCH (BUG!)" : "no match (correct)");

    int res8b = strncasecmp("ETTNA1", "IMPXA1", 8);
    printf("  strncasecmp('ETTNA1', 'IMPXA1', 8) = %d %s\n", res8b, res8b == 0 ? "MATCH (BUG!)" : "no match (correct)");

    int res8c = strncasecmp("AGRDA1", "IMPXA1", 8);
    printf("  strncasecmp('AGRDA1', 'IMPXA1', 8) = %d %s\n", res8c, res8c == 0 ? "MATCH (BUG!)" : "no match (correct)");

    printf("\n=== Tests complete ===\n");
    return 0;
}
