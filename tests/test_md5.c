/*
 * RetroSSL MD5 Test for Windows 98 SE
 * Tests MD5 hash implementation
 */

#include <stdio.h>
#include <string.h>
#include "../src/retrossl_inner.h"

int main(void) {
    br_md5_context ctx;
    unsigned char hash[16];
    const char *input = "abc";
    const char *expected = "900150983cd24fb0d6963f7d28e17f72";
    char result[33];
    int i;

    printf("RetroSSL MD5 Test\n");
    printf("=================\n");
    
    /* Initialize MD5 context */
    br_md5_init(&ctx);
    
    /* Update with input data */
    br_md5_update(&ctx, input, strlen(input));
    
    /* Get final hash */
    br_md5_out(&ctx, hash);
    
    /* Print results */
    printf("Input: \"%s\"\n", input);
    printf("MD5: ");
    for (i = 0; i < 16; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    printf("Expected: %s\n", expected);
    
    /* Verify result */
    for (i = 0; i < 16; i++) {
        sprintf(result + (i * 2), "%02x", hash[i]);
    }
    result[32] = '\0';
    
    if (strcmp(result, expected) == 0) {
        printf("✓ MD5 test PASSED!\n");
        return 0;
    } else {
        printf("✗ MD5 test FAILED!\n");
        return 1;
    }
}
