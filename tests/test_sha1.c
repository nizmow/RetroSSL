/*
 * Simple SHA1 test for RetroSSL Win98 port
 */

#include <stdio.h>
#include <string.h>
#include "../src/retrossl_inner.h"

int main() {
    /* Test data: "abc" should produce SHA1: a9993e364706816aba3e25717850c26c9cd0d89d */
    const char *test_data = "abc";
    unsigned char hash_output[20];
    br_sha1_context ctx;
    int i;
    
    printf("RetroSSL SHA1 Test\n");
    printf("==================\n");
    printf("Input: \"%s\"\n", test_data);
    
    /* Initialize SHA1 context */
    br_sha1_init(&ctx);
    
    /* Add test data */
    br_sha1_update(&ctx, test_data, strlen(test_data));
    
    /* Get the hash */
    br_sha1_out(&ctx, hash_output);
    
    /* Print result */
    printf("SHA1: ");
    for (i = 0; i < 20; i++) {
        printf("%02x", hash_output[i]);
    }
    printf("\n");
    
    /* Expected: a9993e364706816aba3e25717850c26c9cd0d89d */
    printf("Expected: a9993e364706816aba3e25717850c26c9cd0d89d\n");
    
    return 0;
}
