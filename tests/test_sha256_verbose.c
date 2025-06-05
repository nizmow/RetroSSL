/*
 * Verbose SHA256 test for RetroSSL Win98 port
 */

#include <stdio.h>
#include <string.h>
#include "../include/retrossl_hash.h"

int main() {
    const char *test_data = "abc";
    unsigned char hash_output[32];
    br_sha256_context ctx;
    int i;
    
    printf("RetroSSL SHA256 Verbose Test\n");
    printf("============================\n");
    printf("Testing with minimal input to debug step by step\n");
    
    /* Test empty string first */
    printf("\nTest 1: Empty string\n");
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, "", 0);
    br_sha256_out(&ctx, hash_output);
    
    printf("Hash (empty): ");
    for (i = 0; i < 32; i++) {
        printf("%02x", hash_output[i]);
    }
    printf("\n");
    printf("Expected:     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n");
    
    /* Test single byte */
    printf("\nTest 2: Single byte 'a'\n");
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, "a", 1);
    br_sha256_out(&ctx, hash_output);
    
    printf("Hash ('a'): ");
    for (i = 0; i < 32; i++) {
        printf("%02x", hash_output[i]);
    }
    printf("\n");
    printf("Expected:   ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\n");
    
    /* Test "abc" */
    printf("\nTest 3: String 'abc'\n");
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, test_data, strlen(test_data));
    br_sha256_out(&ctx, hash_output);
    
    printf("Hash ('abc'): ");
    for (i = 0; i < 32; i++) {
        printf("%02x", hash_output[i]);
    }
    printf("\n");
    printf("Expected:     ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n");
    
    return 0;
}