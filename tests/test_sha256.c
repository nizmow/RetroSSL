/*
 * Simple SHA256 test for RetroSSL Win98 port
 */

#include <stdio.h>
#include <string.h>
#include "../include/retrossl_hash.h"

int main() {
    /* Test data: "abc" should produce SHA256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    const char *test_data = "abc";
    unsigned char hash_output[32];
    br_sha256_context ctx;
    int i;
    
    printf("RetroSSL SHA256 Test\n");
    printf("===================\n");
    printf("Input: \"%s\"\n", test_data);
    
    /* Initialize SHA256 context */
    br_sha256_init(&ctx);
    
    /* Add test data */
    br_sha256_update(&ctx, test_data, strlen(test_data));
    
    /* Get the hash */
    br_sha256_out(&ctx, hash_output);
    
    /* Print result */
    printf("SHA256: ");
    for (i = 0; i < 32; i++) {
        printf("%02x", hash_output[i]);
    }
    printf("\n");
    
    /* Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    printf("Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n");
    
    return 0;
}
