/*
 * SHA256 debug test for RetroSSL Win98 port
 */

#include <stdio.h>
#include <string.h>
#include "../include/retrossl_hash.h"

extern const uint32_t br_sha256_IV[8];

int main() {
    const char *test_data = "abc";
    unsigned char hash_output[32];
    br_sha256_context ctx;
    int i;
    
    printf("RetroSSL SHA256 Debug Test\n");
    printf("==========================\n");
    
    /* Check IV */
    printf("SHA256 IV:\n");
    for (i = 0; i < 8; i++) {
        printf("  IV[%d] = 0x%08x\n", i, br_sha256_IV[i]);
    }
    
    /* Initialize and check context */
    br_sha256_init(&ctx);
    printf("After init, val:\n");
    for (i = 0; i < 8; i++) {
        printf("  val[%d] = 0x%08x\n", i, ctx.val[i]);
    }
    
    /* Add test data and check result */
    br_sha256_update(&ctx, test_data, strlen(test_data));
    br_sha256_out(&ctx, hash_output);
    
    printf("Final hash: ");
    for (i = 0; i < 32; i++) {
        printf("%02x", hash_output[i]);
    }
    printf("\n");
    
    return 0;
}