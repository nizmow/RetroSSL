/*
 * HMAC test for RetroSSL Win98 port
 */

#include <stdio.h>
#include <string.h>
#include "../include/retrossl_hmac.h"

int main() {
    /* RFC 2202 Test Case 1:
     * key = 0x0b (20 times)
     * data = "Hi There"
     * HMAC-SHA1 = b617318655057264e28bc0b6fb378c8ef146be00
     */
    unsigned char key1[20];
    const char *data1 = "Hi There";
    unsigned char hmac_output[64];
    br_hmac_key_context kc;
    br_hmac_context ctx;
    size_t len;
    int i;
    
    printf("RetroSSL HMAC Test\n");
    printf("==================\n");
    
    /* Test 1: HMAC-SHA1 with short key */
    printf("Test 1: HMAC-SHA1 with short key\n");
    memset(key1, 0x0b, sizeof key1);
    
    br_hmac_key_init(&kc, &br_sha1_vtable, key1, sizeof key1);
    br_hmac_init(&ctx, &kc, 0);
    br_hmac_update(&ctx, data1, strlen(data1));
    len = br_hmac_out(&ctx, hmac_output);
    
    printf("Key: ");
    for (i = 0; i < 20; i++) {
        printf("%02x", key1[i]);
    }
    printf("\n");
    printf("Data: \"%s\"\n", data1);
    printf("HMAC-SHA1 (%zu bytes): ", len);
    for (i = 0; i < (int)len; i++) {
        printf("%02x", hmac_output[i]);
    }
    printf("\n");
    printf("Expected:               b617318655057264e28bc0b6fb378c8ef146be00\n");
    
    /* Test 2: HMAC-SHA256 with same key/data */
    printf("\nTest 2: HMAC-SHA256 with same key/data\n");
    br_hmac_key_init(&kc, &br_sha256_vtable, key1, sizeof key1);
    br_hmac_init(&ctx, &kc, 0);
    br_hmac_update(&ctx, data1, strlen(data1));
    len = br_hmac_out(&ctx, hmac_output);
    
    printf("HMAC-SHA256 (%zu bytes): ", len);
    for (i = 0; i < (int)len; i++) {
        printf("%02x", hmac_output[i]);
    }
    printf("\n");
    printf("Expected:                 b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7\n");
    
    /* Test 3: Empty data */
    printf("\nTest 3: HMAC-SHA256 with empty data\n");
    br_hmac_key_init(&kc, &br_sha256_vtable, key1, sizeof key1);
    br_hmac_init(&ctx, &kc, 0);
    br_hmac_update(&ctx, "", 0);
    len = br_hmac_out(&ctx, hmac_output);
    
    printf("HMAC-SHA256 (empty): ");
    for (i = 0; i < (int)len; i++) {
        printf("%02x", hmac_output[i]);
    }
    printf("\n");
    
    return 0;
}