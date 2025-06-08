/*
 * Test HMAC compatibility with OpenSSL
 * Validates that our HMAC-SHA1 and HMAC-MD5 match OpenSSL output
 */

#include <stdio.h>
#include <string.h>
#include "retrossl_mac.h"
#include "retrossl_hash.h"

static void
print_hex(const char *label, const unsigned char *data, size_t len)
{
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int
test_hmac_sha1_openssl(void)
{
    /* Test data from OpenSSL: echo -n "test data" | openssl dgst -sha1 -hmac "secret key" -hex */
    const char *key = "secret key";
    const char *data = "test data";
    const unsigned char expected[] = {
        0x63, 0xe6, 0xeb, 0x9d, 0x62, 0xee, 0x06, 0x55, 0xd1, 0xde,
        0xd4, 0x98, 0x59, 0xce, 0x33, 0xea, 0x23, 0xab, 0x76, 0xcb
    };
    
    br_hmac_key_context kc;
    br_hmac_context hc;
    unsigned char output[20];
    
    printf("=== Testing HMAC-SHA1 vs OpenSSL ===\n");
    printf("Key: \"%s\"\n", key);
    printf("Data: \"%s\"\n", data);
    
    /* Compute HMAC-SHA1 with our implementation */
    br_hmac_key_init(&kc, &br_sha1_vtable, key, strlen(key));
    br_hmac_init(&hc, &kc, 20);
    br_hmac_update(&hc, data, strlen(data));
    br_hmac_out(&hc, output);
    
    print_hex("Our HMAC-SHA1", output, 20);
    print_hex("OpenSSL HMAC-SHA1", expected, 20);
    
    if (memcmp(output, expected, 20) == 0) {
        printf("✓ HMAC-SHA1 matches OpenSSL!\n\n");
        return 1;
    } else {
        printf("✗ HMAC-SHA1 does NOT match OpenSSL!\n\n");
        return 0;
    }
}

static int
test_hmac_md5_openssl(void)
{
    /* Test data from OpenSSL: echo -n "test data" | openssl dgst -md5 -hmac "secret key" -hex */
    const char *key = "secret key";
    const char *data = "test data";
    const unsigned char expected[] = {
        0x38, 0xb9, 0xef, 0xb4, 0x01, 0x94, 0xba, 0x20, 0xbb, 0x3f,
        0x74, 0x00, 0xbf, 0x91, 0x9c, 0x34
    };
    
    br_hmac_key_context kc;
    br_hmac_context hc;
    unsigned char output[16];
    
    printf("=== Testing HMAC-MD5 vs OpenSSL ===\n");
    printf("Key: \"%s\"\n", key);
    printf("Data: \"%s\"\n", data);
    
    /* Compute HMAC-MD5 with our implementation */
    br_hmac_key_init(&kc, &br_md5_vtable, key, strlen(key));
    br_hmac_init(&hc, &kc, 16);
    br_hmac_update(&hc, data, strlen(data));
    br_hmac_out(&hc, output);
    
    print_hex("Our HMAC-MD5", output, 16);
    print_hex("OpenSSL HMAC-MD5", expected, 16);
    
    if (memcmp(output, expected, 16) == 0) {
        printf("✓ HMAC-MD5 matches OpenSSL!\n\n");
        return 1;
    } else {
        printf("✗ HMAC-MD5 does NOT match OpenSSL!\n\n");
        return 0;
    }
}

static int
test_hmac_sha1_multiple_keys(void)
{
    /* Additional test vectors */
    struct {
        const char *key;
        const char *data;
        const char *expected_hex;
    } tests[] = {
        /* echo -n "hello" | openssl dgst -sha1 -hmac "key" -hex */
        {"key", "hello", "b34ceac4516ff23a143e61d79d0fa7a4fbe5f266"},
        /* echo -n "" | openssl dgst -sha1 -hmac "test" -hex */  
        {"test", "", "fc85087452696e5bcbe3b7a71fde00e320af2cca"},
        /* echo -n "message" | openssl dgst -sha1 -hmac "longer key for testing" -hex */
        {"longer key for testing", "message", "37b9e713df8f95b6f2992f8bc041308eff6f524c"}
    };
    
    printf("=== Testing HMAC-SHA1 Multiple Test Vectors ===\n");
    
    int passed = 0;
    for (int i = 0; i < 3; i++) {
        br_hmac_key_context kc;
        br_hmac_context hc;
        unsigned char output[20];
        unsigned char expected[20];
        
        /* Convert hex string to bytes */
        for (int j = 0; j < 20; j++) {
            sscanf(tests[i].expected_hex + j*2, "%2hhx", &expected[j]);
        }
        
        /* Compute HMAC */
        br_hmac_key_init(&kc, &br_sha1_vtable, tests[i].key, strlen(tests[i].key));
        br_hmac_init(&hc, &kc, 20);
        br_hmac_update(&hc, tests[i].data, strlen(tests[i].data));
        br_hmac_out(&hc, output);
        
        printf("Test %d: Key=\"%s\", Data=\"%s\"\n", i+1, tests[i].key, tests[i].data);
        print_hex("Expected", expected, 20);
        print_hex("Our output", output, 20);
        
        if (memcmp(output, expected, 20) == 0) {
            printf("✓ Test %d passed\n\n", i+1);
            passed++;
        } else {
            printf("✗ Test %d failed\n\n", i+1);
        }
    }
    
    return (passed == 3);
}

int
main(void)
{
    int tests_passed = 0;
    int total_tests = 3;
    
    printf("RetroSSL HMAC OpenSSL Compatibility Test\n");
    printf("========================================\n\n");
    
    if (test_hmac_sha1_openssl()) tests_passed++;
    if (test_hmac_md5_openssl()) tests_passed++;  
    if (test_hmac_sha1_multiple_keys()) tests_passed++;
    
    printf("=== Test Results ===\n");
    printf("Passed: %d/%d tests\n", tests_passed, total_tests);
    
    if (tests_passed == total_tests) {
        printf("✓ All HMAC tests match OpenSSL!\n");
        return 0;
    } else {
        printf("✗ Some HMAC tests failed!\n");
        return 1;
    }
}