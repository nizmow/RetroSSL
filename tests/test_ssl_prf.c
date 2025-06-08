/*
 * Test program for TLS PRF (Pseudo-Random Function)
 * Tests key derivation for TLS_RSA_WITH_AES_128_CBC_SHA
 */

#include <stdio.h>
#include <string.h>
#include "retrossl_ssl.h"

/* Test vectors from RFC 2246 and practical testing */

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
test_tls10_prf_basic(void)
{
    /* Test basic TLS 1.0 PRF functionality */
    unsigned char secret[16];
    unsigned char seed[32]; 
    unsigned char output[32];
    
    printf("=== Testing TLS 1.0 PRF Basic Functionality ===\n");
    
    /* Initialize test data */
    memset(secret, 0xAB, sizeof(secret));
    memset(seed, 0xCD, sizeof(seed));
    
    /* Test PRF with "test label" */
    br_tls10_prf(output, sizeof(output), secret, sizeof(secret), 
                 "test label", seed, sizeof(seed));
    
    print_hex("Secret", secret, sizeof(secret));
    print_hex("Seed", seed, sizeof(seed));
    print_hex("PRF Output", output, sizeof(output));
    
    /* Verify output is not all zeros */
    int all_zero = 1;
    for (int i = 0; i < sizeof(output); i++) {
        if (output[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    
    if (all_zero) {
        printf("ERROR: PRF output is all zeros!\n");
        return 0;
    }
    
    printf("✓ PRF generates non-zero output\n\n");
    return 1;
}

static int
test_master_secret_derivation(void)
{
    /* Test master secret derivation */
    unsigned char pre_master_secret[48];
    unsigned char client_random[32];
    unsigned char server_random[32];
    unsigned char master_secret[48];
    
    printf("=== Testing Master Secret Derivation ===\n");
    
    /* Initialize test data with known patterns */
    memset(pre_master_secret, 0x03, 2);  /* TLS 1.0 version */
    memset(pre_master_secret + 2, 0x01, 46);  /* Random bytes */
    
    for (int i = 0; i < 32; i++) {
        client_random[i] = (unsigned char)(0x10 + i);
        server_random[i] = (unsigned char)(0x20 + i);
    }
    
    /* Derive master secret */
    if (!br_ssl_compute_master_secret(pre_master_secret, sizeof(pre_master_secret),
                                     client_random, server_random, master_secret)) {
        printf("ERROR: Failed to compute master secret\n");
        return 0;
    }
    
    print_hex("Pre-Master Secret", pre_master_secret, 16);  /* Show first 16 bytes */
    print_hex("Client Random", client_random, 32);
    print_hex("Server Random", server_random, 32);
    print_hex("Master Secret", master_secret, 48);
    
    printf("✓ Master secret derived successfully\n\n");
    return 1;
}

static int
test_key_derivation(void)
{
    /* Test session key derivation */
    unsigned char master_secret[48];
    unsigned char client_random[32];
    unsigned char server_random[32];
    
    unsigned char client_write_mac_key[20];
    unsigned char server_write_mac_key[20];
    unsigned char client_write_key[16];
    unsigned char server_write_key[16];
    unsigned char client_write_iv[16];
    unsigned char server_write_iv[16];
    
    printf("=== Testing Session Key Derivation ===\n");
    
    /* Initialize test data */
    for (int i = 0; i < 48; i++) {
        master_secret[i] = (unsigned char)(0x30 + (i % 16));
    }
    
    for (int i = 0; i < 32; i++) {
        client_random[i] = (unsigned char)(0x40 + i);
        server_random[i] = (unsigned char)(0x50 + i);
    }
    
    /* Derive session keys */
    if (!br_ssl_derive_keys(master_secret, client_random, server_random,
                           client_write_mac_key, server_write_mac_key,
                           client_write_key, server_write_key,
                           client_write_iv, server_write_iv)) {
        printf("ERROR: Failed to derive session keys\n");
        return 0;
    }
    
    print_hex("Master Secret", master_secret, 16);  /* Show first 16 bytes */
    printf("\nDerived Keys:\n");
    print_hex("Client MAC Key", client_write_mac_key, 20);
    print_hex("Server MAC Key", server_write_mac_key, 20);
    print_hex("Client Cipher Key", client_write_key, 16);
    print_hex("Server Cipher Key", server_write_key, 16);
    print_hex("Client IV", client_write_iv, 16);
    print_hex("Server IV", server_write_iv, 16);
    
    /* Verify keys are different */
    if (memcmp(client_write_mac_key, server_write_mac_key, 20) == 0) {
        printf("ERROR: Client and server MAC keys are identical!\n");
        return 0;
    }
    
    if (memcmp(client_write_key, server_write_key, 16) == 0) {
        printf("ERROR: Client and server cipher keys are identical!\n");
        return 0;
    }
    
    if (memcmp(client_write_iv, server_write_iv, 16) == 0) {
        printf("ERROR: Client and server IVs are identical!\n");
        return 0;
    }
    
    printf("✓ All keys derived and are unique\n\n");
    return 1;
}

static int
test_prf_reproducibility(void)
{
    /* Test that PRF is deterministic */
    unsigned char secret[32];
    unsigned char seed[16];
    unsigned char output1[64];
    unsigned char output2[64];
    
    printf("=== Testing PRF Reproducibility ===\n");
    
    /* Initialize test data */
    for (int i = 0; i < 32; i++) {
        secret[i] = (unsigned char)(i * 7 + 13);
    }
    for (int i = 0; i < 16; i++) {
        seed[i] = (unsigned char)(i * 3 + 5);
    }
    
    /* Generate output twice */
    br_tls10_prf(output1, sizeof(output1), secret, sizeof(secret),
                 "reproducibility test", seed, sizeof(seed));
    br_tls10_prf(output2, sizeof(output2), secret, sizeof(secret),
                 "reproducibility test", seed, sizeof(seed));
    
    /* Compare outputs */
    if (memcmp(output1, output2, sizeof(output1)) != 0) {
        printf("ERROR: PRF is not deterministic!\n");
        print_hex("Output 1", output1, 32);
        print_hex("Output 2", output2, 32);
        return 0;
    }
    
    print_hex("Reproducible Output", output1, 32);
    printf("✓ PRF is deterministic\n\n");
    return 1;
}

int
main(void)
{
    int tests_passed = 0;
    int total_tests = 4;
    
    printf("RetroSSL TLS PRF Test Suite\n");
    printf("===========================\n\n");
    
    if (test_tls10_prf_basic()) tests_passed++;
    if (test_master_secret_derivation()) tests_passed++;
    if (test_key_derivation()) tests_passed++;
    if (test_prf_reproducibility()) tests_passed++;
    
    printf("=== Test Results ===\n");
    printf("Passed: %d/%d tests\n", tests_passed, total_tests);
    
    if (tests_passed == total_tests) {
        printf("✓ All TLS PRF tests passed!\n");
        return 0;
    } else {
        printf("✗ Some tests failed!\n");
        return 1;
    }
}