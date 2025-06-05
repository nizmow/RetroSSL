/*
 * RetroSSL AES Test Program
 * Tests AES-128 CBC encryption and decryption with known test vectors
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/retrossl_block.h"
#include "../src/retrossl_inner.h"

/* Test vectors for AES-128 CBC */
static const unsigned char test_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const unsigned char test_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char test_plaintext[32] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};

static const unsigned char expected_ciphertext[32] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
};

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int test_aes_cbc(void)
{
    retrossl_aes_small_cbcenc_keys enc_ctx;
    retrossl_aes_small_cbcdec_keys dec_ctx;
    unsigned char buffer[32];
    unsigned char iv_enc[16], iv_dec[16];
    
    printf("=== AES-128 CBC Test ===\n");
    
    /* Test data */
    print_hex("Key", test_key, 16);
    print_hex("IV", test_iv, 16);
    print_hex("Plaintext", test_plaintext, 32);
    print_hex("Expected", expected_ciphertext, 32);
    
    /* Initialize encryption context */
    retrossl_aes_small_cbcenc_init(&enc_ctx, test_key, 16);
    printf("Encryption context initialized (rounds: %u)\n", enc_ctx.num_rounds);
    
    /* Prepare encryption */
    memcpy(buffer, test_plaintext, 32);
    memcpy(iv_enc, test_iv, 16);
    
    /* Encrypt */
    retrossl_aes_small_cbcenc_run(&enc_ctx, iv_enc, buffer, 32);
    print_hex("Encrypted", buffer, 32);
    
    /* Verify encryption result */
    if (memcmp(buffer, expected_ciphertext, 32) == 0) {
        printf("✓ Encryption test PASSED\n");
    } else {
        printf("✗ Encryption test FAILED\n");
        return 0;
    }
    
    /* Initialize decryption context */
    retrossl_aes_small_cbcdec_init(&dec_ctx, test_key, 16);
    printf("Decryption context initialized (rounds: %u)\n", dec_ctx.num_rounds);
    
    /* Prepare decryption (buffer already contains ciphertext) */
    memcpy(iv_dec, test_iv, 16);
    
    /* Decrypt */
    retrossl_aes_small_cbcdec_run(&dec_ctx, iv_dec, buffer, 32);
    print_hex("Decrypted", buffer, 32);
    
    /* Verify decryption result */
    if (memcmp(buffer, test_plaintext, 32) == 0) {
        printf("✓ Decryption test PASSED\n");
        return 1;
    } else {
        printf("✗ Decryption test FAILED\n");
        return 0;
    }
}

static int test_aes_key_schedule(void)
{
    uint32_t skey[44]; /* Enough for AES-128 (44 words) */
    unsigned rounds;
    size_t i;
    
    printf("\n=== AES Key Schedule Test ===\n");
    
    rounds = retrossl_aes_keysched(skey, test_key, 16);
    printf("Generated %u rounds for AES-128\n", rounds);
    
    if (rounds != 10) {
        printf("✗ Expected 10 rounds for AES-128, got %u\n", rounds);
        return 0;
    }
    
    printf("Round keys (first 8 words):\n");
    for (i = 0; i < 8 && i < (rounds + 1) * 4; i++) {
        printf("  skey[%u] = 0x%08lx\n", (unsigned)i, (unsigned long)skey[i]);
    }
    
    printf("✓ Key schedule test PASSED\n");
    return 1;
}

int main(void)
{
    int pass = 0;
    
    printf("RetroSSL AES Test Suite\n");
    printf("=======================\n\n");
    
    if (test_aes_key_schedule()) {
        pass++;
    }
    
    if (test_aes_cbc()) {
        pass++;
    }
    
    printf("\n=== Results ===\n");
    printf("Tests passed: %d/2\n", pass);
    
    if (pass == 2) {
        printf("✓ All AES tests PASSED!\n");
        return 0;
    } else {
        printf("✗ Some AES tests FAILED!\n");
        return 1;
    }
}
