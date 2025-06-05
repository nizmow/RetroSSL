#include <stdio.h>
#include <string.h>
#include "retrossl_rsa.h"

void hexdump_line(const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main()
{
    printf("RetroSSL RSA Test\n");
    printf("=================\n\n");

    printf("Testing basic i31 decode/encode functions...\n");

    {
        unsigned char data[4] = {0x01, 0x23, 0x45, 0x67};
        uint32_t x[10];
        unsigned char result[4];
        
        printf("Input: ");
        hexdump_line(data, 4);
        
        br_i31_decode(x, data, 4);
        printf("Decoded x[0] (bit length): %lu\n", (unsigned long)x[0]);
        printf("Decoded x[1]: 0x%08lX\n", (unsigned long)x[1]);
        
        br_i31_encode(result, 4, x);
        printf("Re-encoded: ");
        hexdump_line(result, 4);
        
        if (memcmp(data, result, 4) == 0) {
            printf("PASS: Round-trip encode/decode successful\n");
        } else {
            printf("FAIL: Round-trip encode/decode failed\n");
        }
    }

    printf("\nTesting bit length function...\n");
    {
        uint32_t x[3] = {32, 0x12345678, 0x00000000};
        uint32_t len = br_i31_bit_length(x + 1, 1);
        printf("Bit length of 0x12345678: %lu\n", (unsigned long)len);
    }

    printf("\nTesting ninv31 function...\n");
    {
        uint32_t x = 0x12345679;  /* odd number */
        uint32_t inv = br_i31_ninv31(x);
        printf("ninv31(0x%08lX) = 0x%08lX\n", (unsigned long)x, (unsigned long)inv);
    }

    printf("\nTesting Montgomery arithmetic...\n");
    {
        /* Simple test: compute 3^5 mod 7 = 5 */
        uint32_t base[3] = {32, 3, 0};      /* base = 3 */
        uint32_t mod[3] = {32, 7, 0};       /* modulus = 7 */
        unsigned char exp[1] = {5};          /* exponent = 5 */
        uint32_t tmp[20];                    /* temporary space */
        uint32_t m0i;
        uint32_t result;
        
        m0i = br_i31_ninv31(7);
        printf("Computing 3^5 mod 7...\n");
        printf("m0i = 0x%08lX\n", (unsigned long)m0i);
        
        if (br_i31_modpow_opt(base, exp, 1, mod, m0i, tmp, 20)) {
            result = base[1];
            printf("Result: %lu (expected: 5)\n", (unsigned long)result);
            if (result == 5) {
                printf("PASS: Modular exponentiation test\n");
            } else {
                printf("FAIL: Modular exponentiation test\n");
            }
        } else {
            printf("FAIL: Modular exponentiation failed\n");
        }
    }

    printf("\nRSA i31 functions test completed.\n");
    return 0;
}
