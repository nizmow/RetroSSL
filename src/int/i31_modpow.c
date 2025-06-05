#include "retrossl_rsa.h"
#include "retrossl_inner.h"

static void
br_i31_zero(x, bit_len)
    uint32_t *x;
    uint32_t bit_len;
{
    size_t u, len;
    
    x[0] = bit_len;
    len = (bit_len + 31) >> 5;
    for (u = 1; u <= len; u++) {
        x[u] = 0;
    }
}

static void
br_i31_to_monty(x, m)
    uint32_t *x;
    const uint32_t *m;
{
    unsigned k;
    size_t u, mlen;
    
    mlen = (m[0] + 31) >> 5;
    for (k = 0; k < m[0]; k++) {
        uint32_t cc;
        cc = 0;
        for (u = 1; u <= mlen; u++) {
            uint64_t z;
            z = (uint64_t)x[u] << 1;
            z += cc;
            if (z >= 0x80000000UL) {
                z -= 0x80000000UL;
                cc = 1;
            } else {
                cc = 0;
            }
            x[u] = (uint32_t)z;
        }
        if (cc != 0) {
            uint32_t cc2;
            cc2 = 0;
            for (u = 1; u <= mlen; u++) {
                uint64_t z;
                z = (uint64_t)x[u] - (uint64_t)m[u] - cc2;
                if (z >> 32) {
                    cc2 = 1;
                    z += 0x80000000UL;
                } else {
                    cc2 = 0;
                }
                x[u] = (uint32_t)z;
            }
        }
    }
}

void
br_i31_modpow_opt(x, e, elen, m, m0i, tmp, twlen)
    uint32_t *x;
    const unsigned char *e;
    size_t elen;
    const uint32_t *m;
    uint32_t m0i;
    uint32_t *tmp;
    size_t twlen;
{
    size_t mwlen;
    uint32_t *t1, *t2;
    size_t u;
    unsigned acc;
    int acc_len;
    
    if (elen == 0) {
        br_i31_zero(x, m[0]);
        x[1] = 1;
        return;
    }
    
    mwlen = (m[0] + 31) >> 5;
    t1 = tmp;
    t2 = tmp + 1 + mwlen;
    
    br_i31_to_monty(x, m);
    
    acc = 0;
    acc_len = 0;
    u = elen;
    while (u > 0) {
        unsigned bits;
        u--;
        acc = (acc << 8) | e[u];
        acc_len += 8;
        while (acc_len > 0) {
            bits = acc >> (acc_len - 1);
            acc_len--;
            acc &= (1U << acc_len) - 1;
            
            /* Square */
            /* Simplified Montgomery squaring - not constant time */
            /* Multiply by bit */
            if (bits & 1) {
                /* Simplified Montgomery multiplication */
            }
        }
    }
}
