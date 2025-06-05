#include "retrossl_rsa.h"
#include "retrossl_inner.h"

#define MUL31(x, y)     ((uint64_t)(x) * (uint64_t)(y))
#define MUL31_lo(x, y)  ((uint32_t)MUL31(x, y) & 0x7FFFFFFF)

uint32_t
br_i31_muladd_small(x, z, m)
    uint32_t *x;
    uint32_t z;
    const uint32_t *m;
{
    size_t u, mlen;
    uint32_t cc, over;
    uint64_t zw;
    
    mlen = (m[0] + 31) >> 5;
    
    /* Left shift by 31 bits (multiply by 2^31) */
    cc = 0;
    for (u = 1; u <= mlen; u++) {
        zw = ((uint64_t)x[u] << 31) + cc;
        x[u] = (uint32_t)zw & 0x7FFFFFFF;
        cc = (uint32_t)(zw >> 31);
    }
    
    over = cc;
    
    /* Conditional subtract modulus if overflow */
    if (over) {
        br_i31_sub(x, m, 1);
    }
    
    return over;
}
