#include "retrossl_rsa.h"
#include "retrossl_inner.h"

#define MUL31_lo(x, y)  ((uint32_t)((uint64_t)(x) * (uint64_t)(y)) & 0x7FFFFFFF)

void
br_i31_from_monty(x, m, m0i)
    uint32_t *x;
    const uint32_t *m;
    uint32_t m0i;
{
    size_t len, u, v;
    
    len = (m[0] + 31) >> 5;
    for (u = 0; u < len; u++) {
        uint32_t f;
        uint64_t cc;
        
        f = MUL31_lo(x[1], m0i);
        cc = 0;
        for (v = 0; v < len; v++) {
            uint64_t z;
            
            z = (uint64_t)x[v + 1] + (uint64_t)f * (uint64_t)m[v + 1] + cc;
            cc = z >> 31;
            if (v != 0) {
                x[v] = (uint32_t)z & 0x7FFFFFFF;
            }
        }
        x[len] = (uint32_t)cc;
        for (v = 1; v <= len; v++) {
            x[v] = x[v + 1];
        }
    }
    
    br_i31_sub(x, m, EQ(x[len], 0) ^ 1);
}
