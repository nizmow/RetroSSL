#include "retrossl_rsa.h"
#include "retrossl_inner.h"

#define MUL31(x, y)     ((uint64_t)(x) * (uint64_t)(y))
#define MUL31_lo(x, y)  ((uint32_t)MUL31(x, y) & 0x7FFFFFFF)

void
br_i31_montymul(d, x, y, m, m0i)
    uint32_t *d;
    const uint32_t *x;
    const uint32_t *y;
    const uint32_t *m;
    uint32_t m0i;
{
    size_t len, len4, u, v;
    uint64_t dh;

    len = (m[0] + 31) >> 5;
    len4 = len & ~(size_t)3;
    
    br_i31_zero(d, m[0]);
    dh = 0;
    
    for (u = 0; u < len; u++) {
        uint32_t f, xu;
        uint64_t r, zh;
        
        xu = x[u + 1];
        f = MUL31_lo((d[1] + MUL31_lo(xu, y[1])), m0i);
        
        r = 0;
        for (v = 0; v < len4; v += 4) {
            uint64_t z;
            
            z = (uint64_t)d[v + 1] + MUL31(xu, y[v + 1]) + MUL31(f, m[v + 1]) + r;
            r = z >> 31;
            d[v + 1] = (uint32_t)z & 0x7FFFFFFF;
            
            z = (uint64_t)d[v + 2] + MUL31(xu, y[v + 2]) + MUL31(f, m[v + 2]) + r;
            r = z >> 31;
            d[v + 2] = (uint32_t)z & 0x7FFFFFFF;
            
            z = (uint64_t)d[v + 3] + MUL31(xu, y[v + 3]) + MUL31(f, m[v + 3]) + r;
            r = z >> 31;
            d[v + 3] = (uint32_t)z & 0x7FFFFFFF;
            
            z = (uint64_t)d[v + 4] + MUL31(xu, y[v + 4]) + MUL31(f, m[v + 4]) + r;
            r = z >> 31;
            d[v + 4] = (uint32_t)z & 0x7FFFFFFF;
        }
        
        for (; v < len; v++) {
            uint64_t z;
            
            z = (uint64_t)d[v + 1] + MUL31(xu, y[v + 1]) + MUL31(f, m[v + 1]) + r;
            r = z >> 31;
            d[v + 1] = (uint32_t)z & 0x7FFFFFFF;
        }
        
        zh = dh + r;
        d[len + 1] = (uint32_t)zh & 0x7FFFFFFF;
        dh = zh >> 31;
        
        for (v = 1; v <= len; v++) {
            d[v] = d[v + 1];
        }
        d[len + 1] = (uint32_t)dh;
        dh >>= 31;
    }
    
    br_i31_sub(d, m, EQ((uint32_t)dh, 0) ^ 1);
} src/int/i31_tmont.c src/int/i31_fmont.c src/int/i31_sub.c src/int/i31_add.c src/int/i31_muladd.c

