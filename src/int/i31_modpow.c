#include "retrossl_rsa.h"
#include "retrossl_inner.h"

void
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
br_ccopy(ctl, dst, src, len)
    uint32_t ctl;
    void *dst;
    const void *src;
    size_t len;
{
    size_t u;
    unsigned char *d;
    const unsigned char *s;
    uint32_t mask;
    
    d = dst;
    s = src;
    mask = (uint32_t)0 - ctl;
    for (u = 0; u < len; u++) {
        d[u] ^= mask & (d[u] ^ s[u]);
    }
}

uint32_t
br_i31_modpow_opt(x, e, elen, m, m0i, tmp, twlen)
    uint32_t *x;
    const unsigned char *e;
    size_t elen;
    const uint32_t *m;
    uint32_t m0i;
    uint32_t *tmp;
    size_t twlen;
{
    size_t mlen;
    uint32_t *t1, *t2;
    
    if (elen == 0) {
        br_i31_zero(x, m[0]);
        x[1] = 1;
        return 1;
    }
    
    mlen = (m[0] + 31) >> 5;
    if (twlen < 2 * (mlen + 1)) {
        return 0;
    }
    
    t1 = tmp;
    t2 = tmp + mlen + 1;
    
    /* Initialize result to 1 */
    br_i31_zero(t1, m[0]);
    t1[1] = 1;
    
    /* Convert base to Montgomery domain */
    br_i31_to_monty(x, m);
    
    /* Convert result to Montgomery domain */
    br_i31_to_monty(t1, m);
    
    /* Square-and-multiply */
    {
        size_t k;
        int first_bit = 1;
        
        for (k = 0; k < elen; k++) {
            unsigned char eb;
            int i;
            
            eb = e[k];
            for (i = 7; i >= 0; i--) {
                uint32_t ctl;
                
                ctl = (eb >> i) & 1;
                
                /* Skip leading zeros */
                if (first_bit) {
                    if (ctl == 0) {
                        continue;
                    }
                    first_bit = 0;
                    /* First bit is 1, so result = base */
                    br_ccopy(1, t1, x, (mlen + 1) * sizeof(uint32_t));
                    continue;
                }
                
                /* Square result */
                br_i31_montymul(t2, t1, t1, m, m0i);
                br_ccopy(1, t1, t2, (mlen + 1) * sizeof(uint32_t));
                
                /* Multiply by base if bit is set */
                if (ctl) {
                    br_i31_montymul(t2, t1, x, m, m0i);
                    br_ccopy(1, t1, t2, (mlen + 1) * sizeof(uint32_t));
                }
            }
        }
    }
    
    /* Convert result back from Montgomery domain */
    br_i31_from_monty(t1, m, m0i);
    
    /* Copy result to x */
    br_ccopy(1, x, t1, (mlen + 1) * sizeof(uint32_t));
    
    return 1;
}
