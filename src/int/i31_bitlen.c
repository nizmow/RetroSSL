#include "retrossl_rsa.h"
#include "retrossl_inner.h"

static uint32_t
bit_length_u32(v)
    uint32_t v;
{
    uint32_t k;

    if (v == 0) return 0;
    k = 31;
    if (v < 0x10000) { k -= 16; v <<= 16; }
    if (v < 0x1000000) { k -= 8; v <<= 8; }
    if (v < 0x10000000) { k -= 4; v <<= 4; }
    if (v < 0x40000000) { k -= 2; v <<= 2; }
    if (v < 0x80000000) { k -= 1; }
    return k;
}

uint32_t
br_i31_bit_length(x, xlen)
    const uint32_t *x;
    size_t xlen;
{
    uint32_t tw, twk;
    size_t u;

    tw = 0;
    twk = 0;
    for (u = xlen; u > 0; u --) {
        uint32_t w, c;

        c = EQ(tw, 0);
        w = x[u - 1];
        tw = MUX(c, w, tw);
        twk = MUX(c, (uint32_t)(u - 1), twk);
    }

    return (twk << 5) + bit_length_u32(tw);
}
