#include "retrossl_rsa.h"
#include "retrossl_inner.h"

uint32_t
br_i31_decode_mod(x, src, len, m)
    uint32_t *x;
    const void *src;
    size_t len;
    const uint32_t *m;
{
    const unsigned char *buf;
    size_t mlen, tlen;
    size_t u, v;
    uint32_t acc;
    int acc_len;
    uint32_t cc;

    if (len == 0) {
        return 0;
    }

    mlen = (m[0] + 31) >> 5;
    tlen = (len << 3);
    if (tlen > m[0]) {
        tlen = m[0];
    }
    x[0] = tlen;

    buf = src;
    u = len;
    v = 1;
    acc = 0;
    acc_len = 0;
    while (u > 0 && v <= mlen) {
        uint32_t b;

        u --;
        if ((tlen >> 3) > u) {
            b = buf[u];
        } else {
            b = 0;
        }
        acc |= (b << acc_len);
        acc_len += 8;
        if (acc_len >= 31) {
            x[v] = acc & 0x7FFFFFFF;
            v ++;
            acc_len -= 31;
            acc = b >> (8 - acc_len);
        }
    }
    if (acc_len > 0 && v <= mlen) {
        x[v] = acc;
        v ++;
    }
    while (v <= mlen) {
        x[v] = 0;
        v ++;
    }

    cc = 0;
    for (u = mlen; u > 0; u --) {
        cc = (cc >> 1) | ((x[u] - m[u] - cc) >> 31) << 31;
    }
    return (cc >> 31) ^ 1;
}
