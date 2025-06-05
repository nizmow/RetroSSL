#include "retrossl_rsa.h"

void
br_i31_encode(dst, len, x)
    void *dst;
    size_t len;
    const uint32_t *x;
{
    unsigned char *buf;
    size_t k, xlen;
    uint32_t acc;
    int acc_len;

    buf = dst;
    xlen = (x[0] + 31) >> 5;
    acc = 0;
    acc_len = 0;
    k = len;
    while (k > 0) {
        uint32_t w;

        if (acc_len < 8) {
            if (xlen > 0) {
                xlen --;
                w = x[1 + xlen];
            } else {
                w = 0;
            }
            acc |= w << acc_len;
            acc_len += 31;
        }
        k --;
        buf[k] = (unsigned char)acc;
        acc >>= 8;
        acc_len -= 8;
    }
}
