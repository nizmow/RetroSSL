#include "retrossl_rsa.h"
#include "retrossl_inner.h"

uint32_t
br_i31_sub(a, b, ctl)
    uint32_t *a;
    const uint32_t *b;
    uint32_t ctl;
{
    uint32_t cc;
    size_t u, m;

    cc = 0;
    m = (a[0] + 63) >> 5;
    for (u = 1; u < m; u++) {
        uint32_t aw, bw;
        uint64_t cw;

        aw = a[u];
        bw = MUX(ctl, b[u], 0);
        cw = (uint64_t)aw - (uint64_t)bw - cc;
        a[u] = (uint32_t)cw & 0x7FFFFFFF;
        cc = (uint32_t)(cw >> 63);
    }
    return cc;
}
