#include "retrossl_rsa.h"
#include "retrossl_inner.h"

uint32_t
br_i31_ninv31(x)
    uint32_t x;
{
    uint32_t y;

    y = 2 - x;
    y *= 2 - y * x;
    y *= 2 - y * x;
    y *= 2 - y * x;
    y *= 2 - y * x;
    return MUX(x & 1, (uint32_t)0 - y, 0) & 0x7FFFFFFF;
}
