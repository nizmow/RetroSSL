/*
 * RetroSSL codec functions for Windows 98 SE
 * Based on BearSSL codec implementation
 */

#include "retrossl_inner.h"

/* see retrossl_inner.h */
void br_range_dec32be(uint32_t *v, size_t num, const void *src) {
    const unsigned char *buf = (const unsigned char *)src;
    
    while (num-- > 0) {
        *v++ = br_dec32be(buf);
        buf += 4;
    }
}

/* see retrossl_inner.h */
void br_range_enc32be(void *dst, const uint32_t *v, size_t num) {
    unsigned char *buf = (unsigned char *)dst;
    
    while (num-- > 0) {
        br_enc32be(buf, *v++);
        buf += 4;
    }
}

/* see retrossl_inner.h */
void br_range_dec32le(uint32_t *v, size_t num, const void *src) {
    const unsigned char *buf = (const unsigned char *)src;
    
    while (num-- > 0) {
        *v++ = br_dec32le(buf);
        buf += 4;
    }
}

/* see retrossl_inner.h */
void br_range_enc32le(void *dst, const uint32_t *v, size_t num) {
    unsigned char *buf = (unsigned char *)dst;
    
    while (num-- > 0) {
        br_enc32le(buf, *v++);
        buf += 4;
    }
}

/* see retrossl_inner.h */
void
br_ccopy(uint32_t ctl, void *dst, const void *src, size_t len)
{
	unsigned char *d;
	const unsigned char *s;

	d = dst;
	s = src;
	while (len -- > 0) {
		uint32_t x, y;

		x = *s ++;
		y = *d;
		*d = y ^ (-ctl & (x ^ y));  /* Inline MUX implementation */
		d ++;
	}
}
