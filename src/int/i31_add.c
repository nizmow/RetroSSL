#include "retrossl_rsa.h"
#include "retrossl_inner.h"

/* see inner.h */
uint32_t
br_i31_add(uint32_t *a, const uint32_t *b, uint32_t ctl)
{
	uint32_t cc;
	size_t u, m;

	cc = 0;
	m = (a[0] + 63) >> 5;
	for (u = 1; u < m; u ++) {
		uint32_t aw, bw, naw;

		aw = a[u];
		bw = b[u];
		naw = aw + bw + cc;
		cc = naw >> 31;
		a[u] = MUX(ctl, naw & (uint32_t)0x7FFFFFFF, aw);
	}
	return cc;
}