#ifndef RETROSSL_INNER_H__
#define RETROSSL_INNER_H__

#include <stdint.h>
#include <string.h>

/* BearSSL constant-time macros */
static inline uint32_t
NOT(uint32_t ctl)
{
	return ctl ^ 1;
}

static inline uint32_t
MUX(uint32_t ctl, uint32_t x, uint32_t y)
{
	return y ^ (-ctl & (x ^ y));
}

static inline uint32_t
EQ(uint32_t x, uint32_t y)
{
	uint32_t q;

	q = x ^ y;
	return NOT((q | -q) >> 31);
}

static inline uint32_t
NEQ(uint32_t x, uint32_t y)
{
	uint32_t q;

	q = x ^ y;
	return (q | -q) >> 31;
}

static inline uint32_t
GT(uint32_t x, uint32_t y)
{
	uint32_t z;

	z = y - x;
	return (z ^ ((x ^ y) & (x ^ z))) >> 31;
}

#define GE(x, y)   NOT(GT(y, x))
#define LT(x, y)   GT(y, x)
#define LE(x, y)   NOT(GT(x, y))

/* BearSSL multiplication macros */
#define MUL31(x, y)     ((uint64_t)(x) * (uint64_t)(y))
#define MUL31_lo(x, y)  (((uint32_t)(x) * (uint32_t)(y)) & (uint32_t)0x7FFFFFFF)

/* Forward declarations for i31 functions */
void br_i31_zero(uint32_t *x, uint32_t bit_len);
uint32_t br_i31_sub(uint32_t *a, const uint32_t *b, uint32_t ctl);
uint32_t br_i31_add(uint32_t *a, const uint32_t *b, uint32_t ctl);
void br_i31_muladd_small(uint32_t *x, uint32_t z, const uint32_t *m);

/* Constant-time conditional copy */
void br_ccopy(uint32_t ctl, void *dst, const void *src, size_t len);

/* BearSSL division function */
static inline uint32_t
br_div(uint32_t hi, uint32_t lo, uint32_t d)
{
	/* Simple 64-bit division */
	uint64_t n = ((uint64_t)hi << 32) | lo;
	return (uint32_t)(n / d);
}

/* BearSSL remainder function */
static inline uint32_t
br_rem(uint32_t hi, uint32_t lo, uint32_t d)
{
	/* Simple 64-bit remainder */
	uint64_t n = ((uint64_t)hi << 32) | lo;
	return (uint32_t)(n % d);
}

#endif
