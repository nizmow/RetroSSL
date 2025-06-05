#ifndef RETROSSL_RSA_H__
#define RETROSSL_RSA_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_MAX_RSA_SIZE   4096
#define BR_MIN_RSA_SIZE   512

typedef struct {
    unsigned char *n;
    size_t nlen;
    unsigned char *e;
    size_t elen;
} br_rsa_public_key;

typedef struct {
    uint32_t n_bitlen;
    unsigned char *p;
    size_t plen;
    unsigned char *q;
    size_t qlen;
    unsigned char *dp;
    size_t dplen;
    unsigned char *dq;
    size_t dqlen;
    unsigned char *iq;
    size_t iqlen;
} br_rsa_private_key;

typedef uint32_t (*br_rsa_public)(unsigned char *x, size_t xlen,
    const br_rsa_public_key *pk);

uint32_t br_rsa_i31_public(unsigned char *x, size_t xlen,
    const br_rsa_public_key *pk);

void br_i31_decode(uint32_t *x, const void *src, size_t len);
uint32_t br_i31_decode_mod(uint32_t *x, const void *src, size_t len, const uint32_t *m);
void br_i31_encode(void *dst, size_t len, const uint32_t *x);
uint32_t br_i31_ninv31(uint32_t x);
uint32_t br_i31_bit_length(const uint32_t *x, size_t xlen);
void br_i31_modpow_opt(uint32_t *x, const unsigned char *e, size_t elen,
    const uint32_t *m, uint32_t m0i, uint32_t *t, size_t twlen);

#ifdef __cplusplus
}
#endif

#endif
