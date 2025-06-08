#ifndef RETROSSL_MAC_H__
#define RETROSSL_MAC_H__

#include <stddef.h>
#include <stdint.h>
#include "retrossl_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * HMAC context structure
 */
typedef struct {
    const br_hash_class *vtable;
    unsigned char ksi[64];  /* Inner key XOR'd with ipad */
    unsigned char kso[64];  /* Outer key XOR'd with opad */
    br_hash_compat_context ctx;
} br_hmac_context;

/*
 * HMAC key context (precomputed key)
 */
typedef struct {
    const br_hash_class *vtable;
    unsigned char ksi[64];  /* Inner key XOR'd with ipad */
    unsigned char kso[64];  /* Outer key XOR'd with opad */
} br_hmac_key_context;

/*
 * HMAC functions
 */
void br_hmac_init(br_hmac_context *ctx, const br_hmac_key_context *kc, size_t out_len);
void br_hmac_update(br_hmac_context *ctx, const void *data, size_t len);
void br_hmac_out(const br_hmac_context *ctx, void *out);

void br_hmac_key_init(br_hmac_key_context *kc, const br_hash_class *dig, 
                     const void *key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif