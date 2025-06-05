/*
 * RetroSSL Internal Header for Windows 98 SE
 * 
 * Based on BearSSL inner.h (commit 3c04036)
 * Source: temp/bearssl-analysis/src/inner.h
 * 
 * Adaptations for Open Watcom and Win98:
 * - Added codec utility functions (br_enc32be, br_dec32be, etc.)
 * - BearSSL compatibility aliases for seamless integration
 * - Win98-specific #ifdef guards and memory model adaptations
 * 
 * Copyright (c) 2025 RetroSSL Project
 * Original BearSSL code: Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 */

#ifndef RETROSSL_INNER_H__
#define RETROSSL_INNER_H__

#include <string.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

/* Include public headers */
#include "../include/retrossl_hash.h"
#include "../include/retrossl_block.h"

/* Win98/Open Watcom compatibility */
#ifdef WIN32
    #define RETROSSL_API __declspec(dllexport) __stdcall
#else
    #define RETROSSL_API
#endif

/* =================================================================== */
/*
 * AES Support Functions and Tables
 */

/*
 * The AES S-box (256-byte table).
 */
extern const unsigned char retrossl_aes_S[];

/*
 * AES key schedule generation.
 * Supports AES-128, AES-192, and AES-256.
 * Returns number of rounds (10, 12, or 14) or 0 on error.
 */
unsigned retrossl_aes_keysched(uint32_t *skey, const void *key, size_t key_len);

/*
 * AES Small implementation function declarations
 */
void retrossl_aes_small_encrypt(unsigned num_rounds, const uint32_t *skey, void *data);
void retrossl_aes_small_decrypt(unsigned num_rounds, const uint32_t *skey, void *data);

/*
 * AES Small CBC mode function declarations
 */
void retrossl_aes_small_cbcenc_init(retrossl_aes_small_cbcenc_keys *ctx,
	const void *key, size_t len);
void retrossl_aes_small_cbcenc_run(const retrossl_aes_small_cbcenc_keys *ctx,
	void *iv, void *data, size_t len);
void retrossl_aes_small_cbcdec_init(retrossl_aes_small_cbcdec_keys *ctx,
	const void *key, size_t len);
void retrossl_aes_small_cbcdec_run(const retrossl_aes_small_cbcdec_keys *ctx,
	void *iv, void *data, size_t len);

/*
 * Byte encoding and decoding functions for endianness handling
 */
static inline void
retrossl_enc32be(void *dst, uint32_t x)
{
    unsigned char *buf = (unsigned char *)dst;
    buf[0] = (unsigned char)(x >> 24);
    buf[1] = (unsigned char)(x >> 16);
    buf[2] = (unsigned char)(x >> 8);
    buf[3] = (unsigned char)x;
}

static inline uint32_t
retrossl_dec32be(const void *src)
{
    const unsigned char *buf = (const unsigned char *)src;
    return ((uint32_t)buf[0] << 24)
        | ((uint32_t)buf[1] << 16)
        | ((uint32_t)buf[2] << 8)
        | (uint32_t)buf[3];
}

static inline void
retrossl_enc32le(void *dst, uint32_t x)
{
    unsigned char *buf = (unsigned char *)dst;
    buf[0] = (unsigned char)x;
    buf[1] = (unsigned char)(x >> 8);
    buf[2] = (unsigned char)(x >> 16);
    buf[3] = (unsigned char)(x >> 24);
}

static inline uint32_t
retrossl_dec32le(const void *src)
{
    const unsigned char *buf = (const unsigned char *)src;
    return (uint32_t)buf[0]
        | ((uint32_t)buf[1] << 8)
        | ((uint32_t)buf[2] << 16)
        | ((uint32_t)buf[3] << 24);
}

static inline void
retrossl_enc64be(void *dst, uint64_t x)
{
    unsigned char *buf = (unsigned char *)dst;
    buf[0] = (unsigned char)(x >> 56);
    buf[1] = (unsigned char)(x >> 48);
    buf[2] = (unsigned char)(x >> 40);
    buf[3] = (unsigned char)(x >> 32);
    buf[4] = (unsigned char)(x >> 24);
    buf[5] = (unsigned char)(x >> 16);
    buf[6] = (unsigned char)(x >> 8);
    buf[7] = (unsigned char)x;
}

static inline void
retrossl_enc64le(void *dst, uint64_t x)
{
    unsigned char *buf = (unsigned char *)dst;
    buf[0] = (unsigned char)x;
    buf[1] = (unsigned char)(x >> 8);
    buf[2] = (unsigned char)(x >> 16);
    buf[3] = (unsigned char)(x >> 24);
    buf[4] = (unsigned char)(x >> 32);
    buf[5] = (unsigned char)(x >> 40);
    buf[6] = (unsigned char)(x >> 48);
    buf[7] = (unsigned char)(x >> 56);
}

/* BearSSL compatibility aliases */
#define br_enc32be retrossl_enc32be
#define br_dec32be retrossl_dec32be
#define br_enc32le retrossl_enc32le
#define br_dec32le retrossl_dec32le
#define br_enc64be retrossl_enc64be
#define br_enc64le retrossl_enc64le

/*
 * Range encoding/decoding functions (used by codec.c)
 */
void br_range_dec32be(uint32_t *v, size_t num, const void *src);
void br_range_enc32be(void *dst, const uint32_t *v, size_t num);
void br_range_dec32le(uint32_t *v, size_t num, const void *src);
void br_range_enc32le(void *dst, const uint32_t *v, size_t num);

#endif
