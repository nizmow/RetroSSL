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
 * - Fixed compatibility with Open Watcom
 * 
 * Copyright (c) 2025 RetroSSL Project
 * Original BearSSL code: Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 */

#ifndef RETROSSL_INNER_H__
#define RETROSSL_INNER_H__

#include <string.h>
#include <limits.h>
#include <stddef.h>

/* Include standard integer types */
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

/* Codec utility functions */
void br_range_dec32be(uint32_t *v, size_t num, const void *src);
void br_range_enc32be(void *dst, const uint32_t *v, size_t num);
void br_range_dec32le(uint32_t *v, size_t num, const void *src);
void br_range_enc32le(void *dst, const uint32_t *v, size_t num);

/* Inline codec utilities */
static inline uint32_t br_dec32be(const void *src) {
    const unsigned char *buf = src;
    return ((uint32_t)buf[0] << 24)
        | ((uint32_t)buf[1] << 16)
        | ((uint32_t)buf[2] << 8)
        | (uint32_t)buf[3];
}

static inline void br_enc32be(void *dst, uint32_t x) {
    unsigned char *buf = dst;
    buf[0] = (unsigned char)(x >> 24);
    buf[1] = (unsigned char)(x >> 16);
    buf[2] = (unsigned char)(x >> 8);
    buf[3] = (unsigned char)x;
}

static inline uint32_t br_dec32le(const void *src) {
    const unsigned char *buf = src;
    return ((uint32_t)buf[3] << 24)
        | ((uint32_t)buf[2] << 16)
        | ((uint32_t)buf[1] << 8)
        | (uint32_t)buf[0];
}

static inline void br_enc32le(void *dst, uint32_t x) {
    unsigned char *buf = dst;
    buf[0] = (unsigned char)x;
    buf[1] = (unsigned char)(x >> 8);
    buf[2] = (unsigned char)(x >> 16);
    buf[3] = (unsigned char)(x >> 24);
}

static inline void br_enc64be(void *dst, uint64_t x) {
    unsigned char *buf = dst;
    buf[0] = (unsigned char)(x >> 56);
    buf[1] = (unsigned char)(x >> 48);
    buf[2] = (unsigned char)(x >> 40);
    buf[3] = (unsigned char)(x >> 32);
    buf[4] = (unsigned char)(x >> 24);
    buf[5] = (unsigned char)(x >> 16);
    buf[6] = (unsigned char)(x >> 8);
    buf[7] = (unsigned char)x;
}

static inline void br_enc64le(void *dst, uint64_t x) {
    unsigned char *buf = dst;
    buf[0] = (unsigned char)x;
    buf[1] = (unsigned char)(x >> 8);
    buf[2] = (unsigned char)(x >> 16);
    buf[3] = (unsigned char)(x >> 24);
    buf[4] = (unsigned char)(x >> 32);
    buf[5] = (unsigned char)(x >> 40);
    buf[6] = (unsigned char)(x >> 48);
    buf[7] = (unsigned char)(x >> 56);
}

/* Define missing hash identifiers */
#ifndef BR_HASHDESC_ID
#define BR_HASHDESC_ID(id)              ((uint32_t)(id) << 28)
#endif
#ifndef BR_HASHDESC_OUT
#define BR_HASHDESC_OUT(size)           ((uint32_t)(size) << 16)
#endif
#ifndef BR_HASHDESC_STATE
#define BR_HASHDESC_STATE(size)         ((uint32_t)(size) << 8)
#endif
#ifndef BR_HASHDESC_LBLEN
#define BR_HASHDESC_LBLEN(size)         ((uint32_t)(size))
#endif
#ifndef BR_HASHDESC_MD_PADDING
#define BR_HASHDESC_MD_PADDING          ((uint32_t)1 << 27)
#endif
#ifndef BR_HASHDESC_MD_PADDING_BE
#define BR_HASHDESC_MD_PADDING_BE       ((uint32_t)1 << 26)
#endif

/* Hash function identifiers (from TLS standard) */
#ifndef br_sha1_ID
#define br_sha1_ID 2
#endif
#ifndef br_sha224_ID
#define br_sha224_ID 3
#endif
#ifndef br_sha256_ID
#define br_sha256_ID 4
#endif

/* AES S-box and inverse S-box (external declarations) */
extern const unsigned char retrossl_aes_S[256];
extern const unsigned char retrossl_aes_iS[256];

#endif /* RETROSSL_INNER_H__ */
