/*
 * RetroSSL Internal Header for Windows 98 SE
 * Based on BearSSL inner.h, adapted for Open Watcom and Win98
 */

#ifndef RETROSSL_INNER_H__
#define RETROSSL_INNER_H__

#include <string.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

/* Win98/Open Watcom compatibility */
#ifdef WIN32
    #define RETROSSL_API __declspec(dllexport) __stdcall
#else
    #define RETROSSL_API
#endif

/* Basic type definitions for Win98 compatibility */
#ifndef BR_HASH_SIZE
#define BR_HASH_SIZE 64
#endif

/* Forward declarations */
typedef struct br_hash_class_ br_hash_class;
typedef struct br_hash_compat_context_ br_hash_compat_context;

/* MD5 specific definitions - RFC 1321 compliant */
#define br_md5_SIZE     16      /* MD5 produces 128-bit (16 byte) hash */
#define br_md5_ID       1       /* Unique identifier for MD5 algorithm */

typedef struct {
    const br_hash_class *vtable;  /* Virtual function table */
    unsigned char buf[64];         /* Internal buffer for partial blocks */
    uint64_t count;               /* Total bytes processed */
    uint32_t val[4];              /* MD5 state registers (A, B, C, D) */
} br_md5_context;

/* SHA-1 specific definitions - FIPS 180-1 compliant */
#define br_sha1_SIZE    20      /* SHA1 produces 160-bit (20 byte) hash */
#define br_sha1_ID      2       /* Unique identifier for SHA1 algorithm */

typedef struct {
    const br_hash_class *vtable;  /* Virtual function table */
    unsigned char buf[64];         /* Internal buffer for partial blocks */
    uint64_t count;               /* Total bytes processed */
    uint32_t val[5];              /* SHA1 state registers (H0-H4) */
} br_sha1_context;

/* MD5 function declarations */
extern const uint32_t br_md5_IV[4];
void br_md5_round(const unsigned char *buf, uint32_t *val);
void br_md5_init(br_md5_context *ctx);
void br_md5_update(br_md5_context *ctx, const void *data, size_t len);
void br_md5_out(const br_md5_context *ctx, void *out);

/* SHA-1 function declarations */
extern const uint32_t br_sha1_IV[5];
void br_sha1_round(const unsigned char *buf, uint32_t *val);
void br_sha1_init(br_sha1_context *ctx);
void br_sha1_update(br_sha1_context *ctx, const void *data, size_t len);
void br_sha1_out(const br_sha1_context *ctx, void *out);

/* Hash class structure */
struct br_hash_class_ {
    size_t context_size;
    unsigned char hash_size;
    unsigned char hash_id;
    void (*init)(void *ctx);
    void (*update)(void *ctx, const void *data, size_t len);
    void (*out)(const void *ctx, void *out);
    uint64_t (*state)(const void *ctx, void *out);
    void (*set_state)(void *ctx, const void *stb, uint64_t count);
};

extern const br_hash_class br_md5_vtable;
extern const br_hash_class br_sha1_vtable;

/* Byte manipulation functions */
static inline uint32_t br_dec32be(const void *src) {
    const unsigned char *buf = (const unsigned char *)src;
    return ((uint32_t)buf[0] << 24)
        | ((uint32_t)buf[1] << 16)
        | ((uint32_t)buf[2] << 8)
        | (uint32_t)buf[3];
}

static inline uint32_t br_dec32le(const void *src) {
    const unsigned char *buf = (const unsigned char *)src;
    return (uint32_t)buf[0]
        | ((uint32_t)buf[1] << 8)
        | ((uint32_t)buf[2] << 16)
        | ((uint32_t)buf[3] << 24);
}

static inline void br_enc32be(void *dst, uint32_t x) {
    unsigned char *buf = (unsigned char *)dst;
    buf[0] = (unsigned char)(x >> 24);
    buf[1] = (unsigned char)(x >> 16);
    buf[2] = (unsigned char)(x >> 8);
    buf[3] = (unsigned char)x;
}

static inline void br_enc32le(void *dst, uint32_t x) {
    unsigned char *buf = (unsigned char *)dst;
    buf[0] = (unsigned char)x;
    buf[1] = (unsigned char)(x >> 8);
    buf[2] = (unsigned char)(x >> 16);
    buf[3] = (unsigned char)(x >> 24);
}

static inline void br_enc64le(void *dst, uint64_t x) {
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

static inline void br_enc64be(void *dst, uint64_t x) {
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

void br_range_dec32le(uint32_t *v, size_t num, const void *src);
void br_range_dec32be(uint32_t *v, size_t num, const void *src);
void br_range_enc32le(void *dst, const uint32_t *v, size_t num);
void br_range_enc32be(void *dst, const uint32_t *v, size_t num);

#endif
