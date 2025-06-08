/*
 * TLS PRF (Pseudo-Random Function) Implementation for RetroSSL
 * Based on RFC 2246 (TLS 1.0) specification
 */

#include "retrossl_ssl.h"
#include "retrossl_hash.h"
#include "retrossl_mac.h"
#include <string.h>
#include <stdlib.h>

/*
 * P_hash function - core of TLS PRF
 * Implements P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
 *                                   HMAC_hash(secret, A(2) + seed) + ...
 * Where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
 */
static void
br_tls_phash(void *dst, size_t len,
            const br_hash_class *dig, size_t hash_len,
            const void *secret, size_t secret_len,
            const void *seed, size_t seed_len)
{
    br_hmac_key_context kc;
    br_hmac_context hc;
    unsigned char A[64];  /* Max hash output size */
    unsigned char tmp[64];
    size_t chunk_len;
    unsigned char *out = (unsigned char *)dst;
    
    /* Initialize HMAC key context */
    br_hmac_key_init(&kc, dig, secret, secret_len);
    
    /* Compute A(1) = HMAC_hash(secret, seed) */
    br_hmac_init(&hc, &kc, hash_len);
    br_hmac_update(&hc, seed, seed_len);
    br_hmac_out(&hc, A);
    
    while (len > 0) {
        /* Compute HMAC_hash(secret, A(i) + seed) */
        br_hmac_init(&hc, &kc, hash_len);
        br_hmac_update(&hc, A, hash_len);
        br_hmac_update(&hc, seed, seed_len);
        br_hmac_out(&hc, tmp);
        
        /* Copy to output */
        chunk_len = (len < hash_len) ? len : hash_len;
        memcpy(out, tmp, chunk_len);
        out += chunk_len;
        len -= chunk_len;
        
        /* Compute A(i+1) = HMAC_hash(secret, A(i)) */
        if (len > 0) {
            br_hmac_init(&hc, &kc, hash_len);
            br_hmac_update(&hc, A, hash_len);
            br_hmac_out(&hc, A);
        }
    }
}

/*
 * TLS 1.0 PRF implementation
 * PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR P_SHA1(S2, label + seed)
 */
void
br_tls10_prf(void *dst, size_t len,
            const void *secret, size_t secret_len,
            const char *label,
            const void *seed, size_t seed_len)
{
    size_t slen, seed_total_len;
    unsigned char *label_seed;
    unsigned char *out = (unsigned char *)dst;
    unsigned char *buf1, *buf2;
    size_t i, label_len;
    const unsigned char *s1, *s2;
    
    label_len = strlen(label);
    seed_total_len = label_len + seed_len;
    
    /* Create label + seed */
    label_seed = malloc(seed_total_len);
    if (!label_seed) {
        return;
    }
    memcpy(label_seed, label, label_len);
    memcpy(label_seed + label_len, seed, seed_len);
    
    /* Allocate buffers for P_hash outputs */
    buf1 = malloc(len);
    buf2 = malloc(len);
    if (!buf1 || !buf2) {
        free(label_seed);
        free(buf1);
        free(buf2);
        return;
    }
    
    /* Split secret into two halves with overlap */
    slen = (secret_len + 1) >> 1;  /* Each half gets at least half, with overlap */
    s1 = (const unsigned char *)secret;        /* First half for MD5 */
    s2 = (const unsigned char *)secret + (secret_len - slen);  /* Second half for SHA-1 */
    
    /* Clear output buffer */
    memset(dst, 0, len);
    
    /* Compute P_MD5(S1, label + seed) */
    br_tls_phash(buf1, len, &br_md5_vtable, br_md5_SIZE, s1, slen, label_seed, seed_total_len);
    
    /* Compute P_SHA1(S2, label + seed) */
    br_tls_phash(buf2, len, &br_sha1_vtable, br_sha1_SIZE, s2, slen, label_seed, seed_total_len);
    
    /* XOR the results */
    for (i = 0; i < len; i++) {
        out[i] = buf1[i] ^ buf2[i];
    }
    
    free(label_seed);
    free(buf1);
    free(buf2);
}

/*
 * Derive TLS session keys from master secret
 * For TLS_RSA_WITH_AES_128_CBC_SHA cipher suite
 */
int
br_ssl_derive_keys(const unsigned char master_secret[48],
                  const unsigned char client_random[32],
                  const unsigned char server_random[32],
                  unsigned char *client_write_mac_key,    /* 20 bytes */
                  unsigned char *server_write_mac_key,    /* 20 bytes */
                  unsigned char *client_write_key,        /* 16 bytes */
                  unsigned char *server_write_key,        /* 16 bytes */
                  unsigned char *client_write_iv,         /* 16 bytes */
                  unsigned char *server_write_iv)         /* 16 bytes */
{
    unsigned char key_block[104];  /* 20+20+16+16+16+16 = 104 bytes */
    unsigned char seed[64];        /* server_random + client_random */
    
    /* Create seed: server_random + client_random (note order!) */
    memcpy(seed, server_random, 32);
    memcpy(seed + 32, client_random, 32);
    
    /* Generate key block using TLS 1.0 PRF */
    br_tls10_prf(key_block, sizeof(key_block),
                 master_secret, 48,
                 "key expansion",
                 seed, 64);
    
    /* Extract keys from key block */
    memcpy(client_write_mac_key, key_block + 0, 20);   /* Bytes 0-19 */
    memcpy(server_write_mac_key, key_block + 20, 20);  /* Bytes 20-39 */
    memcpy(client_write_key, key_block + 40, 16);      /* Bytes 40-55 */
    memcpy(server_write_key, key_block + 56, 16);      /* Bytes 56-71 */
    memcpy(client_write_iv, key_block + 72, 16);       /* Bytes 72-87 */
    memcpy(server_write_iv, key_block + 88, 16);       /* Bytes 88-103 */
    
    return 1;
}

/*
 * Generate master secret from pre-master secret (for testing)
 * Normally this would be done during the handshake
 */
int
br_ssl_compute_master_secret(const unsigned char *pre_master_secret, size_t pms_len,
                            const unsigned char client_random[32],
                            const unsigned char server_random[32],
                            unsigned char master_secret[48])
{
    unsigned char seed[64];  /* client_random + server_random */
    
    /* Create seed: client_random + server_random */
    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);
    
    /* Generate master secret using TLS 1.0 PRF */
    br_tls10_prf(master_secret, 48,
                 pre_master_secret, pms_len,
                 "master secret",
                 seed, 64);
    
    return 1;
}