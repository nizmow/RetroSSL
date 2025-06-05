/*
 * RetroSSL - Block Cipher API for Windows 98 SE
 * Based on BearSSL bearssl_block.h
 * 
 * Copyright (c) 2025 RetroSSL Project
 * Based on BearSSL Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef RETROSSL_BLOCK_H__
#define RETROSSL_BLOCK_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file retrossl_block.h
 *
 * # Block Ciphers and Symmetric Ciphers for Win98
 *
 * This file documents the API for block ciphers and other symmetric
 * ciphers, adapted for Windows 98 SE and Open Watcom compatibility.
 */

/* =================================================================== */
/*
 * AES Small Implementation (optimized for size, suitable for Win98)
 */

/** \brief AES block size (16 bytes). */
#define RETROSSL_AES_BLOCK_SIZE   16

/**
 * \brief Context for AES subkeys (small implementation, CBC encryption).
 *
 * First field is a pointer to the vtable; it is set by the initialisation
 * function. Other fields are not supposed to be accessed by user code.
 */
typedef struct {
    /** \brief Pointer to vtable for this context. */
    const void *vtable;  /* For future extensibility */
    uint32_t skey[60];   /* AES expanded key (up to 14 rounds) */
    unsigned num_rounds; /* Number of AES rounds (10, 12, or 14) */
} retrossl_aes_small_cbcenc_keys;

/**
 * \brief Context for AES subkeys (small implementation, CBC decryption).
 *
 * First field is a pointer to the vtable; it is set by the initialisation
 * function. Other fields are not supposed to be accessed by user code.
 */
typedef struct {
    /** \brief Pointer to vtable for this context. */
    const void *vtable;  /* For future extensibility */
    uint32_t skey[60];   /* AES expanded key (up to 14 rounds) */
    unsigned num_rounds; /* Number of AES rounds (10, 12, or 14) */
} retrossl_aes_small_cbcdec_keys;

/* =================================================================== */
/*
 * AES Small Implementation Functions
 */

/**
 * \brief Context initialisation (key schedule) for AES CBC encryption
 * (small implementation).
 *
 * \param ctx   context to initialise.
 * \param key   secret key.
 * \param len   secret key length (in bytes: 16, 24, or 32).
 */
void retrossl_aes_small_cbcenc_init(retrossl_aes_small_cbcenc_keys *ctx,
    const void *key, size_t len);

/**
 * \brief Context initialisation (key schedule) for AES CBC decryption
 * (small implementation).
 *
 * \param ctx   context to initialise.
 * \param key   secret key.
 * \param len   secret key length (in bytes: 16, 24, or 32).
 */
void retrossl_aes_small_cbcdec_init(retrossl_aes_small_cbcdec_keys *ctx,
    const void *key, size_t len);

/**
 * \brief CBC encryption with AES (small implementation).
 *
 * \param ctx    context (already initialised).
 * \param iv     IV (updated).
 * \param data   data to encrypt (updated).
 * \param len    data length (in bytes, MUST be multiple of 16).
 */
void retrossl_aes_small_cbcenc_run(const retrossl_aes_small_cbcenc_keys *ctx, 
    void *iv, void *data, size_t len);

/**
 * \brief CBC decryption with AES (small implementation).
 *
 * \param ctx    context (already initialised).
 * \param iv     IV (updated).
 * \param data   data to decrypt (updated).
 * \param len    data length (in bytes, MUST be multiple of 16).
 */
void retrossl_aes_small_cbcdec_run(const retrossl_aes_small_cbcdec_keys *ctx, 
    void *iv, void *data, size_t len);

/* =================================================================== */
/*
 * Low-level AES functions (internal use)
 */

/**
 * \brief AES key schedule. 
 * 
 * Returns the number of rounds (10, 12, or 14). If the key size is 
 * invalid (not 16, 24 or 32), then 0 is returned.
 *
 * \param skey     destination for expanded subkeys.
 * \param key      secret key.
 * \param key_len  secret key length (in bytes).
 * \return         number of rounds, or 0 on error.
 */
unsigned retrossl_aes_keysched(uint32_t *skey, const void *key, size_t key_len);

/**
 * \brief AES key schedule for decryption (small implementation).
 * 
 * \param skey     destination for expanded subkeys.
 * \param key      secret key.
 * \param key_len  secret key length (in bytes).
 * \return         number of rounds, or 0 on error.
 */
unsigned retrossl_aes_small_keysched_inv(uint32_t *skey,
    const void *key, size_t key_len);

/**
 * \brief AES block encryption (small implementation).
 * 
 * This function encrypts a single block "in place".
 * 
 * \param num_rounds  number of rounds.
 * \param skey        expanded subkeys.
 * \param data        block to encrypt (16 bytes, modified in place).
 */
void retrossl_aes_small_encrypt(unsigned num_rounds, 
    const uint32_t *skey, void *data);

/**
 * \brief AES block decryption (small implementation).
 * 
 * This function decrypts a single block "in place".
 * 
 * \param num_rounds  number of rounds.
 * \param skey        expanded subkeys.
 * \param data        block to decrypt (16 bytes, modified in place).
 */
void retrossl_aes_small_decrypt(unsigned num_rounds, 
    const uint32_t *skey, void *data);

#ifdef __cplusplus
}
#endif

#endif
