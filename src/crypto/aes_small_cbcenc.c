/*
 * RetroSSL AES Small CBC Encryption
 * Based on BearSSL aes_small_cbcenc.c, adapted for Windows 98 SE and Open Watcom
 * 
 * Provides CBC (Cipher Block Chaining) mode encryption using AES small implementation
 */

#include "../retrossl_inner.h"

/* 
 * Initialize AES CBC encryption context
 * 
 * Parameters:
 *   ctx: Encryption context to initialize
 *   key: AES key (16, 24, or 32 bytes for AES-128/192/256)
 *   len: Key length in bytes
 */
void
retrossl_aes_small_cbcenc_init(retrossl_aes_small_cbcenc_keys *ctx,
	const void *key, size_t len)
{
	ctx->vtable = NULL;  /* Simplified for Win98 */
	ctx->num_rounds = retrossl_aes_keysched(ctx->skey, key, len);
}

/*
 * Run AES CBC encryption
 * 
 * Encrypts data in-place using CBC mode. The IV is updated to contain
 * the last ciphertext block for chaining additional data.
 * 
 * Parameters:
 *   ctx: Initialized encryption context
 *   iv: 16-byte initialization vector (updated in-place)
 *   data: Data to encrypt (length must be multiple of 16 bytes)
 *   len: Length of data in bytes (must be multiple of 16)
 */
void
retrossl_aes_small_cbcenc_run(const retrossl_aes_small_cbcenc_keys *ctx,
	void *iv, void *data, size_t len)
{
	unsigned char *buf, *ivbuf;

	ivbuf = (unsigned char *)iv;
	buf = (unsigned char *)data;
	
	while (len > 0) {
		int i;

		/* XOR plaintext block with IV/previous ciphertext */
		for (i = 0; i < 16; i++) {
			buf[i] ^= ivbuf[i];
		}
		
		/* Encrypt the block */
		retrossl_aes_small_encrypt(ctx->num_rounds, ctx->skey, buf);
		
		/* Copy ciphertext to IV for next block */
		memcpy(ivbuf, buf, 16);
		
		buf += 16;
		len -= 16;
	}
}
