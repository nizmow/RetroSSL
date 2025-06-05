/*
 * RetroSSL AES Small CBC Decryption
 * Based on BearSSL aes_small_cbcdec.c, adapted for Windows 98 SE and Open Watcom
 * 
 * Provides CBC (Cipher Block Chaining) mode decryption using AES small implementation
 */

#include "../retrossl_inner.h"

/*
 * Initialize AES CBC decryption context
 * 
 * Parameters:
 *   ctx: Decryption context to initialize
 *   key: AES key (16, 24, or 32 bytes for AES-128/192/256)
 *   len: Key length in bytes
 */
void
retrossl_aes_small_cbcdec_init(retrossl_aes_small_cbcdec_keys *ctx,
	const void *key, size_t len)
{
	ctx->vtable = NULL;  /* Simplified for Win98 */
	ctx->num_rounds = retrossl_aes_keysched(ctx->skey, key, len);
}

/*
 * Run AES CBC decryption
 * 
 * Decrypts data in-place using CBC mode. The IV is updated to contain
 * the last ciphertext block for chaining additional data.
 * 
 * Parameters:
 *   ctx: Initialized decryption context
 *   iv: 16-byte initialization vector (updated in-place)
 *   data: Data to decrypt (length must be multiple of 16 bytes)
 *   len: Length of data in bytes (must be multiple of 16)
 */
void
retrossl_aes_small_cbcdec_run(const retrossl_aes_small_cbcdec_keys *ctx,
	void *iv, void *data, size_t len)
{
	unsigned char *buf, *ivbuf;

	ivbuf = (unsigned char *)iv;
	buf = (unsigned char *)data;
	
	while (len > 0) {
		unsigned char tmp[16];
		int i;

		/* Save current ciphertext block for next IV */
		memcpy(tmp, buf, 16);
		
		/* Decrypt the block */
		retrossl_aes_small_decrypt(ctx->num_rounds, ctx->skey, buf);
		
		/* XOR with IV/previous ciphertext to get plaintext */
		for (i = 0; i < 16; i++) {
			buf[i] ^= ivbuf[i];
		}
		
		/* Update IV with saved ciphertext block */
		memcpy(ivbuf, tmp, 16);
		
		buf += 16;
		len -= 16;
	}
}
