/*
 * Minimal TLS Record Layer Implementation for RetroSSL
 * Supports CBC mode for TLS_RSA_WITH_AES_128_CBC_SHA
 */

#include "retrossl_ssl.h"
#include "retrossl_block.h"
#include "retrossl_hash.h"
#include "retrossl_mac.h"
#include <string.h>

/* TLS record type constants */
#define BR_SSL_CHANGE_CIPHER_SPEC    20
#define BR_SSL_ALERT                 21
#define BR_SSL_HANDSHAKE             22
#define BR_SSL_APPLICATION_DATA      23

/* TLS content versions */
#define TLS_1_0_VERSION             0x0301

/* Maximum record sizes */
#define SSL_RECORD_MAX_PLAINTEXT    16384
#define SSL_RECORD_HEADER_SIZE      5

/*
 * Encode 16-bit big-endian value
 */
static void
br_enc16be(unsigned char *dst, unsigned x)
{
    dst[0] = (unsigned char)(x >> 8);
    dst[1] = (unsigned char)x;
}

/*
 * Decode 16-bit big-endian value
 */
static unsigned
br_dec16be(const unsigned char *src)
{
    return ((unsigned)src[0] << 8) | (unsigned)src[1];
}

/*
 * Encode 64-bit big-endian value (for sequence numbers)
 */
static void
br_enc64be(unsigned char *dst, uint64_t x)
{
    br_enc16be(dst, (unsigned)(x >> 48));
    br_enc16be(dst + 2, (unsigned)(x >> 32));
    br_enc16be(dst + 4, (unsigned)(x >> 16));
    br_enc16be(dst + 6, (unsigned)x);
}

/*
 * Build TLS record header: [type][version][length]
 */
int
br_ssl_record_build_header(unsigned char *buf, int record_type, 
                          unsigned version, size_t payload_len)
{
    if (payload_len > SSL_RECORD_MAX_PLAINTEXT) {
        return -1;
    }
    
    buf[0] = (unsigned char)record_type;
    br_enc16be(buf + 1, version);
    br_enc16be(buf + 3, (unsigned)payload_len);
    
    return SSL_RECORD_HEADER_SIZE;
}

/*
 * Parse TLS record header
 */
int
br_ssl_record_parse_header(const unsigned char *buf, int *record_type,
                          unsigned *version, size_t *payload_len)
{
    *record_type = buf[0];
    *version = br_dec16be(buf + 1);
    *payload_len = br_dec16be(buf + 3);
    
    /* Validate version (accept 3.x) */
    if ((*version >> 8) != 3) {
        return -1;
    }
    
    /* Validate payload length */
    if (*payload_len > SSL_RECORD_MAX_PLAINTEXT + 1024) { /* +1024 for overhead */
        return -1;
    }
    
    return SSL_RECORD_HEADER_SIZE;
}

/*
 * Simple context for CBC record encryption/decryption
 */
typedef struct {
    br_aes_small_cbcenc_keys enc_ctx;
    br_aes_small_cbcdec_keys dec_ctx;
    br_hmac_key_context mac_ctx;
    unsigned char iv[16];  /* AES block size */
    uint64_t seq_out;      /* Outgoing sequence number */
    uint64_t seq_in;       /* Incoming sequence number */
    int mac_len;           /* MAC length (20 for SHA-1) */
    int key_len;           /* Key length (16 for AES-128) */
    int initialized;
} br_ssl_record_cbc_context;

static br_ssl_record_cbc_context g_record_ctx;

/*
 * Initialize CBC record context with keys derived from handshake
 */
int
br_ssl_record_init_cbc(const unsigned char *client_write_mac_key,
                      const unsigned char *server_write_mac_key,
                      const unsigned char *client_write_key,
                      const unsigned char *server_write_key,
                      const unsigned char *client_write_iv,
                      const unsigned char *server_write_iv)
{
    memset(&g_record_ctx, 0, sizeof(g_record_ctx));
    
    /* For TLS_RSA_WITH_AES_128_CBC_SHA */
    g_record_ctx.mac_len = 20;  /* SHA-1 output */
    g_record_ctx.key_len = 16;  /* AES-128 */
    
    /* Initialize AES contexts (we are client, so use client keys for encryption) */
    br_aes_small_cbcenc_init(&g_record_ctx.enc_ctx, client_write_key, 16);
    br_aes_small_cbcdec_init(&g_record_ctx.dec_ctx, server_write_key, 16);
    
    /* Initialize HMAC contexts */
    br_hmac_key_init(&g_record_ctx.mac_ctx, &br_sha1_vtable, 
                     client_write_mac_key, 20);
    
    /* Set IVs */
    memcpy(g_record_ctx.iv, client_write_iv, 16);
    
    g_record_ctx.seq_out = 0;
    g_record_ctx.seq_in = 0;
    g_record_ctx.initialized = 1;
    
    return 1;
}

/*
 * Compute HMAC for TLS record
 */
static void
compute_record_mac(br_hmac_key_context *mac_ctx, uint64_t seq, int record_type,
                  unsigned version, const unsigned char *data, size_t data_len,
                  unsigned char *mac_out)
{
    br_hmac_context hc;
    unsigned char header[13];
    
    /* Build MAC input: seq_num || type || version || length || data */
    br_enc64be(header, seq);
    header[8] = (unsigned char)record_type;
    br_enc16be(header + 9, version);
    br_enc16be(header + 11, (unsigned)data_len);
    
    br_hmac_init(&hc, mac_ctx, 20);
    br_hmac_update(&hc, header, 13);
    br_hmac_update(&hc, data, data_len);
    br_hmac_out(&hc, mac_out);
}

/*
 * Encrypt TLS record using CBC mode
 */
int
br_ssl_record_encrypt(int record_type, const unsigned char *plaintext, 
                     size_t plaintext_len, unsigned char *output, 
                     size_t *output_len)
{
    unsigned char mac[20];
    unsigned char *payload;
    size_t payload_len, padded_len, pad_len;
    int i;
    
    if (!g_record_ctx.initialized) {
        return -1;
    }
    
    /* Payload = plaintext + MAC + padding */
    payload = output + SSL_RECORD_HEADER_SIZE;
    
    /* Copy plaintext */
    memcpy(payload, plaintext, plaintext_len);
    
    /* Compute and append MAC */
    compute_record_mac(&g_record_ctx.mac_ctx, g_record_ctx.seq_out,
                      record_type, TLS_1_0_VERSION, 
                      plaintext, plaintext_len, mac);
    memcpy(payload + plaintext_len, mac, 20);
    
    payload_len = plaintext_len + 20;
    
    /* Add PKCS#7 padding to block boundary */
    pad_len = 16 - (payload_len % 16);
    if (pad_len == 0) pad_len = 16;
    
    for (i = 0; i < pad_len; i++) {
        payload[payload_len + i] = (unsigned char)(pad_len - 1);
    }
    
    padded_len = payload_len + pad_len;
    
    /* Encrypt with CBC */
    br_aes_small_cbcenc_run(&g_record_ctx.enc_ctx, g_record_ctx.iv,
                           payload, padded_len);
    
    /* Build record header */
    br_ssl_record_build_header(output, record_type, TLS_1_0_VERSION, padded_len);
    
    *output_len = SSL_RECORD_HEADER_SIZE + padded_len;
    g_record_ctx.seq_out++;
    
    return 1;
}

/*
 * Decrypt TLS record using CBC mode  
 */
int
br_ssl_record_decrypt(const unsigned char *input, size_t input_len,
                     int *record_type, unsigned char *plaintext,
                     size_t *plaintext_len)
{
    unsigned version;
    size_t payload_len;
    unsigned char *payload;
    unsigned char expected_mac[20], received_mac[20];
    size_t mac_start;
    int pad_len, i;
    int mac_ok, pad_ok;
    
    if (!g_record_ctx.initialized) {
        return -1;
    }
    
    /* Parse record header */
    if (br_ssl_record_parse_header(input, record_type, &version, &payload_len) < 0) {
        return -1;
    }
    
    if (input_len < SSL_RECORD_HEADER_SIZE + payload_len) {
        return -1;
    }
    
    payload = (unsigned char *)input + SSL_RECORD_HEADER_SIZE;
    
    /* Decrypt payload */
    memcpy(plaintext, payload, payload_len);
    br_aes_small_cbcdec_run(&g_record_ctx.dec_ctx, g_record_ctx.iv,
                           plaintext, payload_len);
    
    /* Extract and verify padding */
    pad_len = plaintext[payload_len - 1] + 1;
    if (pad_len > payload_len || pad_len > 16) {
        return -1;
    }
    
    pad_ok = 1;
    for (i = 0; i < pad_len; i++) {
        if (plaintext[payload_len - 1 - i] != (pad_len - 1)) {
            pad_ok = 0;
        }
    }
    
    if (!pad_ok) {
        return -1;
    }
    
    /* Extract MAC and compute expected MAC */
    *plaintext_len = payload_len - pad_len - 20;
    mac_start = *plaintext_len;
    
    memcpy(received_mac, plaintext + mac_start, 20);
    
    compute_record_mac(&g_record_ctx.mac_ctx, g_record_ctx.seq_in,
                      *record_type, version,
                      plaintext, *plaintext_len, expected_mac);
    
    /* Verify MAC */
    mac_ok = 1;
    for (i = 0; i < 20; i++) {
        if (received_mac[i] != expected_mac[i]) {
            mac_ok = 0;
        }
    }
    
    if (!mac_ok) {
        return -1;
    }
    
    g_record_ctx.seq_in++;
    return 1;
}

/*
 * Send application data over encrypted connection
 */
int
br_ssl_record_send_data(int socket_fd, const unsigned char *data, size_t data_len,
                       int (*sock_write)(int fd, const void *data, size_t len))
{
    unsigned char record_buf[SSL_RECORD_HEADER_SIZE + SSL_RECORD_MAX_PLAINTEXT + 256];
    size_t record_len;
    
    if (br_ssl_record_encrypt(BR_SSL_APPLICATION_DATA, data, data_len,
                             record_buf, &record_len) < 0) {
        return -1;
    }
    
    return sock_write(socket_fd, record_buf, record_len);
}

/*
 * Receive application data over encrypted connection
 */
int
br_ssl_record_recv_data(int socket_fd, unsigned char *data, size_t max_len,
                       int (*sock_read)(int fd, void *data, size_t len))
{
    unsigned char record_buf[SSL_RECORD_HEADER_SIZE + SSL_RECORD_MAX_PLAINTEXT + 256];
    int record_type;
    size_t plaintext_len;
    int rlen;
    
    /* Read record header */
    rlen = sock_read(socket_fd, record_buf, SSL_RECORD_HEADER_SIZE);
    if (rlen != SSL_RECORD_HEADER_SIZE) {
        return -1;
    }
    
    /* Parse header to get payload length */
    int tmp_type;
    unsigned tmp_version;
    size_t payload_len;
    if (br_ssl_record_parse_header(record_buf, &tmp_type, &tmp_version, &payload_len) < 0) {
        return -1;
    }
    
    /* Read payload */
    rlen = sock_read(socket_fd, record_buf + SSL_RECORD_HEADER_SIZE, payload_len);
    if (rlen != (int)payload_len) {
        return -1;
    }
    
    /* Decrypt and verify */
    if (br_ssl_record_decrypt(record_buf, SSL_RECORD_HEADER_SIZE + payload_len,
                             &record_type, data, &plaintext_len) < 0) {
        return -1;
    }
    
    if (record_type != BR_SSL_APPLICATION_DATA) {
        return -1;  /* We only handle application data for now */
    }
    
    return (int)plaintext_len;
}