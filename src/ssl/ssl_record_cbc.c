/*
 * TLS Record Layer with Real CBC Encryption for RetroSSL
 * Implements TLS_RSA_WITH_AES_128_CBC_SHA with proper key derivation
 */

#include "retrossl_ssl.h"
#include "retrossl_block.h"
#include "retrossl_hash.h"
#include "retrossl_mac.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
 * CBC record encryption context with real session keys
 */
typedef struct {
    /* Encryption contexts */
    retrossl_aes_small_cbcenc_keys enc_ctx;
    retrossl_aes_small_cbcdec_keys dec_ctx;
    
    /* HMAC contexts */
    br_hmac_key_context client_mac_ctx;
    br_hmac_key_context server_mac_ctx;
    
    /* Session state */
    unsigned char client_iv[16];
    unsigned char server_iv[16];
    uint64_t seq_out;
    uint64_t seq_in;
    
    /* Configuration */
    int initialized;
    int is_client;  /* 1 if we are the client, 0 if server */
} br_ssl_record_cbc_context;

static br_ssl_record_cbc_context g_record_ctx;

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
static int
br_ssl_record_build_header(unsigned char *buf, int record_type, 
                          unsigned version, size_t payload_len)
{
    if (payload_len > SSL_RECORD_MAX_PLAINTEXT + 256) { /* +256 for CBC overhead */
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
static int
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
 * Initialize CBC record layer with real session keys from TLS PRF
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
    
    /* We are the client */
    g_record_ctx.is_client = 1;
    
    /* Initialize AES contexts - client uses client keys for encryption */
    retrossl_aes_small_cbcenc_init(&g_record_ctx.enc_ctx, client_write_key, 16);
    retrossl_aes_small_cbcdec_init(&g_record_ctx.dec_ctx, server_write_key, 16);
    
    /* Initialize HMAC contexts */
    br_hmac_key_init(&g_record_ctx.client_mac_ctx, &br_sha1_vtable,
                     client_write_mac_key, 20);
    br_hmac_key_init(&g_record_ctx.server_mac_ctx, &br_sha1_vtable,
                     server_write_mac_key, 20);
    
    /* Set IVs */
    memcpy(g_record_ctx.client_iv, client_write_iv, 16);
    memcpy(g_record_ctx.server_iv, server_write_iv, 16);
    
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
 * Encrypt TLS record using real AES-128-CBC + HMAC-SHA1
 */
int
br_ssl_record_encrypt_cbc(int record_type, const unsigned char *plaintext, 
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
    compute_record_mac(&g_record_ctx.client_mac_ctx, g_record_ctx.seq_out,
                      record_type, TLS_1_0_VERSION, 
                      plaintext, plaintext_len, mac);
    memcpy(payload + plaintext_len, mac, 20);
    
    payload_len = plaintext_len + 20;
    
    /* Add PKCS#7 padding to 16-byte boundary */
    pad_len = 16 - (payload_len % 16);
    if (pad_len == 0) pad_len = 16;
    
    for (i = 0; i < (int)pad_len; i++) {
        payload[payload_len + i] = (unsigned char)(pad_len - 1);
    }
    
    padded_len = payload_len + pad_len;
    
    /* Encrypt with AES-128-CBC using current IV */
    retrossl_aes_small_cbcenc_run(&g_record_ctx.enc_ctx, g_record_ctx.client_iv,
                                 payload, padded_len);
    
    /* Update IV for next record - use last ciphertext block as next IV */
    if (padded_len >= 16) {
        memcpy(g_record_ctx.client_iv, payload + padded_len - 16, 16);
    }
    
    /* Build record header */
    br_ssl_record_build_header(output, record_type, TLS_1_0_VERSION, padded_len);
    
    *output_len = SSL_RECORD_HEADER_SIZE + padded_len;
    g_record_ctx.seq_out++;
    
    return 1;
}

/*
 * Decrypt TLS record using real AES-128-CBC + HMAC-SHA1  
 */
static int
decrypt_record_cbc(const unsigned char *input, size_t input_len,
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
        printf("ERROR: Failed to parse record header\n");
        return -1;
    }
    
    printf("DEBUG: Received record type=%d, version=0x%04x, payload_len=%zu\n", 
           *record_type, version, payload_len);
    
    if (input_len < SSL_RECORD_HEADER_SIZE + payload_len) {
        return -1;
    }
    
    payload = (unsigned char *)malloc(payload_len);
    if (!payload) {
        return -1;
    }
    
    /* Copy and decrypt payload */
    memcpy(payload, input + SSL_RECORD_HEADER_SIZE, payload_len);
    
    /* Save the last ciphertext block before decryption for IV chaining */
    unsigned char next_iv[16];
    if (payload_len >= 16) {
        memcpy(next_iv, payload + payload_len - 16, 16);
    }
    
    retrossl_aes_small_cbcdec_run(&g_record_ctx.dec_ctx, g_record_ctx.server_iv,
                                 payload, payload_len);
    
    /* Update IV for next record */
    if (payload_len >= 16) {
        memcpy(g_record_ctx.server_iv, next_iv, 16);
    }
    
    /* Extract and verify padding */
    pad_len = payload[payload_len - 1] + 1;
    if (pad_len > (int)payload_len || pad_len > 16) {
        printf("ERROR: Invalid padding length: %d (payload_len=%zu)\n", pad_len, payload_len);
        free(payload);
        return -1;
    }
    
    pad_ok = 1;
    for (i = 0; i < pad_len; i++) {
        if (payload[payload_len - 1 - i] != (pad_len - 1)) {
            pad_ok = 0;
        }
    }
    
    if (!pad_ok) {
        printf("ERROR: Padding verification failed\n");
        free(payload);
        return -1;
    }
    
    /* Extract MAC and compute expected MAC */
    *plaintext_len = payload_len - pad_len - 20;
    mac_start = *plaintext_len;
    
    if (mac_start + 20 > payload_len) {
        free(payload);
        return -1;
    }
    
    memcpy(received_mac, payload + mac_start, 20);
    
    compute_record_mac(&g_record_ctx.server_mac_ctx, g_record_ctx.seq_in,
                      *record_type, version,
                      payload, *plaintext_len, expected_mac);
    
    /* Verify MAC */
    mac_ok = 1;
    for (i = 0; i < 20; i++) {
        if (received_mac[i] != expected_mac[i]) {
            mac_ok = 0;
        }
    }
    
    if (!mac_ok) {
        printf("ERROR: MAC verification failed\n");
        free(payload);
        return -1;
    }
    
    /* Copy plaintext to output */
    memcpy(plaintext, payload, *plaintext_len);
    free(payload);
    
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
    unsigned char *record_buf;
    size_t record_len, max_record_size;
    int result;
    
    /* Calculate maximum record size (header + data + MAC + padding) */
    max_record_size = SSL_RECORD_HEADER_SIZE + data_len + 20 + 16;
    
    record_buf = malloc(max_record_size);
    if (!record_buf) {
        return -1;
    }
    
    result = br_ssl_record_encrypt_cbc(BR_SSL_APPLICATION_DATA, data, data_len,
                                       record_buf, &record_len);
    
    if (result > 0) {
        result = sock_write(socket_fd, record_buf, record_len);
    }
    
    free(record_buf);
    return result;
}

/*
 * Receive application data over encrypted connection
 */
int
br_ssl_record_recv_data(int socket_fd, unsigned char *data, size_t max_len,
                       int (*sock_read)(int fd, void *data, size_t len))
{
    unsigned char header_buf[SSL_RECORD_HEADER_SIZE];
    unsigned char *record_buf;
    int record_type;
    size_t plaintext_len, payload_len;
    int rlen, result;
    
    if (!g_record_ctx.initialized) {
        return -1;
    }
    
    /* Read record header */
    printf("DEBUG: Trying to read TLS record header (%d bytes)\n", SSL_RECORD_HEADER_SIZE);
    rlen = sock_read(socket_fd, header_buf, SSL_RECORD_HEADER_SIZE);
    printf("DEBUG: Read %d bytes for header\n", rlen);
    if (rlen != SSL_RECORD_HEADER_SIZE) {
        printf("ERROR: Failed to read complete header (got %d, expected %d)\n", 
               rlen, SSL_RECORD_HEADER_SIZE);
        return -1;
    }
    
    /* Dump raw header bytes */
    printf("DEBUG: Raw header bytes: %02x %02x %02x %02x %02x\n",
           header_buf[0], header_buf[1], header_buf[2], header_buf[3], header_buf[4]);
    
    /* Check if this looks like a TLS record header */
    if (header_buf[0] < 20 || header_buf[0] > 23) {
        printf("ERROR: Received non-TLS data (first byte 0x%02x) - protocol violation\n", header_buf[0]);
        return -1;
    }
    
    printf("INFO: Received TLS record type %d\n", header_buf[0]);

    /* Parse header to get payload length */
    int tmp_type;
    unsigned tmp_version;
    if (br_ssl_record_parse_header(header_buf, &tmp_type, &tmp_version, &payload_len) < 0) {
        printf("ERROR: Failed to parse header in recv function\n");
        return -1;
    }
    printf("DEBUG: Recv parsed header: type=%d, version=0x%04x, payload_len=%zu\n", 
           tmp_type, tmp_version, payload_len);
    
    /* Allocate buffer for complete record */
    record_buf = malloc(SSL_RECORD_HEADER_SIZE + payload_len);
    if (!record_buf) {
        return -1;
    }
    
    /* Copy header and read payload */
    memcpy(record_buf, header_buf, SSL_RECORD_HEADER_SIZE);
    rlen = sock_read(socket_fd, record_buf + SSL_RECORD_HEADER_SIZE, payload_len);
    if (rlen != (int)payload_len) {
        free(record_buf);
        return -1;
    }
    
    /* Decrypt and verify */
    result = decrypt_record_cbc(record_buf, SSL_RECORD_HEADER_SIZE + payload_len,
                               &record_type, data, &plaintext_len);
    
    free(record_buf);
    
    if (result <= 0) {
        return -1;
    }
    
    if (record_type != BR_SSL_APPLICATION_DATA) {
        printf("INFO: Received non-application data record type: %d\n", record_type);
        
        if (record_type == 21) { /* TLS Alert */
            printf("  - TLS Alert message received\n");
            if (plaintext_len >= 2) {
                int alert_level = data[0];
                int alert_desc = data[1];
                printf("  - Alert level: %d, description: %d\n", alert_level, alert_desc);
                
                if (alert_level == 2) { /* Fatal alert */
                    printf("  - FATAL ALERT: Connection will be terminated\n");
                    return -1;
                } else if (alert_level == 1) { /* Warning alert */
                    printf("  - Warning alert: Connection may continue\n");
                    if (alert_desc == 0) { /* Close notify */
                        printf("  - Close notify: Server is closing connection gracefully\n");
                        return 0; /* Graceful close */
                    }
                    return 0; /* Continue for other warnings */
                }
            }
            return -1;
            
        } else if (record_type == 20) { /* Change Cipher Spec */
            printf("  - Change Cipher Spec message (post-handshake)\n");
            /* This is normal but we shouldn't receive it during application data */
            return 0; /* Not an error, but no data to return */
            
        } else if (record_type == 22) { /* Handshake */
            printf("  - Handshake message (post-connection)\n");
            /* Could be session renegotiation - for now we ignore */
            return 0; /* Not an error, but no application data */
        }
        
        printf("  - Unknown record type: %d\n", record_type);
        return -1;  /* Unknown record type is an error */
    }
    
    return (int)plaintext_len;
}