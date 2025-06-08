/*
 * Simplified TLS Record Layer for RetroSSL
 * Minimal implementation for testing encrypted data transfer
 */

#include "retrossl_ssl.h"
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
 * Simple record context - initially unencrypted for testing
 */
static struct {
    int initialized;
    uint64_t seq_out;
    uint64_t seq_in;
} g_record_ctx = { 0, 0, 0 };

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
 * Initialize record layer (simplified - no real keys for now)
 */
int
br_ssl_record_init_cbc(const unsigned char *client_write_mac_key,
                      const unsigned char *server_write_mac_key,
                      const unsigned char *client_write_key,
                      const unsigned char *server_write_key,
                      const unsigned char *client_write_iv,
                      const unsigned char *server_write_iv)
{
    /* For now, just mark as initialized */
    /* TODO: Store actual keys when full encryption is implemented */
    (void)client_write_mac_key;
    (void)server_write_mac_key;
    (void)client_write_key;
    (void)server_write_key;
    (void)client_write_iv;
    (void)server_write_iv;
    
    g_record_ctx.initialized = 1;
    g_record_ctx.seq_out = 0;
    g_record_ctx.seq_in = 0;
    
    return 1;
}

/*
 * Send application data - currently unencrypted for testing
 */
int
br_ssl_record_send_data(int socket_fd, const unsigned char *data, size_t data_len,
                       int (*sock_write)(int fd, const void *data, size_t len))
{
    unsigned char record_buf[SSL_RECORD_HEADER_SIZE + SSL_RECORD_MAX_PLAINTEXT];
    size_t record_len;
    
    if (!g_record_ctx.initialized) {
        return -1;
    }
    
    if (data_len > SSL_RECORD_MAX_PLAINTEXT) {
        return -1;
    }
    
    /* Build record header */
    if (br_ssl_record_build_header(record_buf, BR_SSL_APPLICATION_DATA,
                                   TLS_1_0_VERSION, data_len) < 0) {
        return -1;
    }
    
    /* Copy payload (unencrypted for now) */
    memcpy(record_buf + SSL_RECORD_HEADER_SIZE, data, data_len);
    record_len = SSL_RECORD_HEADER_SIZE + data_len;
    
    /* Send record */
    g_record_ctx.seq_out++;
    return sock_write(socket_fd, record_buf, record_len);
}

/*
 * Receive application data - currently expects unencrypted for testing
 */
int
br_ssl_record_recv_data(int socket_fd, unsigned char *data, size_t max_len,
                       int (*sock_read)(int fd, void *data, size_t len))
{
    unsigned char record_buf[SSL_RECORD_HEADER_SIZE + SSL_RECORD_MAX_PLAINTEXT];
    int record_type;
    unsigned version;
    size_t payload_len;
    int rlen;
    
    if (!g_record_ctx.initialized) {
        return -1;
    }
    
    /* Read record header */
    rlen = sock_read(socket_fd, record_buf, SSL_RECORD_HEADER_SIZE);
    if (rlen != SSL_RECORD_HEADER_SIZE) {
        return -1;
    }
    
    /* Parse header */
    if (br_ssl_record_parse_header(record_buf, &record_type, &version, &payload_len) < 0) {
        return -1;
    }
    
    /* Validate record type */
    if (record_type != BR_SSL_APPLICATION_DATA) {
        return -1;  /* We only handle application data for now */
    }
    
    /* Check buffer size */
    if (payload_len > max_len) {
        return -1;
    }
    
    /* Read payload */
    rlen = sock_read(socket_fd, record_buf + SSL_RECORD_HEADER_SIZE, payload_len);
    if (rlen != (int)payload_len) {
        return -1;
    }
    
    /* Copy payload (unencrypted for now) */
    memcpy(data, record_buf + SSL_RECORD_HEADER_SIZE, payload_len);
    
    g_record_ctx.seq_in++;
    return (int)payload_len;
}