#include <stdio.h>
#include "retrossl_ssl.h"
#include "retrossl_inner.h"
#include "retrossl_rsa.h"

/* TLS constants */
#define TLS_CONTENT_TYPE_HANDSHAKE  22
#define TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC  20
#define TLS_CONTENT_TYPE_APPLICATION_DATA  23

#define TLS_HANDSHAKE_CLIENT_HELLO  1
#define TLS_HANDSHAKE_SERVER_HELLO  2
#define TLS_HANDSHAKE_CERTIFICATE   11
#define TLS_HANDSHAKE_SERVER_HELLO_DONE  14
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE  16
#define TLS_HANDSHAKE_FINISHED      20

/* Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA */
#define TLS_RSA_WITH_AES_128_CBC_SHA  0x002F

/* Helper: Write 16-bit big-endian */
static void
write_u16(unsigned char *buf, uint16_t val)
{
    buf[0] = (unsigned char)(val >> 8);
    buf[1] = (unsigned char)val;
}

/* Helper: Write 24-bit big-endian */
static void 
write_u24(unsigned char *buf, uint32_t val)
{
    buf[0] = (unsigned char)(val >> 16);
    buf[1] = (unsigned char)(val >> 8);
    buf[2] = (unsigned char)val;
}

/* Helper: Read 16-bit big-endian */
static uint16_t
read_u16(const unsigned char *buf)
{
    return ((uint16_t)buf[0] << 8) | buf[1];
}

/* Helper: Read 24-bit big-endian */
static uint32_t
read_u24(const unsigned char *buf)
{
    return ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
}

/* Build ClientHello message */
static size_t
build_client_hello(br_ssl_client_context *cc, unsigned char *buf, size_t buf_len)
{
    unsigned char *p = buf;
    size_t hostname_len = strlen(cc->eng.server_name);
    
    /* TLS Record Header */
    *p++ = TLS_CONTENT_TYPE_HANDSHAKE;  /* Content Type */
    write_u16(p, BR_TLS10);             /* Version */
    p += 2;
    
    /* Record Length (placeholder - will fill later) */
    unsigned char *record_len_ptr = p;
    p += 2;
    
    /* Handshake Header */
    *p++ = TLS_HANDSHAKE_CLIENT_HELLO;  /* Handshake Type */
    
    /* Handshake Length (placeholder - will fill later) */
    unsigned char *handshake_len_ptr = p;
    p += 3;
    
    /* ClientHello Body */
    write_u16(p, BR_TLS10);             /* Client Version */
    p += 2;
    
    /* Client Random (32 bytes) - use simple pattern for now */
    memset(p, 0x01, 32);
    p += 32;
    
    /* Session ID Length + Session ID (empty) */
    *p++ = 0;
    
    /* Cipher Suites Length + Cipher Suites */
    write_u16(p, 2);                    /* Length: 1 cipher suite */
    p += 2;
    write_u16(p, TLS_RSA_WITH_AES_128_CBC_SHA);
    p += 2;
    
    /* Compression Methods Length + Methods */
    *p++ = 1;                           /* Length: 1 method */
    *p++ = 0;                           /* No compression */
    
    /* Extensions Length */
    uint16_t ext_total_len = 0;
    if (hostname_len > 0) {
        ext_total_len = 2 + 2 + 2 + 1 + 2 + hostname_len;  /* SNI extension */
    }
    write_u16(p, ext_total_len);
    p += 2;
    
    /* SNI Extension (if hostname provided) */
    if (hostname_len > 0) {
        write_u16(p, 0x0000);           /* Extension Type: Server Name */
        p += 2;
        write_u16(p, 2 + 1 + 2 + hostname_len);  /* Extension Length */
        p += 2;
        write_u16(p, 1 + 2 + hostname_len);      /* Server Name List Length */
        p += 2;
        *p++ = 0;                       /* Name Type: hostname */
        write_u16(p, hostname_len);     /* Hostname Length */
        p += 2;
        memcpy(p, cc->eng.server_name, hostname_len);
        p += hostname_len;
    }
    
    /* Fill in lengths */
    size_t handshake_len = (p - handshake_len_ptr) - 3;
    size_t record_len = (p - record_len_ptr) - 2;
    
    write_u24(handshake_len_ptr, handshake_len);
    write_u16(record_len_ptr, record_len);
    
    return p - buf;
}

/* Parse ServerHello message */
static int
parse_server_hello(br_ssl_client_context *cc, const unsigned char *buf, size_t len)
{
    const unsigned char *p = buf;
    
    /* Skip TLS record header (5 bytes) */
    if (len < 5) return 0;
    if (p[0] != TLS_CONTENT_TYPE_HANDSHAKE) return 0;
    p += 5;
    len -= 5;
    
    /* Parse handshake header */
    if (len < 4) return 0;
    if (p[0] != TLS_HANDSHAKE_SERVER_HELLO) return 0;
    uint32_t handshake_len = read_u24(p + 1);
    p += 4;
    len -= 4;
    
    if (len < handshake_len) return 0;
    
    /* Parse ServerHello body */
    if (handshake_len < 2 + 32 + 1) return 0;
    
    /* Server Version */
    uint16_t server_version = read_u16(p);
    p += 2;
    
    /* Server Random (32 bytes) */
    p += 32;
    
    /* Session ID */
    uint8_t session_id_len = *p++;
    p += session_id_len;
    
    /* Cipher Suite */
    uint16_t cipher_suite = read_u16(p);
    p += 2;
    
    /* Compression Method */
    uint8_t compression = *p++;
    
    /* Check if we got the cipher suite we wanted */
    if (cipher_suite != TLS_RSA_WITH_AES_128_CBC_SHA) {
        return 0;  /* Unsupported cipher suite */
    }
    
    printf("ServerHello: version=0x%04X, cipher=0x%04X, compression=%d\n",
           server_version, cipher_suite, compression);
    
    return 1;  /* Success */
}

/* Minimal handshake implementation */
int
br_ssl_handshake_client(br_ssl_client_context *cc, 
                       int (*sock_write)(int fd, const void *data, size_t len),
                       int (*sock_read)(int fd, void *data, size_t len),
                       int socket_fd)
{
    unsigned char buf[1024];
    size_t len;
    
    printf("Starting TLS handshake with %s\n", cc->eng.server_name);
    
    /* Step 1: Send ClientHello */
    len = build_client_hello(cc, buf, sizeof(buf));
    printf("Sending ClientHello (%u bytes)\n", (unsigned)len);
    
    if (sock_write(socket_fd, buf, len) != (int)len) {
        printf("Failed to send ClientHello\n");
        return 0;
    }
    
    /* Step 2: Read ServerHello */
    printf("Reading ServerHello...\n");
    int rlen = sock_read(socket_fd, buf, sizeof(buf));
    if (rlen <= 0) {
        printf("Failed to read ServerHello\n");
        return 0;
    }
    
    printf("Received %d bytes from server\n", rlen);
    
    if (!parse_server_hello(cc, buf, rlen)) {
        printf("Failed to parse ServerHello\n");
        return 0;
    }
    
    /* For now, just mark handshake as "complete" */
    cc->eng.state = BR_SSL_SENDAPP | BR_SSL_RECVAPP;
    printf("Handshake complete (minimal implementation)\n");
    
    return 1;
}
