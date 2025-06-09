#ifndef RETROSSL_SSL_H__
#define RETROSSL_SSL_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Buffer size constants (from BearSSL) */
#define BR_SSL_BUFSIZE_INPUT    (16384 + 325)
#define BR_SSL_BUFSIZE_OUTPUT   (16384 + 85)
#define BR_SSL_BUFSIZE_MONO     BR_SSL_BUFSIZE_INPUT
#define BR_SSL_BUFSIZE_BIDI     (BR_SSL_BUFSIZE_INPUT + BR_SSL_BUFSIZE_OUTPUT)

/* Protocol versions */
#define BR_SSL30   0x0300
#define BR_TLS10   0x0301
#define BR_TLS11   0x0302
#define BR_TLS12   0x0303

/* Error constants */
#define BR_ERR_OK                      0
#define BR_ERR_BAD_PARAM               1
#define BR_ERR_BAD_STATE               2
#define BR_ERR_UNSUPPORTED_VERSION     3
#define BR_ERR_BAD_VERSION             4
#define BR_ERR_BAD_LENGTH              5
#define BR_ERR_TOO_LARGE               6
#define BR_ERR_BAD_MAC                 7
#define BR_ERR_NO_RANDOM               8
#define BR_ERR_UNKNOWN_TYPE            9
#define BR_ERR_UNEXPECTED              10

/* Engine state flags */
#define BR_SSL_CLOSED      0x0001
#define BR_SSL_SENDREC     0x0002
#define BR_SSL_RECVREC     0x0004
#define BR_SSL_SENDAPP     0x0008
#define BR_SSL_RECVAPP     0x0010

/* Forward declarations */
typedef struct br_ssl_session_parameters_ br_ssl_session_parameters;
typedef struct br_ssl_engine_context_ br_ssl_engine_context;
typedef struct br_ssl_client_context_ br_ssl_client_context;

/* Session parameters structure */
struct br_ssl_session_parameters_ {
    unsigned char session_id[32];
    unsigned char session_id_len;
    uint16_t version;
    uint16_t cipher_suite;
    unsigned char master_secret[48];
};

/* SSL engine context (core of both client and server) */
struct br_ssl_engine_context_ {
    /* Buffer management */
    unsigned char *ibuf, *obuf;
    size_t ibuf_len, obuf_len;
    
    /* Session state */
    br_ssl_session_parameters session;
    
    /* Handshake data */
    unsigned char pre_master_secret[48];
    unsigned char *certificate_data;
    size_t certificate_len;
    
    /* Random values from handshake */
    unsigned char client_random[32];
    unsigned char server_random[32];
    size_t client_random_len;
    size_t server_random_len;
    
    /* Protocol state */
    unsigned version_min;
    unsigned version_max; 
    unsigned version_out;
    unsigned reneg;
    
    /* Server name for SNI */
    char server_name[255];
    
    /* Current state */
    unsigned state;
    int last_error;
    
    /* Handshake functions */
    void (*hs_init)(br_ssl_engine_context *eng);
    void (*hs_run)(br_ssl_engine_context *eng);
    
    /* Record processing */
    unsigned char *record_buf;
    size_t record_len;
    size_t record_ptr;
    
    /* Crypto context placeholder */
    void *crypto_ctx;
};

/* SSL client context */
struct br_ssl_client_context_ {
    /* The encapsulated engine context (MUST be first) */
    br_ssl_engine_context eng;
    
    /* Client-specific configuration */
    uint16_t min_clienthello_len;
    uint32_t hashes;
    int server_curve;
    unsigned char auth_type;
    unsigned char hash_id;
};

/* Core engine functions */
void br_ssl_engine_set_buffer(br_ssl_engine_context *cc,
    void *iobuf, size_t iobuf_len, int bidi);

int br_ssl_engine_last_error(const br_ssl_engine_context *cc);
unsigned br_ssl_engine_current_state(const br_ssl_engine_context *cc);
void br_ssl_engine_fail(br_ssl_engine_context *cc, int err);

/* Client functions */
void br_ssl_client_zero(br_ssl_client_context *cc);
int br_ssl_client_reset(br_ssl_client_context *cc,
    const char *server_name, int resume_session);

/* Simple initialization (no certificate validation) */
void br_ssl_client_init_minimal(br_ssl_client_context *cc);

/* Minimal handshake implementation */
int br_ssl_handshake_client(br_ssl_client_context *cc,
                           int (*sock_write)(int fd, const void *data, size_t len),
                           int (*sock_read)(int fd, void *data, size_t len),
                           int socket_fd);

/* TLS record layer functions */
int br_ssl_record_init_cbc(const unsigned char *client_write_mac_key,
                          const unsigned char *server_write_mac_key,
                          const unsigned char *client_write_key,
                          const unsigned char *server_write_key,
                          const unsigned char *client_write_iv,
                          const unsigned char *server_write_iv);

int br_ssl_record_send_data(int socket_fd, const unsigned char *data, size_t data_len,
                           int (*sock_write)(int fd, const void *data, size_t len));

int br_ssl_record_recv_data(int socket_fd, unsigned char *data, size_t max_len,
                           int (*sock_read)(int fd, void *data, size_t len));

int br_ssl_record_encrypt_cbc(int record_type, const unsigned char *plaintext, 
                             size_t plaintext_len, unsigned char *output, 
                             size_t *output_len);

/* TLS PRF functions */
void br_tls10_prf(void *dst, size_t len,
                 const void *secret, size_t secret_len,
                 const char *label,
                 const void *seed, size_t seed_len);

int br_ssl_derive_keys(const unsigned char master_secret[48],
                      const unsigned char client_random[32],
                      const unsigned char server_random[32],
                      unsigned char *client_write_mac_key,
                      unsigned char *server_write_mac_key,
                      unsigned char *client_write_key,
                      unsigned char *server_write_key,
                      unsigned char *client_write_iv,
                      unsigned char *server_write_iv);

int br_ssl_compute_master_secret(const unsigned char *pre_master_secret, size_t pms_len,
                                const unsigned char client_random[32],
                                const unsigned char server_random[32],
                                unsigned char master_secret[48]);

/* Master secret derivation (BearSSL compatible) */
void br_ssl_engine_compute_master(br_ssl_client_context *cc, const void *pms, size_t pms_len);

#ifdef __cplusplus
}
#endif

#endif
