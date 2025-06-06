#include "retrossl_ssl.h"
#include "retrossl_inner.h"

/* External functions from ssl_engine.c */
extern void br_ssl_engine_hs_reset(br_ssl_engine_context *cc,
    void (*hs_init)(br_ssl_engine_context *),
    void (*hs_run)(br_ssl_engine_context *));
extern int br_ssl_engine_init_rand(br_ssl_engine_context *cc);
extern void br_ssl_hs_client_init_main(br_ssl_engine_context *eng);
extern void br_ssl_hs_client_run(br_ssl_engine_context *eng);

/* Internal function */
static void
br_ssl_client_forget_session(br_ssl_client_context *cc)
{
    memset(&cc->eng.session, 0, sizeof cc->eng.session);
}

/* see retrossl_ssl.h */
void
br_ssl_client_zero(br_ssl_client_context *cc)
{
    /*
     * For really standard C, we should explicitly set to NULL all
     * pointers, and 0 all other fields. However, on all our target
     * architectures, a direct memset() will work, be faster, and
     * use a lot less code.
     */
    memset(cc, 0, sizeof *cc);
}

/* see retrossl_ssl.h */
int
br_ssl_client_reset(br_ssl_client_context *cc,
    const char *server_name, int resume_session)
{
    size_t n;

    br_ssl_engine_set_buffer(&cc->eng, NULL, 0, 0);
    cc->eng.version_out = cc->eng.version_min;
    if (!resume_session) {
        br_ssl_client_forget_session(cc);
    }
    if (!br_ssl_engine_init_rand(&cc->eng)) {
        return 0;
    }

    /*
     * We always set back the "reneg" flag to 0 because we use it
     * to distinguish between first handshake and renegotiation.
     * Note that "renegotiation" and "session resumption" are two
     * different things.
     */
    cc->eng.reneg = 0;

    if (server_name == NULL) {
        cc->eng.server_name[0] = 0;
    } else {
        n = strlen(server_name) + 1;
        if (n > sizeof cc->eng.server_name) {
            br_ssl_engine_fail(&cc->eng, BR_ERR_BAD_PARAM);
            return 0;
        }
        memcpy(cc->eng.server_name, server_name, n);
    }

    br_ssl_engine_hs_reset(&cc->eng,
        br_ssl_hs_client_init_main, br_ssl_hs_client_run);
    return br_ssl_engine_last_error(&cc->eng) == BR_ERR_OK;
}

/* see retrossl_ssl.h */
void
br_ssl_client_init_minimal(br_ssl_client_context *cc)
{
    /* Zero the entire context */
    br_ssl_client_zero(cc);
    
    /* Set up minimal client configuration */
    cc->eng.version_min = BR_TLS10;
    cc->eng.version_max = BR_TLS12;
    cc->eng.version_out = BR_TLS10;
    
    /* No certificate validation (insecure but minimal) */
    cc->min_clienthello_len = 0;
    cc->hashes = 0;
    cc->server_curve = 0;
    cc->auth_type = 0;
    cc->hash_id = 0;
    
    /* Initialize state */
    cc->eng.state = 0;
    cc->eng.last_error = BR_ERR_OK;
}
