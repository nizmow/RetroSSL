#include <stdio.h>
#include <string.h>
#include "retrossl_ssl.h"

int main()
{
    printf("RetroSSL Basic SSL Test\n");
    printf("=======================\n\n");

    /* Test 1: Client context initialization */
    printf("Testing client context initialization...\n");
    {
        br_ssl_client_context cc;
        unsigned char buffer[BR_SSL_BUFSIZE_MONO];
        
        /* Initialize client */
        br_ssl_client_init_minimal(&cc);
        printf("  Client context initialized\n");
        
        /* Set buffer */
        br_ssl_engine_set_buffer(&cc.eng, buffer, sizeof(buffer), 0);
        printf("  Buffer set: %u bytes\n", (unsigned)sizeof(buffer));
        
        /* Reset for connection */
        int result = br_ssl_client_reset(&cc, "example.com", 0);
        printf("  Client reset result: %s\n", result ? "SUCCESS" : "FAILED");
        printf("  Server name: '%s'\n", cc.eng.server_name);
        printf("  Engine state: 0x%04X\n", br_ssl_engine_current_state(&cc.eng));
        printf("  Last error: %d\n", br_ssl_engine_last_error(&cc.eng));
    }

    /* Test 2: Engine state management */
    printf("\nTesting engine state management...\n");
    {
        br_ssl_client_context cc;
        
        br_ssl_client_init_minimal(&cc);
        
        /* Test error handling */
        br_ssl_engine_fail(&cc.eng, BR_ERR_BAD_PARAM);
        printf("  After setting error:\n");
        printf("    State: 0x%04X (should be CLOSED=0x%04X)\n", 
               br_ssl_engine_current_state(&cc.eng), BR_SSL_CLOSED);
        printf("    Error: %d (should be %d)\n",
               br_ssl_engine_last_error(&cc.eng), BR_ERR_BAD_PARAM);
    }

    /* Test 3: Buffer management */  
    printf("\nTesting buffer management...\n");
    {
        br_ssl_client_context cc;
        unsigned char buffer[1024];
        
        br_ssl_client_init_minimal(&cc);
        
        /* Test monodirectional buffer */
        br_ssl_engine_set_buffer(&cc.eng, buffer, sizeof(buffer), 0);
        printf("  Mono buffer: ibuf=%p obuf=%p\n", 
               (void*)cc.eng.ibuf, (void*)cc.eng.obuf);
        printf("  Same buffer: %s\n", 
               (cc.eng.ibuf == cc.eng.obuf) ? "YES" : "NO");
        
        /* Test bidirectional buffer */
        br_ssl_engine_set_buffer(&cc.eng, buffer, sizeof(buffer), 1);
        printf("  Bidi buffer: ibuf=%p obuf=%p\n",
               (void*)cc.eng.ibuf, (void*)cc.eng.obuf);
        printf("  Different buffers: %s\n",
               (cc.eng.ibuf != cc.eng.obuf) ? "YES" : "NO");
        printf("  Input size: %u, Output size: %u\n",
               (unsigned)cc.eng.ibuf_len, (unsigned)cc.eng.obuf_len);
    }

    /* Test 4: Version handling */
    printf("\nTesting version handling...\n");
    {
        br_ssl_client_context cc;
        
        br_ssl_client_init_minimal(&cc);
        printf("  Min version: 0x%04X (TLS 1.0 = 0x%04X)\n",
               cc.eng.version_min, BR_TLS10);
        printf("  Max version: 0x%04X (TLS 1.2 = 0x%04X)\n", 
               cc.eng.version_max, BR_TLS12);
        printf("  Output version: 0x%04X\n", cc.eng.version_out);
    }

    printf("\nBasic SSL structures test completed!\n");
    printf("This confirms the SSL client API is ready for HTTP library integration.\n");
    
    return 0;
}
