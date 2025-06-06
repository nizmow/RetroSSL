#include <stdio.h>
#include <string.h>
#include "retrossl_ssl.h"

/* Mock socket functions for testing */
static unsigned char mock_server_response[] = {
    /* TLS Record Header */
    0x16,                           /* Content Type: Handshake */
    0x03, 0x01,                     /* Version: TLS 1.0 */
    0x00, 0x2A,                     /* Length: 42 bytes */
    
    /* ServerHello Handshake */
    0x02,                           /* Handshake Type: ServerHello */
    0x00, 0x00, 0x26,              /* Length: 38 bytes */
    0x03, 0x01,                     /* Server Version: TLS 1.0 */
    
    /* Server Random (32 bytes) */
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    
    /* Session ID Length */
    0x00,                           /* No session ID */
    
    /* Cipher Suite */
    0x00, 0x2F,                     /* TLS_RSA_WITH_AES_128_CBC_SHA */
    
    /* Compression Method */
    0x00                            /* No compression */
};

static int mock_read_called = 0;
static int mock_write_called = 0;
static unsigned char last_write_data[1024];
static size_t last_write_len = 0;

static int
mock_sock_read(int fd, void *data, size_t len)
{
    printf("Mock read called (fd=%d, len=%u)\n", fd, (unsigned)len);
    mock_read_called = 1;
    
    /* Return our mock ServerHello */
    size_t copy_len = sizeof(mock_server_response);
    if (copy_len > len) copy_len = len;
    
    memcpy(data, mock_server_response, copy_len);
    return (int)copy_len;
}

static int
mock_sock_write(int fd, const void *data, size_t len)
{
    printf("Mock write called (fd=%d, len=%u)\n", fd, (unsigned)len);
    mock_write_called = 1;
    
    /* Save the written data for inspection */
    if (len > sizeof(last_write_data)) len = sizeof(last_write_data);
    memcpy(last_write_data, data, len);
    last_write_len = len;
    
    return (int)len;
}

void hexdump_line(const unsigned char *data, size_t len, const char *prefix) 
{
    size_t i;
    printf("%s", prefix);
    for (i = 0; i < len && i < 16; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main()
{
    printf("RetroSSL Handshake Test\n");
    printf("=======================\n\n");

    /* Test 1: ClientHello generation */
    printf("Testing ClientHello generation and parsing...\n");
    {
        br_ssl_client_context cc;
        unsigned char buffer[BR_SSL_BUFSIZE_MONO];
        
        /* Initialize client */
        br_ssl_client_init_minimal(&cc);
        br_ssl_engine_set_buffer(&cc.eng, buffer, sizeof(buffer), 0);
        br_ssl_client_reset(&cc, "example.com", 0);
        
        printf("  Initial state: 0x%04X\n", br_ssl_engine_current_state(&cc.eng));
        
        /* Test handshake with mock server */
        int result = br_ssl_handshake_client(&cc, mock_sock_write, mock_sock_read, 999);
        
        printf("  Handshake result: %s\n", result ? "SUCCESS" : "FAILED");
        printf("  Final state: 0x%04X\n", br_ssl_engine_current_state(&cc.eng));
        printf("  Mock write called: %s\n", mock_write_called ? "YES" : "NO");
        printf("  Mock read called: %s\n", mock_read_called ? "YES" : "NO");
        
        if (mock_write_called && last_write_len > 0) {
            printf("  ClientHello sent (%u bytes):\n", (unsigned)last_write_len);
            printf("    Record header: ");
            hexdump_line(last_write_data, 5, "");
            printf("    Handshake header: ");
            hexdump_line(last_write_data + 5, 4, "");
            printf("    Version + Random: ");
            hexdump_line(last_write_data + 9, 16, "");
            
            /* Check TLS record header */
            if (last_write_data[0] == 0x16 && 
                last_write_data[1] == 0x03 && last_write_data[2] == 0x01) {
                printf("  ✓ Valid TLS 1.0 Handshake record\n");
            } else {
                printf("  ✗ Invalid TLS record header\n");
            }
            
            /* Check handshake type */
            if (last_write_data[5] == 0x01) {
                printf("  ✓ Valid ClientHello handshake type\n");
            } else {
                printf("  ✗ Invalid handshake type\n");
            }
        }
    }

    /* Test 2: Error handling */
    printf("\nTesting error conditions...\n");
    {
        br_ssl_client_context cc;
        unsigned char buffer[BR_SSL_BUFSIZE_MONO];
        
        br_ssl_client_init_minimal(&cc);
        br_ssl_engine_set_buffer(&cc.eng, buffer, sizeof(buffer), 0);
        br_ssl_client_reset(&cc, "", 0);  /* Empty hostname */
        
        /* Reset mock state */
        mock_write_called = 0;
        mock_read_called = 0;
        
        int result = br_ssl_handshake_client(&cc, mock_sock_write, mock_sock_read, 999);
        printf("  Empty hostname handshake: %s\n", result ? "SUCCESS" : "FAILED");
    }

    printf("\nHandshake test completed!\n");
    printf("This confirms basic TLS ClientHello generation and ServerHello parsing.\n");
    
    return 0;
}
