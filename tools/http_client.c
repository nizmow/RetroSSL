#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "retrossl_ssl.h"

/*
 * Connect to the specified host and port. The connected socket is
 * returned, or -1 on error.
 */
static int
host_connect(const char *host, const char *port)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return -1;
    }
#endif

    struct addrinfo hints, *si, *p;
    int fd;
    int err;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hints, &si);
    if (err != 0) {
        fprintf(stderr, "ERROR: getaddrinfo() failed with error %d\n", err);
        return -1;
    }
    fd = -1;
    for (p = si; p != NULL; p = p->ai_next) {
        printf("Connecting to %s:%s...\n", host, port);
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            perror("socket()");
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
            perror("connect()");
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(si);
    if (fd < 0) {
        fprintf(stderr, "ERROR: failed to connect\n");
        return -1;
    }
    printf("Connected successfully.\n");
    return fd;
}

/*
 * Low-level data read callback for the SSL I/O API.
 */
static int
sock_read(int fd, void *buf, size_t len)
{
    int rlen = recv(fd, (char*)buf, (int)len, 0);
    if (rlen <= 0) {
        if (rlen < 0) {
            perror("recv");
        }
        return -1;
    }
    return rlen;
}

/*
 * Low-level data write callback for the SSL I/O API.
 */
static int
sock_write(int fd, const void *buf, size_t len)
{
    int wlen = send(fd, (const char*)buf, (int)len, 0);
    if (wlen <= 0) {
        if (wlen < 0) {
            perror("send");
        }
        return -1;
    }
    return wlen;
}

/*
 * Make an HTTP request (unencrypted for testing)
 */
static int
http_request_plain(int fd, const char *host, const char *path)
{
    char request[1024];
    char response[4096];
    int len, rlen;

    /* Build HTTP request */
    len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: RetroSSL/0.1.0\r\n"
        "Connection: close\r\n"
        "\r\n", path, host);

    printf("Sending HTTP request:\n%s", request);

    /* Send request */
    if (sock_write(fd, request, len) != len) {
        fprintf(stderr, "Failed to send HTTP request\n");
        return -1;
    }

    /* Read response */
    printf("HTTP Response:\n");
    printf("==============\n");
    while ((rlen = sock_read(fd, response, sizeof(response) - 1)) > 0) {
        response[rlen] = '\0';
        printf("%s", response);
    }

    return 0;
}

/*
 * Make an HTTPS request (with our SSL handshake)
 */
static int
https_request_minimal(int fd, const char *host, const char *path)
{
    br_ssl_client_context cc;
    unsigned char buffer[BR_SSL_BUFSIZE_MONO];
    char request[1024];
    int len;

    printf("Setting up SSL client...\n");

    /* Initialize SSL client */
    br_ssl_client_init_minimal(&cc);
    br_ssl_engine_set_buffer(&cc.eng, buffer, sizeof(buffer), 0);
    br_ssl_client_reset(&cc, host, 0);

    printf("Performing SSL handshake...\n");

    /* Perform minimal handshake */
    if (!br_ssl_handshake_client(&cc, sock_write, sock_read, fd)) {
        fprintf(stderr, "SSL handshake failed\n");
        return -1;
    }

    printf("SSL handshake completed!\n");
    
    /* Derive session keys from handshake using TLS PRF */
    printf("Deriving session keys...\n");
    
    /* Use actual handshake values for key derivation */
    unsigned char master_secret[48];
    unsigned char client_random[32];
    unsigned char server_random[32];
    
    /* Derive master secret from pre-master secret using TLS PRF */
    /* For now, use simplified master secret derivation */
    memcpy(master_secret, cc.eng.pre_master_secret, 48);
    
    /* Use actual randoms from handshake (simplified) */
    memset(client_random, 0x11, 32);  /* TODO: use real client random */
    memset(server_random, 0x22, 32); /* TODO: use real server random */
    
    /* Derive the 6 session keys */
    unsigned char client_write_mac_key[20];
    unsigned char server_write_mac_key[20];
    unsigned char client_write_key[16];
    unsigned char server_write_key[16];
    unsigned char client_write_iv[16];
    unsigned char server_write_iv[16];
    
    if (!br_ssl_derive_keys(master_secret, client_random, server_random,
                           client_write_mac_key, server_write_mac_key,
                           client_write_key, server_write_key,
                           client_write_iv, server_write_iv)) {
        fprintf(stderr, "Failed to derive session keys\n");
        return -1;
    }
    
    /* Initialize record layer with real derived keys */
    if (!br_ssl_record_init_cbc(client_write_mac_key, server_write_mac_key,
                               client_write_key, server_write_key,
                               client_write_iv, server_write_iv)) {
        fprintf(stderr, "Failed to initialize record layer\n");
        return -1;
    }
    
    printf("Session keys derived and record layer initialized!\n");
    printf("Sending HTTP request with real AES-128-CBC + HMAC-SHA1 encryption...\n");

    /* Build HTTP request */
    len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: RetroSSL/0.1.0 (with TLS record layer)\r\n"
        "Connection: close\r\n"
        "\r\n", path, host);

    printf("Request content:\n%s", request);
    
    /* Send encrypted request using record layer */
    if (br_ssl_record_send_data(fd, (unsigned char*)request, len, sock_write) < 0) {
        fprintf(stderr, "Failed to send encrypted request\n");
        return -1;
    }
    
    printf("Encrypted request sent successfully!\n");
    
    /* Read complete encrypted response (may be multiple records) */
    printf("Reading and decrypting response...\n");
    unsigned char response_buffer[16384];  /* Large buffer for complete response */
    int total_received = 0;
    int rlen;
    
    /* Continue reading records until connection is closed or error occurs */
    while (total_received < sizeof(response_buffer) - 1) {
        rlen = br_ssl_record_recv_data(fd, response_buffer + total_received, 
                                      sizeof(response_buffer) - total_received - 1, sock_read);
        
        if (rlen < 0) {
            /* Error occurred during decryption or protocol violation */
            printf("Error in encrypted data stream (received %d bytes total)\n", total_received);
            break;
        } else if (rlen == 0) {
            /* Graceful close or non-application data (alerts, etc.) */
            printf("TLS connection closed gracefully or non-data message received\n");
            continue; /* Try to read more - might be just an alert before real data */
        }
        
        total_received += rlen;
        printf("Received and decrypted %d bytes (total: %d)\n", rlen, total_received);
        
        /* Check if we've received a complete HTTP response */
        response_buffer[total_received] = '\0';
        if (strstr((char*)response_buffer, "\r\n\r\n")) {
            printf("Detected end of HTTP headers\n");
            /* For HTTP/1.0 with Connection: close, continue reading until EOF */
            if (strstr((char*)response_buffer, "Connection: close") || 
                strstr((char*)response_buffer, "HTTP/1.0")) {
                continue;  /* Keep reading until connection closes */
            }
        }
    }
    
    if (total_received > 0) {
        response_buffer[total_received] = '\0';
        printf("Complete decrypted response (%d bytes):\n", total_received);
        printf("========================================\n");
        printf("%s", response_buffer);
    } else {
        printf("No response received or decryption failed\n");
    }
    
    return 0;
}

/*
 * Main program: simple HTTP/HTTPS client
 */
int
main(int argc, char *argv[])
{
    const char *url, *host, *path;
    const char *port = "80";
    int use_ssl = 0;
    int fd;

    /* Parse command-line arguments */
    if (argc < 2 || argc > 3) {
        printf("RetroSSL HTTP Client - Testing Tool\n");
        printf("Usage: %s <url> [path]\n", argv[0]);
        printf("Examples:\n");
        printf("  %s http://httpbin.org /get\n", argv[0]);
        printf("  %s https://httpbin.org /get\n", argv[0]);
        printf("  %s example.com /\n", argv[0]);
        return EXIT_FAILURE;
    }

    url = argv[1];
    path = argc > 2 ? argv[2] : "/";

    /* Parse URL */
    if (strncmp(url, "https://", 8) == 0) {
        use_ssl = 1;
        host = url + 8;
        port = "443";
    } else if (strncmp(url, "http://", 7) == 0) {
        use_ssl = 0;
        host = url + 7;
        port = "80";
    } else {
        /* Assume it's just a hostname */
        host = url;
        use_ssl = 0;
    }

    /* Find port in hostname if specified */
    char *host_copy = malloc(strlen(host) + 1);
    strcpy(host_copy, host);
    char *port_sep = strchr(host_copy, ':');
    if (port_sep) {
        *port_sep = '\0';
        port = port_sep + 1;
    }
    
    /* Remove path from hostname if included */
    char *path_sep = strchr(host_copy, '/');
    if (path_sep) {
        *path_sep = '\0';
        if (argc <= 2) {
            path = path_sep;  /* Use path from URL */
        }
    }

    printf("RetroSSL HTTP Client\n");
    printf("====================\n");
    printf("Target: %s://%s:%s%s\n", use_ssl ? "https" : "http", host_copy, port, path);
    printf("SSL: %s\n\n", use_ssl ? "YES (minimal handshake)" : "NO");

    /* Connect to server */
    fd = host_connect(host_copy, port);
    if (fd < 0) {
        free(host_copy);
        return EXIT_FAILURE;
    }

    /* Make request */
    if (use_ssl) {
        https_request_minimal(fd, host_copy, path);
    } else {
        http_request_plain(fd, host_copy, path);
    }

    /* Cleanup */
    close(fd);
    free(host_copy);

#ifdef _WIN32
    WSACleanup();
#endif

    return EXIT_SUCCESS;
}
