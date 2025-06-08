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
    
    /* Initialize record layer with dummy keys (simplified for now) */
    unsigned char dummy_key[20] = {0};
    if (!br_ssl_record_init_cbc(dummy_key, dummy_key, dummy_key, dummy_key, dummy_key, dummy_key)) {
        fprintf(stderr, "Failed to initialize record layer\n");
        return -1;
    }
    
    printf("Sending encrypted HTTP request over TLS...\n");

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
    
    /* Try to receive encrypted response */
    printf("Reading encrypted response...\n");
    unsigned char response[4096];
    int rlen = br_ssl_record_recv_data(fd, response, sizeof(response) - 1, sock_read);
    if (rlen > 0) {
        response[rlen] = '\0';
        printf("Decrypted response (%d bytes):\n", rlen);
        printf("==================================\n");
        printf("%s", response);
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
