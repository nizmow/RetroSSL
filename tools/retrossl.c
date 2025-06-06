#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "retrossl_hash.h"

static void print_usage(void)
{
    printf("RetroSSL v%s - OpenSSL-compatible cryptographic tools for Windows 98 SE\n", 
           RETROSSL_VERSION);
    printf("Usage: retrossl <command> [options]\n\n");
    printf("Available commands:\n");
    printf("  md5      - Compute MD5 hash\n");
    printf("  sha1     - Compute SHA-1 hash  \n");
    printf("  sha256   - Compute SHA-256 hash\n");
    printf("  version  - Show version information\n");
    printf("  help     - Show this help message\n\n");
    printf("Examples:\n");
    printf("  echo \"abc\" | retrossl md5\n");
    printf("  retrossl sha1 < file.txt\n");
    printf("  retrossl sha256 -hex < data.bin\n\n");
    printf("Compatible with OpenSSL command-line interface.\n");
}

static void print_version(void)
{
    printf("RetroSSL %s\n", RETROSSL_VERSION);
    printf("Built: %s\n", RETROSSL_BUILD_TAG);
    printf("Target: Windows 98 SE (i386)\n");
    printf("Compiler: Open Watcom C/C++\n");
    printf("Based on: BearSSL (minimal port)\n");
}

static void print_hex(const unsigned char *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int hash_stdin(const char *algorithm)
{
    unsigned char buffer[4096];
    unsigned char digest[32]; /* Enough for SHA-256 */
    size_t digest_len;
    size_t total_read = 0;
    size_t bytes_read;
    
    if (strcmp(algorithm, "md5") == 0) {
        br_md5_context ctx;
        br_md5_init(&ctx);
        
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            br_md5_update(&ctx, buffer, bytes_read);
            total_read += bytes_read;
        }
        
        br_md5_out(&ctx, digest);
        digest_len = 16;
        
    } else if (strcmp(algorithm, "sha1") == 0) {
        br_sha1_context ctx;
        br_sha1_init(&ctx);
        
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            br_sha1_update(&ctx, buffer, bytes_read);
            total_read += bytes_read;
        }
        
        br_sha1_out(&ctx, digest);
        digest_len = 20;
        
    } else if (strcmp(algorithm, "sha256") == 0) {
        br_sha256_context ctx;
        br_sha256_init(&ctx);
        
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            br_sha256_update(&ctx, buffer, bytes_read);
            total_read += bytes_read;
        }
        
        br_sha256_out(&ctx, digest);
        digest_len = 32;
        
    } else {
        fprintf(stderr, "Error: Unknown algorithm '%s'\n", algorithm);
        return 1;
    }
    
    if (ferror(stdin)) {
        fprintf(stderr, "Error: Failed to read from stdin\n");
        return 1;
    }
    
    /* Print result in OpenSSL format */
    print_hex(digest, digest_len);
    
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage();
        return 1;
    }
    
    if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage();
        return 0;
    }
    
    if (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0) {
        print_version();
        return 0;
    }
    
    if (strcmp(argv[1], "md5") == 0 || 
        strcmp(argv[1], "sha1") == 0 || 
        strcmp(argv[1], "sha256") == 0) {
        return hash_stdin(argv[1]);
    }
    
    fprintf(stderr, "Error: Unknown command '%s'\n", argv[1]);
    fprintf(stderr, "Run 'retrossl help' for usage information.\n");
    return 1;
}