# RetroSSL - Windows 98 SE SSL Library

> **⚠️ EXPERIMENTAL TOY PROJECT ⚠️**  
> AI-generated educational project for exploring cryptography on vintage systems. **NOT FOR PRODUCTION USE!**

An experimental SSL/TLS library for Windows 98 SE, featuring BearSSL porting with Open Watcom cross-compilation.

## Quick Start

```bash
git clone <repository-url>
cd RetroSSL
./setup_dependencies.sh
make all test
```

## Current Status

### ✅ **Working Features**
- **Hash Functions**: SHA1, MD5, SHA256 with test vectors
- **HMAC**: SHA1/SHA256 message authentication (RFC 2202, OpenSSL-compatible)
- **AES-128 CBC**: Symmetric encryption with NIST test vectors
- **RSA**: Complete public key operations with OpenSSL interoperability
- **TLS Handshake**: Complete TLS 1.0 handshake with proper encryption switching
- **TLS PRF**: Complete key derivation (master secret → session keys)
- **TLS Record Layer**: Real AES-128-CBC + HMAC-SHA1 encryption/decryption
- **Certificate Parsing**: Basic DER/ASN.1 parser for RSA public key extraction
- **PKCS#1 Encryption**: Proper RSA encryption with server's real public keys
- **Encrypted Handshake**: Finished messages properly encrypted after ChangeCipherSpec
- **TLS Protocol Handling**: Alert messages, cipher spec changes, multi-record responses
- **HTTP/HTTPS Client**: Can perform complete TLS handshakes with live HTTPS servers
- **Command-Line Tools**: OpenSSL-compatible `retrossl` utility

### 🔧 **Recent Improvements (BearSSL-based)**
- **Real Certificate Parsing**: Extracts actual RSA modulus from server certificates
- **Proper Key Exchange**: PKCS#1 type 2 padding with real server public keys
- **BearSSL Compatibility**: Direct port of BearSSL's encryption switching logic
- **Complete TLS Records**: Handles encrypted application data and protocol messages

## Build System

### **Essential Commands**
```bash
# Development build and test
make all test

# Individual tests  
make test-sha1 test-md5 test-sha256 test-hmac test-aes test-rsa test-ssl test-ssl-handshake test-ssl-prf

# Release with tagging
make release package

# Clean up
make clean
```

### **Key Targets**
- `all` - Build all development executables
- `test` - Run all tests with Wine validation
- `release` - Tagged builds with version/commit info
- `package` - Create distribution tarball
- `sizes` - Show executable sizes

## Directory Structure

```
RetroSSL/
├── src/
│   ├── hash/          # Hash functions (SHA1, MD5, SHA256)
│   ├── mac/           # HMAC implementation
│   ├── crypto/        # AES encryption
│   ├── rsa/           # RSA public key operations
│   ├── int/           # Big integer arithmetic
│   └── ssl/           # TLS handshake and record layer
├── tests/             # Test programs with validation
├── tools/             # Command-line utilities and HTTP client
└── build/
    ├── temp/          # Development builds
    └── release/       # Tagged release artifacts
```

## Features

### **Cryptographic Primitives**
- **Hashes**: SHA1/MD5/SHA256 (RFC compliant)
- **HMAC**: Variable key lengths, OpenSSL-compatible output
- **AES-128 CBC**: NIST validated encrypt/decrypt
- **RSA**: Montgomery arithmetic, constant-time operations
- **TLS**: Complete handshake + key derivation with live HTTPS servers

### **Tools & Testing**
- **retrossl**: OpenSSL-compatible hash commands (`md5`, `sha1`, `sha256`)
- **http_client**: HTTP/HTTPS testing tool with SSL handshake
- **Wine validation**: All tests run on Windows 98 SE compatibility layer
- **OpenSSL interop**: Verified compatibility with real RSA keys

## Testing

```bash
# Run all tests
make test

# Test OpenSSL compatibility
printf "abc" | wine build/temp/retrossl.exe sha256
printf "abc" | openssl sha256
# Both output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

# Test HTTPS handshake + encrypted request sending
wine build/temp/http_client.exe https://httpbin.org /get

# Test TLS key derivation
wine build/temp/test_ssl_prf.exe

# Test OpenSSL HMAC compatibility
wine build/temp/test_hmac_openssl.exe
```

See **[TESTING.md](TESTING.md)** for comprehensive testing procedures.

## Architecture

- **Target**: Windows 98 SE (32-bit x86)
- **Host**: macOS ARM64 cross-compilation  
- **Toolchain**: Open Watcom C/C++ 2.0
- **Reference**: BearSSL implementation
- **Testing**: Wine-based validation

## Dependencies

- Open Watcom C/C++ (cross-compiler)
- Wine (Windows 98 SE testing)
- Make & Git

Run `./setup_dependencies.sh` to install automatically.

## Documentation

- **[TESTING.md](TESTING.md)** - Testing procedures and OpenSSL compatibility
- **[VERSION](VERSION)** - Version and feature tracking
- **[BEARSSL_MAPPING.md](BEARSSL_MAPPING.md)** - Source mapping for upstream
- **[CLAUDE.md](CLAUDE.md)** - AI workflow documentation

## License

Contains code derived from [BearSSL](https://bearssl.org/) by Thomas Pornin (MIT License). See [LICENSE](LICENSE) for details.