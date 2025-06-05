# RetroSSL Porting Strategy

## Project Structure

Based on BearSSL analysis, our incremental porting structure:

```
RetroSSL/
├── src/
│   ├── hash/        # Hash functions (MD5, SHA1, SHA256)
│   ├── crypto/      # Symmetric crypto (AES, DES) 
│   ├── ssl/         # SSL/TLS protocol engine
│   └── x509/        # Certificate parsing
├── include/         # Win98-adapted headers
├── dll/             # DLL export definitions and Win98 interface
├── tests/           # Incremental test programs
└── tools/           # Build and test utilities
```

## BearSSL Analysis Results

### ✅ **Excellent Structure for Incremental Porting**

**Key Components Identified:**
- **Hash Functions**: `src/hash/` (MD5, SHA1, SHA256, SHA512)
- **Symmetric Crypto**: `src/symcipher/` (AES variants, DES, ChaCha20)
- **Asymmetric Crypto**: `src/rsa/`, `src/ec/` (RSA, ECDSA)
- **SSL Engine**: `src/ssl/` (handshake, record layer)
- **X.509 Support**: `src/x509/` (certificate parsing)

**Build System**: Simple Makefile-based, easy to adapt for Open Watcom

### 🎯 **Minimal Components for Win98 DLL**

**Phase 1: Basic Crypto (Start Here)**
```
1. Hash functions: SHA1, MD5 (for older SSL compatibility)
2. AES implementation: aes_small_* (optimized for size)
3. RSA: rsa_i31_* (good balance of speed/size for 32-bit)
```

**Phase 2: SSL Essentials**
```
1. SSL engine core: ssl_engine.c, ssl_io.c
2. Handshake: ssl_hs_client.c (client support first)  
3. Record layer: ssl_rec_cbc.c (basic CBC mode)
```

**Phase 3: Certificate Support**
```
1. X.509 minimal: x509_minimal.c
2. Certificate decoder: x509_decoder.c
3. Known key support: x509_knownkey.c
```

## File-by-File Porting Plan

### Start with Foundation (Week 1)
1. **Copy and adapt headers**: `inc/bearssl_hash.h` → `include/retrossl_hash.h`
2. **Basic hash**: `src/hash/sha1.c` → `src/hash/sha1.c`
3. **Test compilation**: Create simple hash test
4. **Fix Win98/OpenWatcom issues**: stdint, calling conventions, etc.

### Add Symmetric Crypto (Week 2)  
1. **AES small**: `src/symcipher/aes_small_*.c`
2. **AES CBC**: `src/symcipher/aes_*_cbc*.c` 
3. **Test symmetric operations**: Encrypt/decrypt test

### RSA Support (Week 3)
1. **Integer math**: `src/int/i31_*.c` (32-bit optimized)
2. **RSA operations**: `src/rsa/rsa_i31_*.c`
3. **Test key operations**: Generate, sign, verify

### SSL Protocol (Week 4-5)
1. **SSL engine core**: `src/ssl/ssl_engine.c`
2. **Client handshake**: `src/ssl/ssl_hs_client.c`
3. **I/O layer**: `src/ssl/ssl_io.c`
4. **Record processing**: `src/ssl/ssl_rec_cbc.c`

### DLL Integration (Week 6)
1. **Win98 DLL exports**: Create DEF file
2. **Calling conventions**: Ensure proper stdcall/cdecl
3. **Memory management**: DLL-safe allocation
4. **Test applications**: Simple client/server

## Win98-Specific Adaptations Needed

### 1. Calling Conventions
```c
// Add Win98 DLL exports
#define RETROSSL_API __declspec(dllexport) __stdcall
```

### 2. Memory Constraints
```c
// Reduce buffer sizes for Win98 memory limits
#define BR_SSL_BUFSIZE_MONO 4096  // vs 16384 default
```

### 3. Integer Types
```c
// Ensure compatibility with Open Watcom stdint
#include <stdint.h>  // Confirmed available
```

### 4. Network Interface
```c
// Use Winsock 1.1 compatible calls
#include <winsock.h>  // Not winsock2.h
```

## Success Metrics

**Phase 1**: Hash function compiles and passes basic tests
**Phase 2**: AES encryption/decryption works  
**Phase 3**: RSA key operations functional
**Phase 4**: SSL handshake completes with test server
**Phase 5**: Win98 DLL exports and loads properly

## File Copy Priority List

**BearSSL Source Location**: All source files referenced below are in `bearssl-analysis/`

**Immediate (Start Today):**
```
bearssl-analysis/inc/bearssl_hash.h       → include/retrossl_hash.h
bearssl-analysis/src/hash/sha1.c         → src/hash/sha1.c  
bearssl-analysis/src/hash/md5.c          → src/hash/md5.c
```

**Next (Week 1):**
```
bearssl-analysis/src/symcipher/aes_small_enc.c     → src/crypto/aes_small_enc.c
bearssl-analysis/src/symcipher/aes_small_dec.c     → src/crypto/aes_small_dec.c
bearssl-analysis/src/symcipher/aes_small_cbcenc.c  → src/crypto/aes_small_cbcenc.c
```

This incremental approach lets us validate each component works with Open Watcom before proceeding to the next layer.