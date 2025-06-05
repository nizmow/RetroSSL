# BearSSL to RetroSSL Source Mapping

This document maintains the 1:1 mapping between BearSSL source files and RetroSSL ports to enable easy tracking of upstream changes and updates.

## Reference Version
- **BearSSL Commit**: `3c04036`
- **BearSSL Repository**: https://www.bearssl.org/git/BearSSL
- **Last Mapping Update**: June 2025

## File Mapping Table

### Hash Functions ✅ PORTED
| RetroSSL | BearSSL | Status | Notes |
|----------|---------|--------|-------|
| `src/hash/md5.c` | `temp/bearssl-analysis/src/hash/md5.c` | ✅ Complete | Vtable adapted for br_hash_class |
| `src/hash/sha1.c` | `temp/bearssl-analysis/src/hash/sha1.c` | ✅ Complete | Vtable adapted for br_hash_class |
| `include/retrossl_hash.h` | `temp/bearssl-analysis/inc/bearssl_hash.h` | ✅ Complete | Win98/Open Watcom adapted |

### Symmetric Crypto (AES) ✅ PORTED  
| RetroSSL | BearSSL | Status | Notes |
|----------|---------|--------|-------|
| `src/crypto/aes_common.c` | `temp/bearssl-analysis/src/symcipher/aes_ct.c` | ✅ Complete | S-box table + key schedule |
| `src/crypto/aes_small_enc.c` | `temp/bearssl-analysis/src/symcipher/aes_small_enc.c` | ✅ Complete | Small table encryption |
| `src/crypto/aes_small_dec.c` | `temp/bearssl-analysis/src/symcipher/aes_small_dec.c` | ✅ Complete | Small table decryption |
| `src/crypto/aes_small_cbcenc.c` | `temp/bearssl-analysis/src/symcipher/aes_small_cbcenc.c` | ✅ Complete | CBC encryption wrapper |
| `src/crypto/aes_small_cbcdec.c` | `temp/bearssl-analysis/src/symcipher/aes_small_cbcdec.c` | ✅ Complete | CBC decryption wrapper |
| `include/retrossl_block.h` | `temp/bearssl-analysis/inc/bearssl_block.h` | ✅ Complete | Win98/Open Watcom adapted |

### Codec Utilities ✅ PORTED
| RetroSSL | BearSSL | Status | Notes |
|----------|---------|--------|-------|
| `src/codec.c` | `temp/bearssl-analysis/src/codec/` (various) | ✅ Complete | Combined endian conversion functions |
| `src/retrossl_inner.h` | `temp/bearssl-analysis/src/inner.h` | 🔧 Partial | Core functions, codec macros added |

### RSA (Asymmetric Crypto) 🔄 PLANNED
| RetroSSL | BearSSL | Status | Notes |
|----------|---------|--------|-------|
| `src/rsa/` (TBD) | `temp/bearssl-analysis/src/rsa/rsa_i32_*.c` | 📋 TODO | 32-bit RSA implementation for Win98 |

### SSL/TLS Protocol Engine 🔄 PLANNED  
| RetroSSL | BearSSL | Status | Notes |
|----------|---------|--------|-------|
| `src/ssl/` (TBD) | `temp/bearssl-analysis/src/ssl/` | 📋 TODO | Core SSL engine |

### X.509 Certificate Support 🔄 PLANNED
| RetroSSL | BearSSL | Status | Notes |
|----------|---------|--------|-------|
| `src/x509/` (TBD) | `temp/bearssl-analysis/src/x509/` | 📋 TODO | Certificate parsing |

## Adaptation Notes

### Common Adaptations Applied
1. **Headers**: `#include "bearssl.h"` → `#include "../include/retrossl_*.h"`
2. **Function Prefixes**: `br_*` functions kept for compatibility via `#define` aliases
3. **Vtables**: Updated to match exact `br_hash_class` structure specifications
4. **Memory Models**: Adapted for Open Watcom 32-bit compilation
5. **Win98 Compatibility**: Added `#ifdef WIN32` guards where needed

### Key Differences from BearSSL
- **Build System**: Custom `build.sh` instead of Makefile (Open Watcom specific)
- **Headers**: Split into focused headers (`retrossl_hash.h`, `retrossl_block.h`)
- **Codec Functions**: Consolidated into single `codec.c` file with inline helpers
- **Test Structure**: Individual test files per component for incremental validation

## Update Procedure

When updating from newer BearSSL versions:

1. **Check Reference Version**: Update BearSSL commit in `setup_dependencies.sh`
2. **Compare Files**: Use this mapping table to identify changed source files
3. **Apply Diffs**: Port relevant changes while preserving Win98/Open Watcom adaptations  
4. **Test Build**: Ensure `./build.sh` still works with unified builds
5. **Update Mapping**: Update this file with any new/changed mappings

## File Header Template

For future ported files, use this header template:

```c
/*
 * RetroSSL [Component] for Windows 98 SE
 * 
 * Based on BearSSL [original_file.c] (commit 3c04036)
 * Source: temp/bearssl-analysis/src/[path]/[original_file.c]
 * 
 * Adaptations for Open Watcom and Win98:
 * - [List key changes made]
 * 
 * Copyright (c) 2025 RetroSSL Project
 * Original BearSSL code: Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 */
```

## Version History
- **June 2025**: Initial mapping document created
- **June 2025**: Hash functions and AES crypto ported and working
- **June 2025**: Vtable conflicts resolved, unified builds working

---
*This mapping enables easy synchronization with BearSSL updates while maintaining Win98 compatibility.*
