# RetroSSL - Windows 98 SE SSL Library

A professional SSL/TLS cryptographic library for Windows 98 SE, featuring systematic BearSSL porting with Open Watcom cross-compilation.

## Quick Start

```bash
git clone <repository-url>
cd RetroSSL
./setup_dependencies.sh
make all test
```

## Current Status

### ✅ **Implemented Cryptographic Primitives**
- **Hash Functions**: SHA1, MD5, SHA256 with full test vectors
- **Message Authentication**: HMAC-SHA1, HMAC-SHA256 (RFC 2202 compliant)
- **Symmetric Encryption**: AES-128 CBC with NIST test vectors
- **Asymmetric Cryptography**: RSA i31 big integer arithmetic (foundation)

### 🔄 **In Development**
- RSA modular exponentiation and public key operations
- SSL/TLS handshake protocol implementation

### 📦 **Release Management**
- **Version**: 0.1.0 (see [VERSION](VERSION) file)
- **Build tagging**: `version-date-time-commit` format
- **Release artifacts**: Tagged executables with MD5 checksums
- **Package creation**: Automated tarball generation

## Build System

### **Development Workflow**
```bash
# Quick development build and test
make dev test

# Individual component testing
make test-sha1 test-md5 test-sha256 test-hmac test-aes test-rsa

# Build all development targets
make all

# Check executable sizes
make sizes
```

### **Release Management**
```bash
# Create tagged release builds
make release

# Validate release artifacts
make test-release

# Create distribution package
make package

# Check release sizes and manifest
make sizes-release
cat build/release/MANIFEST.txt
```

### **Build Targets Reference**

#### **Primary Targets**
- `all` - Build all development executables to `build/temp/`
- `release` - Build tagged release executables to `build/release/`
- `test` - Build and run all tests with Wine validation
- `package` - Create release tarball with manifest
- `clean` - Remove all build artifacts

#### **Development Targets**
- `dev` - Build key development targets (HMAC, SHA256, RSA)
- `smoke` - Quick build and test (SHA1 only)
- `sizes` - Show development build sizes
- `sizes-release` - Show release build sizes

#### **Individual Component Tests**
- `test-sha1` - SHA1 hash function test
- `test-md5` - MD5 hash function test  
- `test-sha256` - SHA256 hash function test
- `test-hmac` - HMAC message authentication test
- `test-aes` - AES-128 CBC encryption test
- `test-rsa` - RSA big integer arithmetic test

#### **Release Validation**
- `test-release` - Test release builds with Wine
- `debug` - Show build configuration details
- `help` - Display comprehensive help

## Directory Structure

```
RetroSSL/
├── build/
│   ├── temp/           # Development builds
│   └── release/        # Tagged release artifacts
├── src/
│   ├── hash/          # Hash function implementations
│   ├── mac/           # Message authentication codes
│   ├── crypto/        # Symmetric encryption
│   ├── rsa/           # RSA public key cryptography
│   └── int/           # Big integer arithmetic
├── include/           # Header files
├── tests/             # Test programs
└── temp/              # External dependencies and analysis
```

## Cryptographic Features

### **Hash Functions**
- **SHA1**: RFC 3174 compliant (160-bit output)
- **MD5**: RFC 1321 compliant (128-bit output) 
- **SHA256**: FIPS 180-4 compliant (256-bit output)
- **Test vectors**: All implementations pass standard test vectors

### **Message Authentication**
- **HMAC-SHA1**: RFC 2202 test vectors validated
- **HMAC-SHA256**: RFC 2202 test vectors validated
- **Variable key lengths**: Supports keys shorter and longer than block size

### **Symmetric Encryption**
- **AES-128 CBC**: NIST test vectors validated
- **Encrypt/Decrypt**: Full round-trip testing
- **Memory-efficient**: Small-table AES implementation

### **Asymmetric Cryptography (RSA)**
- **i31 arithmetic**: 31-bit limbs in 32-bit words
- **Constant-time**: Side-channel resistant operations
- **Modular arithmetic**: Decode, encode, bit length, modular inverse
- **Foundation ready**: Prepared for full RSA implementation

## Example Output

```bash
$ make test-sha256
RetroSSL SHA256 Test
===================
Input: "abc"
SHA256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
✓ Test PASSED!

$ make test-rsa
RetroSSL RSA Test
=================
Testing basic i31 decode/encode functions...
Input: 01 23 45 67 
Decoded x[0] (bit length): 24
Decoded x[1]: 0x01234567
Re-encoded: 01 23 45 67 
PASS: Round-trip encode/decode successful
```

## Build Artifacts

### **Development Builds** (`build/temp/`)
- Rapid iteration with descriptive names
- No versioning tags for fast development

### **Release Builds** (`build/release/`)
- Tagged with version, date, time, and commit hash
- Example: `retrossl_sha256_0.1.0-20250606-0851-de3cb41.exe`
- MD5 checksums in manifest for integrity verification
- Packaged in compressed tarball for distribution

## Wine Testing

All executables are validated on Windows 98 SE compatibility via Wine:
- Console application format (`-l=nt`)
- 32-bit x86 target architecture (`-bt=nt`)  
- C99 features enabled for modern development (`-za99`)
- Optimized for speed (`-ox`)

## Dependencies

- **Open Watcom C/C++**: Cross-compilation toolchain
- **Wine**: Windows 98 SE compatibility testing
- **Make**: Build system orchestration
- **Git**: Version control and commit hash tagging

Run `./setup_dependencies.sh` to automatically install all requirements.

## Documentation

- **[VERSION](VERSION)** - Semantic versioning and feature tracking
- **[BEARSSL_MAPPING.md](BEARSSL_MAPPING.md)** - Source file mapping for upstream tracking
- **[CLAUDE.md](CLAUDE.md)** - AI agent workflow documentation  
- **[WATCOM_SETUP_NOTES.md](WATCOM_SETUP_NOTES.md)** - Compilation troubleshooting

## Architecture

- **Target Platform**: Windows 98 SE (32-bit x86)
- **Host Platform**: macOS ARM64 cross-compilation
- **Toolchain**: Open Watcom C/C++ 2.0
- **Reference Implementation**: BearSSL (pinned at `temp/bearssl-analysis/`)
- **Build System**: GNU Make with professional artifact management
- **Testing**: Wine-based Windows 98 SE validation