# Claude Agent Instructions for RetroSSL Project

## PROJECT GOAL: MINIMAL BEARSSL PORT

RetroSSL is a minimal port of BearSSL to Open Watcom C/C++ for Windows 98 SE.

### CORE PRINCIPLE: BearSSL First, Always
- **ALWAYS** start with original BearSSL source from `temp/bearssl-analysis/src/`
- **COPY** BearSSL implementations as directly as possible
- **ONLY** modify for Open Watcom compiler compatibility
- **DO NOT** implement crypto algorithms from scratch
- **PRESERVE** BearSSL's structure, logic, and algorithms exactly
- **MINIMIZE** diffs - focus on compilation fixes, not improvements

### Development Approach
1. **Find BearSSL source**: Look in `temp/bearssl-analysis/src/` first
2. **Copy directly**: Start with exact BearSSL code  
3. **Fix compilation**: Make minimal changes for Open Watcom
4. **Test**: Verify functionality matches BearSSL behavior
5. **Document**: Note changes made and why

**When in doubt: Check BearSSL source first. Innovation is NOT the goal - compatibility is.**

## Check Local Documentation First

This project has local documentation that MUST be consulted before external research.

### Required Reading Order

1. **Open Watcom Issues**: `WATCOM_SETUP_NOTES.md` - All gotchas and solutions
2. **C Library Questions**: `docs/watcom/clib_reference.md` - Available functions
3. **Platform/Compatibility**: `docs/watcom/c_readme.md` - Win98 SE support
4. **Advanced Compilation**: `docs/watcom/programming_guide.md` - Memory models

## Style
- Always add newlines at the ends of files.

## Project Context

- **Target**: Windows 98 SE SSL library  
- **Host**: macOS ARM64 cross-compilation
- **Toolchain**: Open Watcom C/C++ (`opt/armo64/`)
- **Architecture**: 32-bit x86 (`-bt=nt -l=nt`)
- **BearSSL source**: `temp/bearssl-analysis/`

## Current Status (June 2025)

**Working**: Hash functions (SHA1, MD5, SHA256), HMAC, AES-128, RSA i31 (90%)
**Executables**: 30-31KB each (Win98 friendly)  
**Source**: `src/hash/`, `src/crypto/`, `src/int/`, `src/rsa/`
**Tests**: All major crypto components have test programs

**Build System**: Professional Makefile with:
- Temp/release directory organization
- Version tagging with commit hashes  
- MD5 checksums and manifest generation
- Automated packaging

## BearSSL Reference Source Location

**IMPORTANT**: The complete BearSSL source code is located at:
- **Path**: `temp/bearssl-analysis/`
- **Headers**: `temp/bearssl-analysis/inc/`
- **Source code**: `temp/bearssl-analysis/src/`
- **Purpose**: Reference copy for incremental porting to RetroSSL
- **Version**: Pinned to commit `3c04036` (see setup_dependencies.sh)

**📋 SOURCE MAPPING**: See `BEARSSL_MAPPING.md` for complete 1:1 file mapping and update procedures

**Key directories for porting**:
- `temp/bearssl-analysis/src/hash/` - Hash functions (SHA1, MD5, SHA256)
- `temp/bearssl-analysis/src/symcipher/` - Symmetric crypto (AES, DES)
- `temp/bearssl-analysis/src/int/` - Big integer arithmetic (i31, i32)
- `temp/bearssl-analysis/src/rsa/` - RSA operations
- `temp/bearssl-analysis/src/ssl/` - SSL/TLS protocol engine
- `temp/bearssl-analysis/src/x509/` - Certificate handling

## 🚨 FRESH CLONE SETUP

**If working with a fresh git clone, run this FIRST:**

```bash
./setup_dependencies.sh
```

This script will:
- Fetch BearSSL at pinned commit `3c04036`
- Download and extract Open Watcom
- Verify the setup

**Then proceed with normal workflow:**
```bash
make all
```

## ✅ Confirmed Working (June 2025)

**Hash Functions**: SHA1, MD5, SHA256 - all produce correct hashes
**MAC**: HMAC with SHA1, MD5, SHA256 - test vectors pass
**Symmetric Crypto**: AES-128 CBC encryption/decryption working
**Big Integer**: i31 arithmetic (decode, encode, ninv31, bit_length)
**RSA**: Montgomery arithmetic 90% complete (needs final debugging)

**Build System**: Professional Makefile handles all components automatically

## Environment Setup

Modern build system handles this automatically via Makefile.

## Build Process

**Always use**: `make all` or `make tests`
**Individual tests**: `make build/temp/test_<component>.exe`
**Release build**: `make release`

## Common Open Watcom Compatibility Changes

When porting BearSSL code:
1. **Function declarations**: Use K&R style parameter lists
2. **64-bit types**: `uint64_t` works but may need explicit casts
3. **Inline functions**: Use `static inline` in headers
4. **Macros**: BearSSL's constant-time macros work directly
5. **Memory operations**: `memmove`, `memcmp` available
6. **Division**: Simple 64/32 division works for br_div/br_rem

## Critical Console Application Discovery (June 2025)

**Problem**: Without `-l=nt`, executables fail with Wine errors  
**Solution**: Makefile uses `-bt=nt -l=nt` for proper console apps  
**Result**: Executables work correctly in Wine testing environment

## ✅ PROVEN DEVELOPMENT WORKFLOW (June 2025)

**For building and testing:**
1. `make all` (builds all components)
2. `make tests` (builds test programs)
3. `wine build/temp/test_<component>.exe` (testing on macOS)

**For adding new features:**
1. **Reference BearSSL source** in `temp/bearssl-analysis/src/`
2. **Copy implementation** to appropriate `src/` directory
3. **Adapt for Open Watcom** (minimal changes only)
4. **Add test case** to `tests/`
5. **Update Makefile** if needed for new source files
6. **Test functionality** matches BearSSL behavior

## Workflow

1. **Check local docs** before external research
2. **Use BearSSL source** as starting point always
3. **Minimize changes** - only fix compilation issues
4. **Test thoroughly** to ensure correct behavior
5. **Document minimal diffs** and reasoning

## Key Flags (Handled by Makefile)

- `-bt=nt -l=nt`: Windows NT console application (critical for Wine testing)
- `-dWIN32 -d_WIN32`: Windows headers
- `-za99`: C99 compatibility mode
- `-ox`: Optimize for size (Win98 friendly)

## Documentation Updates

- **New BearSSL ports** → Document in commit messages
- **Compilation fixes** → Add to `WATCOM_SETUP_NOTES.md` if significant  
- **Major discoveries** → Update this file
- **Build changes** → Update Makefile and test

## Resources (Last Resort)

Check local docs and BearSSL source first. If needed:
- Open Watcom GitHub: https://github.com/open-watcom/open-watcom-v2
- BearSSL documentation: Review `temp/bearssl-analysis/` thoroughly

## Project Memories

- Minimal BearSSL port - stay true to original implementations
- Professional build system with versioning and packaging
- All major crypto primitives working or nearly complete
- Focus on compatibility, not innovation

**Last updated**: June 2025 (RSA Montgomery arithmetic 90% complete)