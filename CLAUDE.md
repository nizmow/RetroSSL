# Claude Agent Instructions for RetroSSL Project

## 🚨 Check Local Documentation First

This project has local documentation that MUST be consulted before external research.

## Required Reading Order

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

**Working**: MD5 & SHA1 hash functions + AES-128 CBC encryption  
**Executables**: 30-31KB each (Win98 friendly)  
**Source**: `src/hash/`, `src/crypto/`, `src/retrossl_inner.h`  
**Tests**: `tests/test_md5.c`, `tests/test_sha1.c`, `tests/test_aes.c`
- `test_console.exe` - Console version for Wine testing
- `*.o`, `*.err` - Compilation artifacts

**Key Scripts**:
- `build.sh` - **RELIABLE** build script (use this)
- `setup_watcom.sh` - Environment configuration
- `setup_dependencies.sh` - Fresh clone setup

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
source setup_watcom.sh
./build.sh
```

**IMPORTANT**: Always use `build.sh` for compilation. Do NOT provide manual compilation commands to users.

## ✅ Confirmed Working (June 2025)

**Hash Functions**: MD5 & SHA1 produce correct hashes (30KB executables)
- SHA1: `a9993e364706816aba3e25717850c26c9cd0d89d` for "abc"  
- MD5: `900150983cd24fb0d6963f7d28e17f72` for "abc"

**AES-128 CBC**: Complete encryption/decryption (31KB executable)
- Key schedule: ✅ Working with test vectors
- Encryption: ✅ Produces expected ciphertext  
- Decryption: ✅ Recovers original plaintext
- Wine testing: All tests pass (ignore compatibility warnings)

## Environment Setup

```bash
export WATCOM="$(pwd)/opt"
export PATH="$(pwd)/opt/armo64:$PATH"
```

## Build Process

**Always use**: `./build.sh` (never manual commands)  
**AI Agents**: Fix `build.sh` when things break, don't provide workarounds
## Workflow

1. **Check local docs** before external research
2. **Use `./build.sh`** for all compilation  
3. **Fix build scripts** when things break
4. **Document discoveries** in reference files

## Critical Console Application Discovery (June 2025)

**Problem**: Without `-l=nt`, executables fail with Wine "winevdm.exe" errors  
**Solution**: Build script now uses `-bt=nt -l=nt` for proper console apps  
**Result**: Executables show as "PE32 executable (console)" and work correctly
- ✅ Humans can run `./build.sh` reliably
- ✅ AI agents use the same script
- ✅ No manual compilation commands to remember
- ✅ Build process is documented in the script itself

**When things break:**
1. Fix the `build.sh` script (AI agents should do this automatically)
2. Don't provide workarounds or manual commands to humans
3. Keep the script simple and self-documenting  
4. Test fixes work for both AI and human use

**README.md Focus**: 
- README.md is optimized for human developers
- Technical implementation details and agent workflows belong here in CLAUDE.md
- Keep README.md concise and action-oriented for humans

## ✅ PROVEN DEVELOPMENT WORKFLOW (June 2025)

**For building and testing:**
1. `source setup_watcom.sh` (environment setup)
2. `./build.sh` (ALWAYS use this - never manual commands)
3. `wine test_console.exe` (testing on macOS)
4. Verify expected SHA1 output: `a9993e364706816aba3e25717850c26c9cd0d89d`

**For adding new features:**
1. Reference BearSSL source in `temp/bearssl-analysis/src/`
2. Port to `src/` directory with Win98/Open Watcom compatibility
3. Add test case to `tests/`
4. **Update `build.sh` to include new files** (critical!)
## Build Script Maintenance

**When adding files or fixing compilation:**
1. **Fix `build.sh`** (never give manual commands)
2. **Test the changes work** 
3. **Document discoveries** in reference files

## Key Flags

- `-bt=nt -l=nt`: Windows NT console application (critical for Wine testing)
- `-dWIN32 -d_WIN32`: Windows headers
- `-fe=filename.exe`: Output executable name
- `wcl386`: Use this (not `wcc386`) for simplicity

## Documentation Updates

- **New files added** → Update `build.sh` immediately
- **Compilation errors solved** → Document in `WATCOM_SETUP_NOTES.md`  
- **Major discoveries** → Update this file
- **MISSING CRITICAL PATHS** → Add to "Project Context" section

## 🚨 MANDATORY: Maintain Build Scripts Over Manual Commands

**NEVER provide manual compilation commands. Always:**

1. **Update `build.sh`** to handle new requirements
2. **Test the updated script** works correctly
3. **Document changes** in commit messages and this file
4. **Keep it simple** so humans can understand and modify it

**Why this approach:**
- ✅ Consistent builds for all developers (human and AI)
- ✅ No need to remember complex flag combinations
- ✅ Easy to maintain and update
- ✅ Self-documenting build process
- ✅ Prevents manual command errors
- ✅ Works in any environment (CI, local, containers)

## 🚨 MANDATORY: Update CLAUDE.md for New Project Structure

## Next Steps for New Features

1. **Reference BearSSL source** in `temp/bearssl-analysis/src/`
2. **Port to `src/`** with Win98/Open Watcom compatibility  
3. **Add test** to `tests/`
4. **Update `build.sh`** to include new files
5. **Document** in local files

## Resources (Last Resort)

Check local docs first. If needed:
- Open Watcom GitHub: https://github.com/open-watcom/open-watcom-v2

## Project Memories

- We don't care that much about file sizes

**Last updated**: June 2025 (MD5 & SHA1 working, console app builds fixed)