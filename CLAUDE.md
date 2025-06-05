# Claude Agent Instructions for RetroSSL Project

## 🚨 MANDATORY: Always Check Local Documentation First

This project has extensive local documentation that MUST be consulted before making assumptions or asking questions about Open Watcom, Windows 98 compatibility, or build processes.

## Required Reading Order

### 1. For Any Open Watcom Issues
**ALWAYS check first**: `WATCOM_SETUP_NOTES.md`
- Contains all discovered gotchas and solutions
- Working compiler commands and environment setup
- Common mistakes and how to avoid them

### 2. For C Library Questions
**Check**: `docs/watcom/clib_reference.md`
- Standard C functions available
- Memory management approaches
- Header file requirements

### 3. For Platform/Compatibility Questions  
**Check**: `docs/watcom/c_readme.md`
- Confirms Windows 98 SE support
- System requirements
- Installation considerations

### 4. For Advanced Compilation Issues
**Check**: `docs/watcom/programming_guide.md`
- Memory models and management
- Platform-specific compilation
- Cross-platform development techniques

## Project Context (Always Remember)

- **Target**: Windows 98 SE SSL library port
- **Host**: macOS ARM64 cross-compilation  
- **Toolchain**: Open Watcom C/C++
- **Architecture**: 32-bit x86 (`-bt=nt`)
- **Binary location**: `opt/armo64/` (not binnt64 or binl64)
- **BearSSL source**: `temp/bearssl-analysis/` (cloned reference copy)

## BearSSL Reference Source Location

**IMPORTANT**: The complete BearSSL source code is located at:
- **Path**: `temp/bearssl-analysis/`
- **Headers**: `temp/bearssl-analysis/inc/`
- **Source code**: `temp/bearssl-analysis/src/`
- **Purpose**: Reference copy for incremental porting to RetroSSL
- **Version**: Pinned to commit `3c04036` (see setup_dependencies.sh)

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
make -f Makefile.retrossl test_sha1.exe
```

## Mandatory Environment Setup

Before any compilation, ALWAYS ensure:
```bash
export WATCOM="$(pwd)/opt"
export PATH="$(pwd)/opt/armo64:$PATH"
```

## Working Compilation Command
```bash
./opt/armo64/wcl386 -bt=nt -dWIN32 -d_WIN32 -fe=program.exe program.c
```

## Required Workflow

1. **Before suggesting solutions**: Read relevant local documentation
2. **When compilation fails**: Check `WATCOM_SETUP_NOTES.md` first
3. **For new errors**: Document solution in appropriate reference file
4. **Before external research**: Exhaust local documentation first

## Critical Flags Learned Through Experience

- `-bt=nt`: Build target Windows NT (Win98 compatible)
- `-dWIN32 -d_WIN32`: Required for Windows headers
- Use `wcl386` not `wcc386` for simplicity
- Set `WATCOM` environment variable (critical for linker)

## When Documentation Updates Are Required

- New compilation errors solved
- Additional Open Watcom features discovered
- Platform-specific issues encountered
- SSL library integration challenges found
- **NEW DIRECTORIES OR FILES ADDED** - Update CLAUDE.md immediately
- **MISSING CRITICAL PATHS** - Add to "Project Context" section

## 🚨 MANDATORY: Update CLAUDE.md for New Project Structure

**Before working on any new features, ALWAYS:**

1. **Check if new directories/files are referenced** in your work
2. **If adding external dependencies** (clones, downloads, etc.):
   - Document the location in "Project Context"
   - Explain the purpose and structure
   - Add to relevant workflow sections
3. **If file paths are mentioned** in documentation but not in CLAUDE.md:
   - Add them immediately to prevent future confusion
   - Include full paths, not relative references
4. **If you find missing documentation** that causes confusion:
   - Fix it immediately
   - Add prevention measures to this section

**Example of what MUST be documented:**
- Source code locations (like `temp/bearssl-analysis/`)
- Build output directories
- External tool locations (`opt/armo64/`)
- Downloaded reference materials
- Test data locations
- Dependency setup scripts (`setup_dependencies.sh`)
- Version pins (BearSSL commit `3c04036`)

**Why this matters:**
- Future Claude sessions are stateless
- Missing path information breaks workflows
- Prevents repeating discovery work
- Ensures consistent agent behavior

## External Resources (Last Resort Only)

Only after exhausting local docs:
- Open Watcom GitHub: https://github.com/open-watcom/open-watcom-v2
- Online docs: https://open-watcom.github.io/open-watcom-v2-wikidocs/

**Remember**: This local documentation was created specifically for this project's exact use case. Generic external docs may not apply to our macOS->Win98 cross-compilation scenario.