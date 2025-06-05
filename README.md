# RetroSSL - Windows 98 SE SSL Library Port

This project aims to port a minimal SSL library to Windows 98 SE using Open Watcom.

## Development Environment Setup

### Open Watcom Cross-Compilation

The project uses Open Watcom C/C++ compiler for targeting Windows 98 SE from macOS.

**Installation:**
- Open Watcom has been downloaded and extracted to `opt/`
- Compiler binaries are in `opt/armo64/` for macOS ARM64

**Environment Setup:**
```bash
# Source the environment setup script
source setup_watcom.sh

# Or set manually:
export WATCOM="$(pwd)/opt"
export PATH="$(pwd)/opt/armo64:$PATH"
```

**Build Configuration:**
- Target: Windows NT (compatible with Win98 SE)
- Compiler flags: `-bt=nt -dWIN32 -d_WIN32`
- 32-bit compilation with `wcc386`/`wcl386`

**Basic Usage:**
```bash
# Compile a simple C program
./opt/armo64/wcl386 -bt=nt -fe=program.exe program.c

# Using make
make basic_test.exe
```

## Project Status

✅ Open Watcom downloaded and extracted  
✅ Environment configuration created  
✅ SHA1 hash function ported and working  
✅ Win98 cross-compilation confirmed (20KB executable)  
✅ BearSSL selected and dependency management set up  
✅ Git version control with pinned dependencies  
✅ **SHA1 testing confirmed working** (June 2025)  
✅ **Wine-based testing workflow established**  
🔄 Additional hash functions (MD5, SHA256)  
❌ Full SSL/TLS implementation  
❌ Win98 compatibility testing on real hardware  

### ✅ Recent Achievements

**SHA1 Hash Function** (June 2025):
- ✅ Compiles successfully with Open Watcom
- ✅ Produces correct SHA1: `a9993e364706816aba3e25717850c26c9cd0d89d` for "abc"
- ✅ 20KB executable size (Win98 friendly)
- ✅ Wine testing working on macOS
- ✅ Build system proven reliable  

## Documentation System

This project includes comprehensive local documentation:
- `CLAUDE.md` - Agent instructions and workflow
- `WATCOM_SETUP_NOTES.md` - Setup troubleshooting and gotchas
- `docs/watcom/` - Local copies of Open Watcom documentation

**Important**: Always check local documentation before external resources!

## Quick Start

For a fresh clone:
```bash
git clone <repository-url>
cd RetroSSL
./setup_dependencies.sh
./build.sh
```

**Note**: Use `build.sh` for reliable compilation. The Makefile has PATH issues.

## Testing

### Wine-based Testing (macOS)

The project includes Wine-based testing for development verification:

```bash
# Build and test SHA1
./build.sh
wine test_console.exe
```

**Expected output:**
```
RetroSSL SHA1 Test
==================
Input: "abc"
SHA1: a9993e364706816aba3e25717850c26c9cd0d89d
Expected: a9993e364706816aba3e25717850c26c9cd0d89d
```

**Note**: Wine may show hardware compatibility warnings, but the test functionality works correctly.

## BearSSL Source Reference

The complete BearSSL source code is fetched by `setup_dependencies.sh` at a pinned commit for incremental porting reference.

## Next Steps

1. ~~Complete basic test compilation~~ ✅ (SHA1 working)
2. ~~Choose and evaluate SSL library candidates~~ ✅ (BearSSL selected)  
3. **Port additional hash functions** (MD5, SHA256 from BearSSL)
4. Create minimal SSL implementation (in progress)
5. Test on actual Windows 98 SE system

### Current Focus: Hash Function Expansion

With SHA1 proven working, next priority is expanding the hash function library:
- **MD5**: Required for legacy SSL compatibility
- **SHA256**: Modern hash standard
- **Source**: `temp/bearssl-analysis/src/hash/`