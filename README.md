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
✅ Basic build system (Makefile) set up  
🔄 Testing compilation process  
❌ SSL library selection and integration  
❌ Win98 compatibility testing  

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
source setup_watcom.sh
make -f Makefile.retrossl test_sha1.exe
```

## BearSSL Source Reference

The complete BearSSL source code is fetched by `setup_dependencies.sh` at a pinned commit for incremental porting reference.

## Next Steps

1. Complete basic test compilation
2. ~~Choose and evaluate SSL library candidates~~ ✅ (BearSSL selected)  
3. Create minimal SSL implementation (in progress)
4. Test on actual Windows 98 SE system