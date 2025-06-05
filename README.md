# RetroSSL - Windows 98 SE SSL Library Port

A minimal SSL library for Windows 98 SE, cross-compiled using Open Watcom on macOS.

## Quick Start

```bash
git clone <repository-url>
cd RetroSSL
./setup_dependencies.sh
./build.sh
wine test_md5.exe  # or wine test_sha1.exe
```

## Status

✅ **SHA1 & MD5** hash functions (30KB executables)  
✅ **Open Watcom** cross-compilation (macOS → Win98)  
✅ **Console applications** with Wine testing  
🔄 **Next**: SHA256, SHA512, SSL/TLS implementation  

## Build & Test

```bash
./build.sh
wine test_sha1.exe  # SHA1: a9993e364706816aba3e25717850c26c9cd0d89d
wine test_md5.exe   # MD5: 900150983cd24fb0d6963f7d28e17f72
```

## Documentation

- `CLAUDE.md` - AI agent workflow
- `WATCOM_SETUP_NOTES.md` - Compilation troubleshooting  
- `docs/watcom/` - Local Open Watcom docs


## Architecture

- **Target**: Windows 98 SE (32-bit x86)
- **Host**: macOS ARM64 cross-compilation
- **Toolchain**: Open Watcom C/C++
- **Reference**: BearSSL (pinned at `temp/bearssl-analysis/`)
