# RetroSSL - Windows 98 SE SSL Library Port

A minimal SSL library for Windows 98 SE, cross-compiled using Open Watcom on macOS.

## Quick Start

```bash
git clone <repository-url>
cd RetroSSL
./setup_dependencies.sh
./build.sh
wine test_console.exe
```

## Project Status

✅ **Working**: SHA1 hash function (30KB executable)  
✅ **Working**: MD5 hash function (30KB executable)  
✅ **Working**: Open Watcom cross-compilation (macOS → Win98)  
✅ **Working**: Wine-based testing workflow  
✅ **Working**: Console application builds  
✅ **Ready**: BearSSL reference source for porting  
🔄 **Next**: Additional hash functions (SHA256, SHA512)  
❌ **TODO**: Full SSL/TLS implementation  
❌ **TODO**: Real Windows 98 hardware testing  

## Build System

```bash
./build.sh
```

Test it works:
```bash
wine test_sha1.exe  # Test SHA1
wine test_md5.exe   # Test MD5
```

You should see:
```
RetroSSL SHA1 Test
==================
Input: "abc"
SHA1: a9993e364706816aba3e25717850c26c9cd0d89d
Expected: a9993e364706816aba3e25717850c26c9cd0d89d

RetroSSL MD5 Test
=================
Input: "abc"
MD5: 900150983cd24fb0d6963f7d28e17f72
Expected: 900150983cd24fb0d6963f7d28e17f72
✓ MD5 test PASSED!
```

## Documentation

- `CLAUDE.md` - AI agent development workflow  
- `WATCOM_SETUP_NOTES.md` - Open Watcom troubleshooting
- `docs/watcom/` - Local Open Watcom documentation

**Tip**: Check local docs first for faster answers.

## Architecture

- **Target**: Windows 98 SE (32-bit x86)
- **Host**: macOS ARM64 cross-compilation
- **Toolchain**: Open Watcom C/C++
- **Reference**: BearSSL (pinned at `temp/bearssl-analysis/`)
- **Size**: 20KB executables (Win98 friendly)

## Next Steps

1. **Hash Functions**: Port MD5 and SHA256 from BearSSL
2. **SSL Core**: Implement basic SSL/TLS handshake
3. **Testing**: Validate on real Windows 98 hardware

---

*Need to modify the build process? See `CLAUDE.md` for development workflows.*