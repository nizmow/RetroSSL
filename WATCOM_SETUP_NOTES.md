# Open Watcom Cross-Compilation Setup Notes

This document captures lessons learned and gotchas encountered while setting up Open Watcom for Windows 98 SE cross-compilation on macOS ARM64.

## Key Learnings

### 1. Platform-Specific Binary Locations
- ❌ **Wrong**: Assumed `binnt64` or `binl64` would work on macOS
- ✅ **Correct**: macOS ARM64 binaries are in `opt/armo64/`
- **Lesson**: Always check the actual directory structure after extraction

### 2. Compiler vs Compile+Link Tools
- ❌ **Wrong**: Using `wcc386` + `wlink` separately requires complex setup
- ✅ **Correct**: Use `wcl386` for compile+link in one step
- **Lesson**: `wcl386` is the high-level driver, much easier for simple builds

### 3. Environment Variables Are Critical
- ❌ **Wrong**: Linker fails with "undefined system name: nt" without `WATCOM` env var
- ✅ **Correct**: Must set `WATCOM` environment variable to root directory
- **Lesson**: Open Watcom tools rely heavily on `WATCOM` env var for finding config files

### 4. Windows API Headers Need Proper Defines
- ❌ **Wrong**: Including `windows.h` without defines causes missing types
- ✅ **Correct**: Need `-dWIN32 -d_WIN32` compiler flags
- **Lesson**: Win32 headers have conditional compilation based on these defines

### 5. File Extensions Matter
- ❌ **Wrong**: Expected `.obj` files, got `.o` files with direct `wcc386`
- ✅ **Correct**: Use `wcl386` for consistent behavior
- **Lesson**: Different tools have different default behaviors

## Working Configuration

### Environment Setup
```bash
export WATCOM="$(pwd)/opt"
export PATH="$(pwd)/opt/armo64:$PATH"
```

### Compiler Flags for Win98
```bash
wcl386 -bt=nt -iopt/h -iopt/h/nt -dWIN32 -d_WIN32 -fe=output.exe input.c
```

### Flag Meanings
- `-bt=nt`: Build target = Windows NT (Win98 compatible)
- `-i<path>`: Include path
- `-d<macro>`: Define preprocessor macro
- `-fe=<file>`: Force executable name
- `-zq`: Quiet mode (suppress banner)
- `-w4`: Warning level 4
- `-ox`: Optimize for execution speed

## Common Mistakes to Avoid

1. **Don't use relative paths for WATCOM env var** - Use full absolute path
2. **Don't forget WIN32 defines** - Windows headers won't work without them
3. **Don't mix compiler tools** - Stick with `wcl386` for simplicity
4. **Don't assume binary locations** - Check actual directory structure
5. **Don't skip environment setup** - Tools won't find configs without `WATCOM`

## Directory Structure Reference
```
opt/
├── armo64/          # macOS ARM64 binaries (what we use)
├── binnt/           # Windows NT binaries
├── binl64/          # Linux x64 binaries
├── h/               # Standard headers
│   └── nt/          # Windows NT specific headers
├── lib386/          # 32-bit libraries
└── ...
```

## Testing Commands That Work
```bash
# Basic C program
./opt/armo64/wcl386 -bt=nt -fe=test.exe test.c

# With full flags
WATCOM="$(pwd)/opt" ./opt/armo64/wcl386 -bt=nt -iopt/h -iopt/h/nt -dWIN32 -d_WIN32 -fe=test.exe test.c
```

## What Didn't Work (Learn From Our Mistakes)

### Failed Approach #1: Manual compile + link
```bash
# This approach had too many moving parts
./opt/armo64/wcc386 -bt=nt -fe=test.exe test.c  # Wrong file extension issues
./opt/armo64/wlink system nt file test.obj name test.exe  # Environment issues
```

### Failed Approach #2: Wrong binary directory
```bash
# These directories don't exist or don't work on macOS ARM64
./opt/binnt64/wcl386  # Not found
./opt/binl64/wcl386   # Not found
```

### Failed Approach #3: Missing defines
```bash
# Windows headers fail without proper defines
wcl386 -bt=nt test.c  # Missing WIN32 defines = header errors
```

## Future Reference Checklist

When setting up Open Watcom again:
- [ ] Extract to known location
- [ ] Find correct binary directory for platform
- [ ] Set WATCOM environment variable
- [ ] Test with simple C program first
- [ ] Add WIN32 defines for Windows programs
- [ ] Use wcl386 for simplicity
- [ ] Verify with basic compilation before complex builds

## Resources

- Open Watcom Documentation: https://github.com/open-watcom/open-watcom-v2
- Linker system definitions: Check `opt/armo64/wlink.lnk` for available targets
- Available compiler flags: Run `./opt/armo64/wcl386 /?` for help