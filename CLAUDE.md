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

## Current Project Structure (June 2025)

**Source Code**:
- `src/` - RetroSSL implementation
- `src/hash/` - Hash function implementations (SHA1 working)
- `src/retrossl_inner.h` - Core header file
- `tests/test_sha1.c` - SHA1 test (proven working)

**Build Outputs**:
- `test_sha1.exe` - SHA1 test executable (20KB)
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

**Human vs Agent Approach:**
- **Humans**: Run `./build.sh` and troubleshoot as needed
- **AI Agents**: NEVER provide manual compilation workarounds - always fix `build.sh` instead

## Mandatory Environment Setup

Before any compilation, ALWAYS ensure:
```bash
export WATCOM="$(pwd)/opt"
export PATH="$(pwd)/opt/armo64:$PATH"
```

## Working Compilation Command

**DO NOT USE MANUAL COMMANDS. Always use build scripts:**
```bash
./build.sh
```

**For reference only** (the build script uses):
```bash
./opt/armo64/wcl386 -bt=nt -dWIN32 -d_WIN32 -fe=program.exe program.c
```

## ✅ CONFIRMED WORKING STATUS (June 2025)

**SHA1 Implementation**: ✅ **FULLY FUNCTIONAL**
- Successfully compiled with Open Watcom
- Produces correct SHA1 hash: `a9993e364706816aba3e25717850c26c9cd0d89d` for input "abc"
- Executable size: 20KB (excellent for Win98)
- Wine testing: Working (with minor compatibility warnings)
- Build system: `build.sh` reliable, Makefile has PATH issues

**Test Results:**
```
RetroSSL SHA1 Test
==================
Input: "abc"
SHA1: a9993e364706816aba3e25717850c26c9cd0d89d
Expected: a9993e364706816aba3e25717850c26c9cd0d89d
```

**Proven Build Commands:**
1. `source setup_watcom.sh` (environment setup)
2. `./build.sh` (ONLY build method - never use manual commands)
3. `wine test_console.exe` (testing - works despite Wine warnings)

**Build Script Status**: ✅ **RELIABLE AND MAINTAINED**
- Automatically cleans previous builds
- Handles all compilation flags correctly
- Generates both test executables
- Eliminates compilation warnings
- Works for both human developers and AI agents

## Required Workflow

1. **Before suggesting solutions**: Read relevant local documentation
2. **When compilation fails**: Check `WATCOM_SETUP_NOTES.md` first
3. **For build issues**: Update `build.sh`, don't provide manual commands
4. **For new errors**: Document solution in appropriate reference file
5. **Before external research**: Exhaust local documentation first

## 🎯 HUMAN-FRIENDLY DEVELOPMENT APPROACH

**This project is designed for both AI agents AND human developers:**

**Core Principle**: All compilation should happen through `build.sh`
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
5. Test the updated build script
6. Document in local files (this file, README.md, etc.)

## 🚨 BUILD SCRIPT MAINTENANCE (CRITICAL)

**When compilation breaks or new files are added:**

1. **NEVER give users manual compilation commands**
2. **ALWAYS update `build.sh` instead**
3. **Test the updated build script works**
4. **Keep build script simple and reliable**

**Build script responsibilities:**
- Environment setup verification
- Clean previous builds
- Compile all necessary source files
- Generate both test executables
- Provide clear success/failure feedback

**If build script needs changes:**
1. Edit `build.sh` directly
2. Test the changes work
3. Update documentation if workflow changes
4. Commit the working build script

## Critical Flags Learned Through Experience

- `-bt=nt`: Build target Windows NT (Win98 compatible)
- `-dWIN32 -d_WIN32`: Required for Windows headers
- Use `wcl386` not `wcc386` for simplicity
- Set `WATCOM` environment variable (critical for linker)

## When Documentation Updates Are Required

- New compilation errors solved → **Update build.sh AND document**
- Additional Open Watcom features discovered → **Update build.sh if needed**
- Platform-specific issues encountered → **Fix in build.sh, document here**
- SSL library integration challenges found → **Update build.sh for new dependencies**
- **NEW DIRECTORIES OR FILES ADDED** → **Update build.sh immediately**
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

## 📋 Documentation Maintenance

**Critical**: When project structure changes, update these files immediately:
1. **This file** (`CLAUDE.md`) - Update project context, file locations, workflows
2. **README.md** - Update project status, quick start instructions
3. **`.github/copilot-instructions.md`** - Update if major workflow changes occur

**Last updated**: June 2025 (Build script approach established, SHA1 testing confirmed)