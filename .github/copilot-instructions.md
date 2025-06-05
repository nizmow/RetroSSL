# GitHub Copilot Instructions for RetroSSL Project

## 🚨 CRITICAL: Read CLAUDE.md First

**BEFORE doing anything else in this workspace, you MUST read and follow the comprehensive agent instructions in `CLAUDE.md`.**

This file contains:
- Mandatory local documentation reading order
- Project context and critical paths
- Working compilation commands
- Required environment setup
- Established workflows and gotchas
- BearSSL source reference locations

## Quick Reference

- **Target**: Windows 98 SE SSL library port
- **Toolchain**: Open Watcom C/C++ cross-compilation from macOS
- **Key files**: Check `CLAUDE.md`, `WATCOM_SETUP_NOTES.md`, `docs/watcom/`
- **BearSSL source**: `temp/bearssl-analysis/` (reference copy)
- **Working compiler**: `./opt/armo64/wcl386 -bt=nt -dWIN32 -d_WIN32`

## Workflow

1. **Always read `CLAUDE.md` first** - Contains complete agent directives
2. **Use `build.sh` for ALL compilation** - Never provide manual commands
3. **Check local documentation** before external resources
4. **Follow established environment setup** in `setup_watcom.sh`
5. **Update build scripts when things change** - Don't provide workarounds
6. **Document new discoveries** in appropriate reference files
7. **Update `CLAUDE.md`** when project structure changes

## Critical Build Approach

- ✅ **ALWAYS use `./build.sh`** for compilation
- ❌ **NEVER give manual compilation commands** to users
- 🔧 **Fix `build.sh` when things break** instead of providing workarounds
- 📝 **Keep build process human-friendly** and self-documenting

## Important

This project has extensive accumulated knowledge about Open Watcom cross-compilation challenges. The local documentation was created specifically for this exact use case. Always prioritize local docs over generic external resources.

**Remember**: `CLAUDE.md` is the authoritative source for agent behavior in this workspace.
