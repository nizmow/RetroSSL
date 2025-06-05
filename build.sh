#!/bin/bash
# RetroSSL Build Script for Windows 98 SE
# 
# Successfully builds both SHA1 and MD5 hash functions
# Creates proper Windows console applications for Win98 compatibility

set -e  # Exit on any error

echo "Building RetroSSL for Windows 98 SE..."

# Setup Open Watcom environment
export WATCOM="$(pwd)/opt"
export PATH="$(pwd)/opt/armo64:$PATH"
export INCLUDE="$(pwd)/opt/h"

# Verify compiler exists
if [ ! -f "opt/armo64/wcl386" ]; then
    echo "ERROR: Open Watcom not found. Run ./setup_dependencies.sh first"
    exit 1
fi

# Build flags for Win98 compatibility - console application
# CRITICAL: -l=nt creates console applications (not GUI apps)
# Without -l=nt, executables build as GUI apps and fail to run properly
# CRITICAL: -za99 enables C99 features including stdint.h support
# CRITICAL: -zc enables C99 specific features
CFLAGS="-bt=nt -l=nt -za99 -zc -iopt/h -iopt/h/nt -zq -w4 -ox -dWIN32 -d_WIN32 -d__STDC_CONSTANT_MACROS -d__STDC_LIMIT_MACROS"

# Clean previous builds
echo "Cleaning previous builds..."
rm -f test_sha1.exe test_md5.exe test_aes.exe test_unified.exe test_console.exe *.o *.err

echo "Compiling SHA1 test..."
./opt/armo64/wcl386 $CFLAGS -fe=test_sha1.exe tests/test_sha1.c src/codec.c src/hash/sha1.c

echo "Compiling MD5 test..."
./opt/armo64/wcl386 $CFLAGS -fe=test_md5.exe tests/test_md5.c src/codec.c src/hash/md5.c

echo "Compiling AES test..."
./opt/armo64/wcl386 $CFLAGS -fe=test_aes.exe tests/test_aes.c src/codec.c \
    src/crypto/aes_common.c src/crypto/aes_small_enc.c src/crypto/aes_small_dec.c \
    src/crypto/aes_small_cbcenc.c src/crypto/aes_small_cbcdec.c

# Test unified build (hash only for now)
echo "Testing unified build (hash only)..."
./opt/armo64/wcl386 $CFLAGS -fe=test_unified.exe tests/test_sha1.c src/codec.c \
    src/hash/sha1.c src/hash/md5.c

# Create console version for better Wine compatibility (legacy compatibility)
echo "Creating console version..."
cp test_md5.exe test_console.exe

echo "Build complete!"
echo "Created executables:"
echo "  - test_sha1.exe ($(ls -lh test_sha1.exe 2>/dev/null | awk '{print $5}' || echo 'missing'))"
echo "  - test_md5.exe ($(ls -lh test_md5.exe 2>/dev/null | awk '{print $5}' || echo 'missing'))" 
echo "  - test_aes.exe ($(ls -lh test_aes.exe 2>/dev/null | awk '{print $5}' || echo 'missing'))"
echo "  - test_unified.exe ($(ls -lh test_unified.exe 2>/dev/null | awk '{print $5}' || echo 'missing'))"
echo "  - test_console.exe ($(ls -lh test_console.exe 2>/dev/null | awk '{print $5}' || echo 'missing'))"

# Simple verification that files exist
if [ -f "test_md5.exe" ] && [ -f "test_unified.exe" ]; then
    echo "Build successful - all executables created"
else
    echo "Build failed - some executables not found"
    exit 1
fi