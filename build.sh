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
CFLAGS="-bt=nt -l=nt -iopt/h -iopt/h/nt -zq -w4 -ox -dWIN32 -d_WIN32"

# Clean previous builds
echo "Cleaning previous builds..."
rm -f test_sha1.exe test_md5.exe test_console.exe *.o *.err

echo "Compiling SHA1 test..."
./opt/armo64/wcl386 $CFLAGS -fe=test_sha1.exe tests/test_sha1.c src/codec.c src/hash/sha1.c

echo "Compiling MD5 test..."
./opt/armo64/wcl386 $CFLAGS -fe=test_md5.exe tests/test_md5.c src/codec.c src/hash/md5.c

# Create console version for better Wine compatibility (legacy compatibility)
echo "Creating console version..."
cp test_md5.exe test_console.exe

echo "Build complete!"
echo "Created: test_sha1.exe ($(ls -lh test_sha1.exe | awk '{print $5}'))"
echo "Created: test_md5.exe ($(ls -lh test_md5.exe | awk '{print $5}'))"

# Verify executable format - should show "PE32 executable (console)"
echo "Executable format: $(file test_md5.exe)"