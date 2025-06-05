#!/bin/bash
# RetroSSL Build Script for Windows 98 SE

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

# Build flags for Win98 compatibility
CFLAGS="-bt=nt -iopt/h -iopt/h/nt -zq -w4 -ox -dWIN32 -d_WIN32"

echo "Compiling SHA1 test..."
wcl386 $CFLAGS -fe=test_sha1.exe tests/test_sha1.c src/codec.c src/hash/sha1.c

echo "Build complete!"
echo "Created: test_sha1.exe ($(ls -lh test_sha1.exe | awk '{print $5}'))"

# Verify executable format
echo "Executable format: $(file test_sha1.exe)"