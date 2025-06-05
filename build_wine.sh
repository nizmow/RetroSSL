#!/bin/bash
# RetroSSL Wine-Compatible Build Script

set -e  # Exit on any error

echo "Building RetroSSL for Wine testing..."

# Setup Open Watcom environment
export WATCOM="$(pwd)/opt"
export PATH="$(pwd)/opt/armo64:$PATH"

# Verify compiler exists
if [ ! -f "opt/armo64/wcl386" ]; then
    echo "ERROR: Open Watcom not found. Run ./setup_dependencies.sh first"
    exit 1
fi

# Build Win32 console application (Wine-compatible)
echo "Compiling Win32 console application..."
wcl386 -bt=nt -l=nt -iopt/h -iopt/h/nt -zq -dWIN32 -d_WIN32 \
       -fe=test_wine.exe tests/test_sha1.c src/codec.c src/hash/sha1.c

echo "Build complete!"
echo "Created: test_wine.exe ($(ls -lh test_wine.exe | awk '{print $5}'))"
echo "Format: $(file test_wine.exe)"
echo ""
echo "Testing with Wine:"
echo "=================="
WINEDEBUG=-all wine test_wine.exe 2>/dev/null || echo "Wine test failed"