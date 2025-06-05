#!/bin/bash
# RetroSSL Dependency Setup Script
# Fetches external dependencies at pinned versions

set -e  # Exit on any error

echo "Setting up RetroSSL dependencies..."

# Configuration
BEARSSL_COMMIT="3c04036"
BEARSSL_REPO="https://www.bearssl.org/git/BearSSL"
WATCOM_URL="https://github.com/open-watcom/open-watcom-v2/releases/download/Current-build/ow-snapshot.tar.xz"

# Create temp directory
mkdir -p temp

# Fetch BearSSL at pinned commit
echo "Fetching BearSSL at commit $BEARSSL_COMMIT..."
if [ ! -d "temp/bearssl-analysis" ]; then
    cd temp
    git clone "$BEARSSL_REPO" bearssl-analysis
    cd bearssl-analysis
    git checkout "$BEARSSL_COMMIT"
    cd ../..
    echo "BearSSL fetched successfully"
else
    echo "BearSSL already exists, checking commit..."
    cd temp/bearssl-analysis
    current_commit=$(git rev-parse HEAD | cut -c1-7)
    if [ "$current_commit" != "$BEARSSL_COMMIT" ]; then
        echo "WARNING: BearSSL is at commit $current_commit, expected $BEARSSL_COMMIT"
        echo "Run: rm -rf temp/bearssl-analysis && ./setup_dependencies.sh"
        exit 1
    fi
    cd ../..
    echo "BearSSL is at correct commit"
fi

# Fetch Open Watcom
echo "Fetching Open Watcom..."
if [ ! -f "ow-snapshot.tar.xz" ]; then
    curl -L -o ow-snapshot.tar.xz "$WATCOM_URL"
    echo "Open Watcom downloaded"
else
    echo "Open Watcom archive already exists"
fi

# Extract Open Watcom
echo "Extracting Open Watcom..."
if [ ! -d "opt" ]; then
    mkdir -p opt
    tar -xf ow-snapshot.tar.xz -C opt
    echo "Open Watcom extracted"
else
    echo "Open Watcom already extracted"
fi

# Verify setup
echo "Verifying setup..."
if [ ! -f "opt/armo64/wcl386" ]; then
    echo "ERROR: Open Watcom compiler not found at opt/armo64/wcl386"
    exit 1
fi

if [ ! -f "temp/bearssl-analysis/inc/bearssl_hash.h" ]; then
    echo "ERROR: BearSSL headers not found"
    exit 1
fi

echo "✅ Dependencies setup complete!"
echo ""
echo "Next steps:"
echo "1. Source the environment: source setup_watcom.sh"
echo "2. Build test: make -f Makefile.retrossl test_sha1.exe"
echo ""
echo "Dependency versions:"
echo "- BearSSL: commit $BEARSSL_COMMIT"
echo "- Open Watcom: Current snapshot build"