#!/bin/bash

# Open Watcom Environment Setup for RetroSSL
export WATCOM_ROOT="$(pwd)/opt"
export WATCOM="$WATCOM_ROOT"
export PATH="$WATCOM_ROOT/armo64:$PATH"
export INCLUDE="$WATCOM_ROOT/h"
export LIB="$WATCOM_ROOT/lib386"

# Win98 build targets
export WATCOM_NT_TARGET="-bt=nt -l=nt"

echo "Open Watcom environment configured for Win98 cross-compilation"
echo "WATCOM: $WATCOM"
echo "Available compilers:"
ls -la "$WATCOM_ROOT/armo64/wcc*"