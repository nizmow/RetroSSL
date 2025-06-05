# RetroSSL Makefile for Windows 98 SE cross-compilation
# Uses Open Watcom C/C++ compiler for Win32 console applications

# Toolchain configuration
WATCOM_ROOT = opt
WATCOM_PATH = $(shell pwd)/$(WATCOM_ROOT)
CC = $(WATCOM_PATH)/armo64/wcl386
WINE = wine

# Compiler flags for Win98 compatibility
# -bt=nt: target Windows NT/98/2000/XP
# -l=nt: create console application (critical for proper execution)
# -za99: enable C99 features including stdint.h
# -zc: enable C99 specific features  
# -w4: warning level 4
# -ox: optimize for speed
CFLAGS = -bt=nt -l=nt -za99 -zc -iopt/h -iopt/h/nt -zq -w4 -ox \
         -dWIN32 -d_WIN32 -d__STDC_CONSTANT_MACROS -d__STDC_LIMIT_MACROS

# Source file organization
CODEC_SRCS = src/codec.c

HASH_SRCS = src/hash/sha1.c \
            src/hash/md5.c \
            src/hash/sha2small.c

MAC_SRCS = src/mac/hmac.c

CRYPTO_SRCS = src/crypto/aes_common.c \
              src/crypto/aes_small_enc.c \
              src/crypto/aes_small_dec.c \
              src/crypto/aes_small_cbcenc.c \
              src/crypto/aes_small_cbcdec.c

# Test executables
TESTS = test_sha1.exe \
        test_md5.exe \
        test_sha256.exe \
        test_hmac.exe \
        test_aes.exe \
        test_unified.exe \
        test_console.exe

# Default target
all: verify-toolchain $(TESTS)
	@echo "Build complete!"
	@echo "Created executables:"
	@for exe in $(TESTS); do \
		if [ -f "$$exe" ]; then \
			size=$$(ls -lh "$$exe" 2>/dev/null | awk '{print $$5}' || echo 'unknown'); \
			echo "  - $$exe ($$size)"; \
		else \
			echo "  - $$exe (missing)"; \
		fi; \
	done

# Verify Open Watcom toolchain is available
verify-toolchain:
	@if [ ! -f "$(WATCOM_ROOT)/armo64/wcl386" ]; then \
		echo "ERROR: Open Watcom not found. Run ./setup_dependencies.sh first"; \
		exit 1; \
	fi
	@echo "Open Watcom toolchain verified at $(WATCOM_ROOT)"

# Individual test targets
test_sha1.exe: tests/test_sha1.c $(CODEC_SRCS) src/hash/sha1.c
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

test_md5.exe: tests/test_md5.c $(CODEC_SRCS) src/hash/md5.c  
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

test_sha256.exe: tests/test_sha256.c $(CODEC_SRCS) src/hash/sha2small.c
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

test_hmac.exe: tests/test_hmac.c $(CODEC_SRCS) $(HASH_SRCS) $(MAC_SRCS)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

test_aes.exe: tests/test_aes.c $(CODEC_SRCS) $(CRYPTO_SRCS)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

test_unified.exe: tests/test_sha1.c $(CODEC_SRCS) src/hash/sha1.c src/hash/md5.c
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

test_console.exe: test_md5.exe
	cp test_md5.exe test_console.exe

# Test execution targets (requires Wine)
test: $(TESTS)
	@echo "Running tests with Wine..."
	@echo "Testing SHA1..."
	$(WINE) test_sha1.exe
	@echo "Testing MD5..."
	$(WINE) test_md5.exe  
	@echo "Testing SHA256..."
	$(WINE) test_sha256.exe
	@echo "Testing HMAC..."
	$(WINE) test_hmac.exe
	@echo "Testing AES..."
	$(WINE) test_aes.exe
	@echo "All tests completed!"

# Individual test runs
test-sha1: test_sha1.exe
	$(WINE) test_sha1.exe

test-md5: test_md5.exe
	$(WINE) test_md5.exe

test-sha256: test_sha256.exe
	$(WINE) test_sha256.exe

test-hmac: test_hmac.exe
	$(WINE) test_hmac.exe

test-aes: test_aes.exe
	$(WINE) test_aes.exe

# Quick smoke test - just build and run one test
smoke: test_sha1.exe
	$(WINE) test_sha1.exe

# Clean build artifacts
clean:
	rm -f $(TESTS) *.o *.err

# Clean everything including toolchain
distclean: clean
	rm -rf opt/

# Development targets
dev: test_hmac.exe test_sha256.exe
	@echo "Development build complete"

# Show file sizes
sizes: $(TESTS)
	@echo "Executable sizes:"
	@ls -lh $(TESTS) 2>/dev/null | awk '{print "  " $$9 " (" $$5 ")"}'

# Debug - show what make is thinking
debug:
	@echo "WATCOM_ROOT: $(WATCOM_ROOT)"
	@echo "CC: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "TESTS: $(TESTS)"
	@echo "HASH_SRCS: $(HASH_SRCS)"
	@echo "MAC_SRCS: $(MAC_SRCS)"
	@echo "CRYPTO_SRCS: $(CRYPTO_SRCS)"

# Help target
help:
	@echo "RetroSSL Build System"
	@echo "====================="
	@echo ""
	@echo "Primary targets:"
	@echo "  all          - Build all test executables"
	@echo "  test         - Build and run all tests with Wine"
	@echo "  clean        - Remove build artifacts"
	@echo ""
	@echo "Individual tests:"
	@echo "  test_sha1.exe   - SHA1 hash function test"
	@echo "  test_md5.exe    - MD5 hash function test" 
	@echo "  test_sha256.exe - SHA256 hash function test"
	@echo "  test_hmac.exe   - HMAC message authentication test"
	@echo "  test_aes.exe    - AES encryption test"
	@echo ""
	@echo "Test execution:"
	@echo "  test-sha1    - Run SHA1 test"
	@echo "  test-md5     - Run MD5 test"
	@echo "  test-sha256  - Run SHA256 test"
	@echo "  test-hmac    - Run HMAC test"
	@echo "  test-aes     - Run AES test"
	@echo ""
	@echo "Utilities:"
	@echo "  sizes        - Show executable sizes"
	@echo "  smoke        - Quick build and test"
	@echo "  dev          - Build development targets"
	@echo "  debug        - Show build configuration"
	@echo "  help         - Show this help"

.PHONY: all verify-toolchain test test-sha1 test-md5 test-sha256 test-hmac test-aes \
        smoke clean distclean dev sizes debug help