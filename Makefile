# RetroSSL Makefile for Windows 98 SE cross-compilation
# Uses Open Watcom C/C++ compiler for Win32 console applications

# Version information
include VERSION
BUILD_DATE := $(shell date +"%Y%m%d-%H%M")
COMMIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TAG := $(RETROSSL_VERSION)-$(BUILD_DATE)-$(COMMIT_HASH)

# Toolchain configuration
WATCOM_ROOT = opt
WATCOM_PATH = $(shell pwd)/$(WATCOM_ROOT)
CC = $(WATCOM_PATH)/armo64/wcl386
WINE = wine

# Build directories
BUILD_DIR = build
TEMP_DIR = $(BUILD_DIR)/temp
RELEASE_DIR = $(BUILD_DIR)/release
OBJ_DIR = $(TEMP_DIR)/obj

# Compiler flags for Win98 compatibility
CFLAGS = -bt=nt -l=nt -za99 -zc -iopt/h -iopt/h/nt -iinclude -zq -w4 -ox \
         -dWIN32 -d_WIN32 -d__STDC_CONSTANT_MACROS -d__STDC_LIMIT_MACROS \
         -dRETROSSL_VERSION=\"$(RETROSSL_VERSION)\" \
         -dRETROSSL_BUILD_TAG=\"$(BUILD_TAG)\"

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

RSA_SRCS = src/rsa/rsa_i31_pub.c \
           src/int/i31_decode.c \
           src/int/i31_bitlen.c \
           src/int/i31_ninv31.c \
           src/int/i31_encode.c \
           src/int/i31_decmod.c \
           src/int/i31_modpow.c \
           src/int/i31_montmul.c \
           src/int/i31_tmont.c \
           src/int/i31_fmont.c \
           src/int/i31_sub.c \
           src/int/i31_add.c \
           src/int/i31_muladd.c

SSL_SRCS = src/ssl/ssl_engine.c \
           src/ssl/ssl_client.c \
           src/ssl/ssl_handshake.c \
           src/ssl/sslio.c

# Test source files
TEST_SRCS = tests/test_sha1.c \
            tests/test_md5.c \
            tests/test_sha256.c \
            tests/test_hmac.c \
            tests/test_aes.c \
            tests/test_rsa.c \
            tests/test_ssl_basic.c \
            tests/test_ssl_handshake.c

# Output executables
TEST_EXES = $(TEMP_DIR)/test_sha1.exe \
            $(TEMP_DIR)/test_md5.exe \
            $(TEMP_DIR)/test_sha256.exe \
            $(TEMP_DIR)/test_hmac.exe \
            $(TEMP_DIR)/test_aes.exe \
            $(TEMP_DIR)/test_rsa.exe \
            $(TEMP_DIR)/test_ssl_basic.exe \
            $(TEMP_DIR)/test_ssl_handshake.exe \
            $(TEMP_DIR)/retrossl.exe

RELEASE_EXES = $(RELEASE_DIR)/retrossl_sha1_$(BUILD_TAG).exe \
               $(RELEASE_DIR)/retrossl_md5_$(BUILD_TAG).exe \
               $(RELEASE_DIR)/retrossl_sha256_$(BUILD_TAG).exe \
               $(RELEASE_DIR)/retrossl_hmac_$(BUILD_TAG).exe \
               $(RELEASE_DIR)/retrossl_aes_$(BUILD_TAG).exe \
               $(RELEASE_DIR)/retrossl_rsa_$(BUILD_TAG).exe \
               $(RELEASE_DIR)/retrossl_$(BUILD_TAG).exe

# Default target
all: verify-toolchain $(TEST_EXES)
	@echo "Development build complete!"
	@echo "Build tag: $(BUILD_TAG)"
	@echo "Built executables in $(TEMP_DIR):"
	@for exe in $(TEST_EXES); do \
		if [ -f "$$exe" ]; then \
			size=$$(ls -lh "$$exe" 2>/dev/null | awk '{print $$5}' || echo 'unknown'); \
			echo "  - $$(basename $$exe) ($$size)"; \
		fi; \
	done

# Release target
release: verify-toolchain $(RELEASE_EXES)
	@echo "Release build complete!"
	@echo "Build tag: $(BUILD_TAG)"
	@echo "Features: $(RETROSSL_BUILD_FEATURES)"
	@echo "Release artifacts in $(RELEASE_DIR):"
	@for exe in $(RELEASE_EXES); do \
		if [ -f "$$exe" ]; then \
			size=$$(ls -lh "$$exe" 2>/dev/null | awk '{print $$5}' || echo 'unknown'); \
			echo "  - $$(basename $$exe) ($$size)"; \
		fi; \
	done
	@echo "Creating release manifest..."
	@echo "RetroSSL Release $(BUILD_TAG)" > $(RELEASE_DIR)/MANIFEST.txt
	@echo "Built on: $(shell date)" >> $(RELEASE_DIR)/MANIFEST.txt
	@echo "Commit: $(COMMIT_HASH)" >> $(RELEASE_DIR)/MANIFEST.txt
	@echo "Features: $(RETROSSL_BUILD_FEATURES)" >> $(RELEASE_DIR)/MANIFEST.txt
	@echo "" >> $(RELEASE_DIR)/MANIFEST.txt
	@echo "Files:" >> $(RELEASE_DIR)/MANIFEST.txt
	@for exe in $(RELEASE_EXES); do \
		if [ -f "$$exe" ]; then \
			size=$$(ls -lh "$$exe" | awk '{print $$5}'); \
			hash=$$(md5 -q "$$exe" 2>/dev/null || md5sum "$$exe" 2>/dev/null | cut -d' ' -f1 || echo 'unknown'); \
			echo "  $$(basename $$exe) ($$size) - MD5: $$hash" >> $(RELEASE_DIR)/MANIFEST.txt; \
		fi; \
	done

# Create build directories
$(TEMP_DIR) $(RELEASE_DIR) $(OBJ_DIR):
	mkdir -p $@

# Verify Open Watcom toolchain is available
verify-toolchain:
	@if [ ! -f "$(WATCOM_ROOT)/armo64/wcl386" ]; then \
		echo "ERROR: Open Watcom not found. Run ./setup_dependencies.sh first"; \
		exit 1; \
	fi
	@echo "Open Watcom toolchain verified at $(WATCOM_ROOT)"

# Development test targets (build to temp)
$(TEMP_DIR)/test_sha1.exe: tests/test_sha1.c $(CODEC_SRCS) src/hash/sha1.c | $(TEMP_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(TEMP_DIR)/test_md5.exe: tests/test_md5.c $(CODEC_SRCS) src/hash/md5.c | $(TEMP_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(TEMP_DIR)/test_sha256.exe: tests/test_sha256.c $(CODEC_SRCS) src/hash/sha2small.c | $(TEMP_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(TEMP_DIR)/test_hmac.exe: tests/test_hmac.c $(CODEC_SRCS) $(HASH_SRCS) $(MAC_SRCS) | $(TEMP_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(TEMP_DIR)/test_aes.exe: tests/test_aes.c $(CODEC_SRCS) $(CRYPTO_SRCS) | $(TEMP_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(TEMP_DIR)/test_rsa.exe: tests/test_rsa.c $(CODEC_SRCS) $(RSA_SRCS) | $(TEMP_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(TEMP_DIR)/test_ssl_basic.exe: tests/test_ssl_basic.c $(CODEC_SRCS) $(SSL_SRCS) | $(TEMP_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(TEMP_DIR)/test_ssl_handshake.exe: tests/test_ssl_handshake.c $(CODEC_SRCS) $(SSL_SRCS) $(RSA_SRCS) | $(TEMP_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(TEMP_DIR)/retrossl.exe: tools/retrossl.c $(CODEC_SRCS) $(HASH_SRCS) | $(TEMP_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

# Release targets (build to release with tagged names)
$(RELEASE_DIR)/retrossl_sha1_$(BUILD_TAG).exe: tests/test_sha1.c $(CODEC_SRCS) src/hash/sha1.c | $(RELEASE_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(RELEASE_DIR)/retrossl_md5_$(BUILD_TAG).exe: tests/test_md5.c $(CODEC_SRCS) src/hash/md5.c | $(RELEASE_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(RELEASE_DIR)/retrossl_sha256_$(BUILD_TAG).exe: tests/test_sha256.c $(CODEC_SRCS) src/hash/sha2small.c | $(RELEASE_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(RELEASE_DIR)/retrossl_hmac_$(BUILD_TAG).exe: tests/test_hmac.c $(CODEC_SRCS) $(HASH_SRCS) $(MAC_SRCS) | $(RELEASE_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(RELEASE_DIR)/retrossl_aes_$(BUILD_TAG).exe: tests/test_aes.c $(CODEC_SRCS) $(CRYPTO_SRCS) | $(RELEASE_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(RELEASE_DIR)/retrossl_rsa_$(BUILD_TAG).exe: tests/test_rsa.c $(CODEC_SRCS) $(RSA_SRCS) | $(RELEASE_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

$(RELEASE_DIR)/retrossl_$(BUILD_TAG).exe: tools/retrossl.c $(CODEC_SRCS) $(HASH_SRCS) | $(RELEASE_DIR)
	WATCOM=$(WATCOM_PATH) PATH=$(WATCOM_PATH)/armo64:$$PATH $(CC) $(CFLAGS) -fe=$@ $^

# Test execution targets (requires Wine)
test: $(TEST_EXES)
	@echo "Running development tests with Wine..."
	@echo "Build tag: $(BUILD_TAG)"
	@echo "Testing SHA1..."
	$(WINE) $(TEMP_DIR)/test_sha1.exe
	@echo "Testing MD5..."
	$(WINE) $(TEMP_DIR)/test_md5.exe
	@echo "Testing SHA256..."
	$(WINE) $(TEMP_DIR)/test_sha256.exe
	@echo "Testing HMAC..."
	$(WINE) $(TEMP_DIR)/test_hmac.exe
	@echo "Testing AES..."
	$(WINE) $(TEMP_DIR)/test_aes.exe
	@echo "Testing RSA..."
	$(WINE) $(TEMP_DIR)/test_rsa.exe
	@echo "Testing SSL basic..."
	$(WINE) $(TEMP_DIR)/test_ssl_basic.exe
	@echo "Testing SSL handshake..."
	$(WINE) $(TEMP_DIR)/test_ssl_handshake.exe
	@echo "All tests completed!"

# Individual test runs
test-sha1: $(TEMP_DIR)/test_sha1.exe
	$(WINE) $(TEMP_DIR)/test_sha1.exe

test-md5: $(TEMP_DIR)/test_md5.exe
	$(WINE) $(TEMP_DIR)/test_md5.exe

test-sha256: $(TEMP_DIR)/test_sha256.exe
	$(WINE) $(TEMP_DIR)/test_sha256.exe

test-hmac: $(TEMP_DIR)/test_hmac.exe
	$(WINE) $(TEMP_DIR)/test_hmac.exe

test-aes: $(TEMP_DIR)/test_aes.exe
	$(WINE) $(TEMP_DIR)/test_aes.exe

test-rsa: $(TEMP_DIR)/test_rsa.exe
	$(WINE) $(TEMP_DIR)/test_rsa.exe

test-ssl: $(TEMP_DIR)/test_ssl_basic.exe
	$(WINE) $(TEMP_DIR)/test_ssl_basic.exe

test-ssl-handshake: $(TEMP_DIR)/test_ssl_handshake.exe
	$(WINE) $(TEMP_DIR)/test_ssl_handshake.exe

# Release validation
test-release: release
	@echo "Running release validation tests..."
	@echo "Testing release build SHA1..."
	$(WINE) $(RELEASE_DIR)/retrossl_sha1_$(BUILD_TAG).exe
	@echo "Testing release build RSA..."
	$(WINE) $(RELEASE_DIR)/retrossl_rsa_$(BUILD_TAG).exe
	@echo "Release validation completed!"

# Quick smoke test
smoke: $(TEMP_DIR)/test_sha1.exe
	$(WINE) $(TEMP_DIR)/test_sha1.exe

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f *.o *.err
	@echo "Cleaned all build artifacts"

# Clean everything including toolchain
distclean: clean
	rm -rf $(WATCOM_ROOT)/
	@echo "Cleaned everything including toolchain"

# Development targets
dev: $(TEMP_DIR)/test_hmac.exe $(TEMP_DIR)/test_sha256.exe $(TEMP_DIR)/test_rsa.exe
	@echo "Development build complete - $(BUILD_TAG)"

# Package release (creates tarball)
package: release
	@echo "Creating release package..."
	cd $(RELEASE_DIR) && tar czf retrossl-$(BUILD_TAG).tar.gz *.exe MANIFEST.txt
	@echo "Created $(RELEASE_DIR)/retrossl-$(BUILD_TAG).tar.gz"

# Show file sizes
sizes: $(TEST_EXES)
	@echo "Development build sizes:"
	@ls -lh $(TEST_EXES) 2>/dev/null | awk '{print "  " $$9 " (" $$5 ")"}'

sizes-release: $(RELEASE_EXES)
	@echo "Release build sizes:"
	@ls -lh $(RELEASE_EXES) 2>/dev/null | awk '{print "  " $$9 " (" $$5 ")"}'

# Debug - show what make is thinking
debug:
	@echo "BUILD_TAG: $(BUILD_TAG)"
	@echo "COMMIT_HASH: $(COMMIT_HASH)"
	@echo "BUILD_DATE: $(BUILD_DATE)"
	@echo "WATCOM_ROOT: $(WATCOM_ROOT)"
	@echo "CC: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "BUILD_DIR: $(BUILD_DIR)"
	@echo "TEMP_DIR: $(TEMP_DIR)"
	@echo "RELEASE_DIR: $(RELEASE_DIR)"

# Help target
help:
	@echo "RetroSSL Build System"
	@echo "====================="
	@echo "Version: $(RETROSSL_VERSION)"
	@echo "Build tag: $(BUILD_TAG)"
	@echo ""
	@echo "Primary targets:"
	@echo "  all          - Build all development executables to $(TEMP_DIR)"
	@echo "  release      - Build tagged release executables to $(RELEASE_DIR)"
	@echo "  test         - Build and run all tests with Wine"
	@echo "  package      - Create release tarball"
	@echo "  clean        - Remove build artifacts"
	@echo ""
	@echo "Development:"
	@echo "  dev          - Build key development targets"
	@echo "  smoke        - Quick build and test"
	@echo "  sizes        - Show development build sizes"
	@echo "  sizes-release - Show release build sizes"
	@echo ""
	@echo "Individual tests:"
	@echo "  test-sha1    - Run SHA1 test"
	@echo "  test-md5     - Run MD5 test"
	@echo "  test-sha256  - Run SHA256 test"
	@echo "  test-hmac    - Run HMAC test"
	@echo "  test-aes     - Run AES test"
	@echo "  test-rsa     - Run RSA test"
	@echo ""
	@echo "Command-line tools:"
	@echo "  retrossl     - OpenSSL-compatible hash utility"
	@echo "               Usage: echo 'data' | wine build/temp/retrossl.exe md5"
	@echo "               Commands: md5, sha1, sha256, version, help"
	@echo ""
	@echo "Validation:"
	@echo "  test-release - Test release builds"
	@echo ""
	@echo "Utilities:"
	@echo "  debug        - Show build configuration"
	@echo "  help         - Show this help"

.PHONY: all release verify-toolchain test test-sha1 test-md5 test-sha256 test-hmac test-aes test-rsa \
        test-release smoke clean distclean dev package sizes sizes-release debug help