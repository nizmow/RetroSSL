/*
 * RetroSSL - AES Small Implementation (Decryption)
 * Based on BearSSL aes_small_dec.c, adapted for Windows 98 SE
 * 
 * Copyright (c) 2025 RetroSSL Project  
 * Based on BearSSL Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "../retrossl_inner.h"

/*
 * Inverse S-box.
 */
static const unsigned char iS[] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
    0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
    0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
    0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
    0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
    0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
    0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
    0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
    0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0C, 0x7D
};

static void
add_round_key(unsigned *state, const uint32_t *skeys)
{
    int i;

    for (i = 0; i < 16; i += 4) {
        uint32_t k;

        k = *skeys ++;
        state[i + 0] ^= (unsigned)(k >> 24);
        state[i + 1] ^= (unsigned)(k >> 16) & 0xFF;
        state[i + 2] ^= (unsigned)(k >> 8) & 0xFF;
        state[i + 3] ^= (unsigned)k & 0xFF;
    }
}

static void
inv_sub_bytes(unsigned *state)
{
    int i;

    for (i = 0; i < 16; i ++) {
        state[i] = iS[state[i]];
    }
}

static void
inv_shift_rows(unsigned *state)
{
    unsigned tmp;

    tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;

    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

static inline unsigned
gf256red(unsigned x)
{
    unsigned y;

    y = x >> 8;
    return (x ^ y ^ (y << 1) ^ (y << 3) ^ (y << 4)) & 0xFF;
}

static void
inv_mix_columns(unsigned *state)
{
    int i;

    for (i = 0; i < 16; i += 4) {
        unsigned s0, s1, s2, s3;
        unsigned t0, t1, t2, t3;

        s0 = state[i + 0];
        s1 = state[i + 1];
        s2 = state[i + 2];
        s3 = state[i + 3];
        t0 = (s0 << 1) ^ (s0 << 2) ^ (s0 << 3)
            ^ s1 ^ (s1 << 1) ^ (s1 << 3)
            ^ s2 ^ (s2 << 2) ^ (s2 << 3)
            ^ s3 ^ (s3 << 3);
        t1 = s0 ^ (s0 << 3)
            ^ (s1 << 1) ^ (s1 << 2) ^ (s1 << 3)
            ^ s2 ^ (s2 << 1) ^ (s2 << 3)
            ^ s3 ^ (s3 << 2) ^ (s3 << 3);
        t2 = s0 ^ (s0 << 2) ^ (s0 << 3)
            ^ s1 ^ (s1 << 3)
            ^ (s2 << 1) ^ (s2 << 2) ^ (s2 << 3)
            ^ s3 ^ (s3 << 1) ^ (s3 << 3);
        t3 = s0 ^ (s0 << 1) ^ (s0 << 3)
            ^ s1 ^ (s1 << 2) ^ (s1 << 3)
            ^ s2 ^ (s2 << 3)
            ^ (s3 << 1) ^ (s3 << 2) ^ (s3 << 3);
        state[i + 0] = gf256red(t0);
        state[i + 1] = gf256red(t1);
        state[i + 2] = gf256red(t2);
        state[i + 3] = gf256red(t3);
    }
}

/* see retrossl_block.h */
void
retrossl_aes_small_decrypt(unsigned num_rounds, const uint32_t *skey, void *data)
{
    unsigned char *buf;
    unsigned state[16];
    unsigned u;

    buf = data;
    for (u = 0; u < 16; u ++) {
        state[u] = buf[u];
    }
    add_round_key(state, skey + (num_rounds << 2));
    for (u = num_rounds - 1; u > 0; u --) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, skey + (u << 2));
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, skey);
    for (u = 0; u < 16; u ++) {
        buf[u] = state[u];
    }
}
