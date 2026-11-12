/*
 * Not part of the upstream spake2 sources. Defined here so that spake2.c can
 * use the platform SHA-512 instead of the LGPL glibc copy it originally shipped
 * with, and a real CSPRNG instead of rand().
 */
#ifndef SPAKE2_HASH_H
#define SPAKE2_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Streaming SHA-512. spake2.c hashes less than 512 bytes per context (two 16
// byte names, two 32 byte messages, a 32 byte shared secret and a 64 byte
// password hash, each with an 8 byte length prefix), so the implementation may
// buffer the input instead of compressing incrementally.
#define SPAKE2_SHA512_MAX_INPUT 512

typedef struct {
    uint8_t buf[SPAKE2_SHA512_MAX_INPUT];
    size_t len;
} spake2_sha512_ctx;

void spake2_sha512_init(spake2_sha512_ctx *ctx);
void spake2_sha512_update(spake2_sha512_ctx *ctx, const uint8_t *data, size_t len);
void spake2_sha512_finish(spake2_sha512_ctx *ctx, uint8_t out[64]);

// Fills out with len cryptographically secure random bytes.
void spake2_random_bytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif  // SPAKE2_HASH_H
