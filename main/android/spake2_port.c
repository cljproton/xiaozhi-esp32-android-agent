// Platform side of the vendored spake2: SHA-512 and a CSPRNG.
//
// The upstream sources call into glibc's LGPL sha512.c and rand(); both are
// replaced here (mbedTLS 4.x removed the legacy mbedtls_sha512 API, so PSA is
// the only SHA-512 in the tree).

#include "third_party/spake2/spake2_hash.h"

#include <assert.h>
#include <string.h>

#include <esp_random.h>
#include <psa/crypto.h>

void spake2_sha512_init(spake2_sha512_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

void spake2_sha512_update(spake2_sha512_ctx *ctx, const uint8_t *data, size_t len) {
    // spake2.c never feeds more than SPAKE2_SHA512_MAX_INPUT bytes per context.
    assert(ctx->len + len <= SPAKE2_SHA512_MAX_INPUT);
    memcpy(ctx->buf + ctx->len, data, len);
    ctx->len += len;
}

void spake2_sha512_finish(spake2_sha512_ctx *ctx, uint8_t out[64]) {
    size_t out_len = 0;
    psa_status_t status = psa_crypto_init();
    if (status == PSA_SUCCESS) {
        status = psa_hash_compute(PSA_ALG_SHA_512, ctx->buf, ctx->len, out, 64, &out_len);
    }
    assert(status == PSA_SUCCESS && out_len == 64);
    (void)status;
    memset(ctx, 0, sizeof(*ctx));
}

void spake2_random_bytes(uint8_t *out, size_t len) {
    esp_fill_random(out, len);
}
