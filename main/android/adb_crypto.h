#ifndef ADB_CRYPTO_H
#define ADB_CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <string>

#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

// The device half of ADB's RSA authentication: one 2048 bit key pair that is
// both the client certificate of the pairing TLS connection and the key that
// answers adbd's AUTH challenge. adbd remembers the public key it saw while
// pairing, so both uses have to share the same key.
class AdbIdentity {
public:
    // RSA-2048 signature size, the only size adbd accepts.
    static constexpr size_t kSignatureSize = 256;

    static AdbIdentity& Get();

    // Loads the key from NVS, generating it on first use. Generation takes a
    // second or two, so display a hint before calling this for the first time.
    bool EnsureReady();

    // "base64(android public key) xiaozhi@esp32" plus the terminating NUL that
    // adbd expects in its AUTH public key packet, ready to send as it is.
    const std::string& encoded_public_key() const { return encoded_public_key_; }

    // Answers an AUTH token: PKCS#1 v1.5 over SHA-1, exactly what adbd's
    // RSA_verify() accepts.
    bool SignAuthToken(const uint8_t token[20], uint8_t signature[kSignatureSize]);

    // Used by the pairing connection. The certificate and key stay valid for
    // the lifetime of this object, so the TLS session can keep pointers.
    mbedtls_x509_crt* certificate() { return &certificate_; }
    mbedtls_pk_context* private_key() { return &private_key_; }

private:
    AdbIdentity();
    ~AdbIdentity();
    AdbIdentity(const AdbIdentity&) = delete;
    AdbIdentity& operator=(const AdbIdentity&) = delete;

    bool Load();
    bool Generate();
    bool ParsePrivateKey(const uint8_t* der, size_t der_len);
    bool BuildCertificate();

    mbedtls_pk_context private_key_;
    mbedtls_x509_crt certificate_;
    std::string encoded_public_key_;
    bool ready_ = false;
};

#endif  // ADB_CRYPTO_H
