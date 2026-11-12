#ifndef ADB_NET_H
#define ADB_NET_H

#include <cstdint>
#include <string>

#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include "adb_io.h"

// TLS 1.3 connection to adbd: either its pairing port or its regular control
// port. adbd insists on TLS 1.3 and authenticates with the ADB RSA key
// exchange, not with a certificate chain, so the chain is not verified;
// pairing relies on SPAKE2 and later connections on the AUTH signature.
class AdbTlsStream : public AdbStream {
public:
    AdbTlsStream();
    ~AdbTlsStream() override;
    AdbTlsStream(const AdbTlsStream&) = delete;
    AdbTlsStream& operator=(const AdbTlsStream&) = delete;

    // |certificate| and |key| are both required: adbd only lets a TLS client
    // in when its certificate carries a public key it already knows, which is
    // the one pairing registered. Pass nullptr for both only to see why the
    // handshake gets cut. Set |upgrade_stls| for the control port, which answers
    // a plaintext CNXN with STLS and expects TLS only after the reply.
    bool Connect(const std::string& host, uint16_t port, mbedtls_x509_crt* certificate,
                 mbedtls_pk_context* key, bool upgrade_stls = false);

    // The 64 bytes SPAKE2 mixes into the pairing code, exported with adbd's
    // "adb-label".
    bool ExportKeyingMaterial(uint8_t out[64]);

    bool ReadFully(uint8_t* buffer, size_t size) override;
    bool WriteFully(const uint8_t* data, size_t size) override;

private:
    bool OpenSocket(const std::string& host, uint16_t port);
    bool UpgradeStls();
    bool ReadPlain(uint8_t* buffer, size_t size);
    bool WritePlain(const uint8_t* data, size_t size);
    void Close();

    static int SendCallback(void* context, const unsigned char* data, size_t size);
    static int RecvCallback(void* context, unsigned char* data, size_t size);

    int socket_ = -1;
    bool ssl_ready_ = false;
    mbedtls_ssl_context ssl_;
    mbedtls_ssl_config config_;
};

// Runs the whole pairing exchange against the phone's pairing port: TLS,
// keying material export and SPAKE2. On success |peer_public_key| receives the
// phone's ADB public key.
bool AdbPairWithPhone(const std::string& host, uint16_t port, const std::string& pairing_code,
                      std::string* peer_public_key);

#endif  // ADB_NET_H
