#ifndef ADB_CONNECTION_H
#define ADB_CONNECTION_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "adb_frame.h"
#include "adb_io.h"

// ADB message channel: banner exchange, key authentication and running one
// service (a shell command, a sync session, ...) per call.
class AdbConnection {
public:
    static constexpr size_t kSignatureSize = 256;

    // Signs the 20 byte AUTH token with the RSA identity.
    using Signer = std::function<bool(const uint8_t token[20], uint8_t signature[kSignatureSize])>;

    // |public_key| is the NUL terminated base64 key, sent as it is when adbd
    // asks for it instead of accepting a signature. |stls_upgraded| marks a
    // stream that already did the plaintext CNXN + STLS + TLS upgrade; official
    // adb then waits for the device CNXN instead of sending another one (the
    // extra CNXN inside TLS derails MIUI adbd and breaks every later OPEN).
    AdbConnection(AdbStream* stream, Signer signer, const std::string& public_key,
                  bool stls_upgraded = false);

    // Sends CNXN, answers adbd's AUTH challenge and waits for the device
    // banner. Call once before RunService.
    bool Connect();

    // Opens |service|, writes |input| once the device accepts the stream and
    // collects everything the device sends back. |output| may be null when the
    // command's reply does not matter.
    bool RunService(const std::string& service, const std::string& input, std::string* output);

private:
    bool SendFrame(uint32_t command, uint32_t arg0, uint32_t arg1, const void* data, size_t size);
    bool ReadFrame(AdbFrame* frame, std::string* payload);

    AdbStream* stream_;
    Signer signer_;
    std::string public_key_;
    bool stls_upgraded_;
    uint32_t next_local_id_ = 1;
    uint32_t peer_version_ = 0;
    uint32_t peer_max_payload_ = 0;
};

#endif  // ADB_CONNECTION_H
