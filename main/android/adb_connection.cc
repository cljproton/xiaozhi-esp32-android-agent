#include "adb_connection.h"

#include <cstring>
#include <utility>

#ifdef ESP_PLATFORM
#include <esp_log.h>
#define ADB_LOG_ERROR(fmt, ...) ESP_LOGE("AdbConnection", fmt, ##__VA_ARGS__)
#define ADB_LOG_INFO(fmt, ...) ESP_LOGI("AdbConn", fmt, ##__VA_ARGS__)
#define ADB_LOG_DEBUG(fmt, ...) ESP_LOGD("AdbConn", fmt, ##__VA_ARGS__)
#else
#define ADB_LOG_ERROR(fmt, ...) \
    do {                        \
    } while (0)
#define ADB_LOG_INFO(fmt, ...) \
    do {                       \
    } while (0)
#define ADB_LOG_DEBUG(fmt, ...) \
    do {                        \
    } while (0)
#endif

namespace {

// Matches the official adb client; MIUI adbd sent STLS on every OPEN when we
// advertised an older/smaller identity.
constexpr uint32_t kLocalMaxPayload = 1024 * 1024;
// One CNXN, then a bounded number of AUTH challenges.
constexpr int kMaxAuthRounds = 4;
// Same identity the official adb advertises; keep in sync with kAdbBanner.
constexpr char kBanner[] =
    "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,"
    "fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,"
    "sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,"
    "devicetracker_proto_format,devraw,app_info,server_status,track_mdns";

}  // namespace

AdbConnection::AdbConnection(AdbStream* stream, Signer signer, const std::string& public_key,
                             bool stls_upgraded)
    : stream_(stream),
      signer_(std::move(signer)),
      public_key_(public_key),
      stls_upgraded_(stls_upgraded) {}

bool AdbConnection::SendFrame(uint32_t command, uint32_t arg0, uint32_t arg1, const void* data,
                              size_t size) {
    AdbFrame frame;
    frame.command = command;
    frame.arg0 = arg0;
    frame.arg1 = arg1;
    frame.data_length = static_cast<uint32_t>(size);
    frame.data_check = AdbFrameChecksum(static_cast<const uint8_t*>(data), size);

    uint8_t header[kAdbFrameSize];
    AdbFrameEncode(frame, header);
    if (!stream_->WriteFully(header, sizeof(header))) {
        return false;
    }
    return size == 0 || stream_->WriteFully(static_cast<const uint8_t*>(data), size);
}

bool AdbConnection::ReadFrame(AdbFrame* frame, std::string* payload) {
    uint8_t header[kAdbFrameSize];
    if (!stream_->ReadFully(header, sizeof(header))) {
        ADB_LOG_ERROR("Stream ended while reading a frame header");
        return false;
    }
    if (!AdbFrameDecode(header, frame)) {
        ADB_LOG_ERROR("Frame magic mismatch, the stream lost sync");
        return false;
    }
    if (frame->data_length > kAdbMaxPayload) {
        ADB_LOG_ERROR("Frame payload of %u bytes is too large", frame->data_length);
        return false;
    }
    payload->resize(frame->data_length);
    if (frame->data_length != 0 &&
        !stream_->ReadFully(reinterpret_cast<uint8_t*>(payload->data()), frame->data_length)) {
        return false;
    }
    // Before the banner the peer version is unknown, and at or above
    // A_VERSION_SKIP_CHECKSUM the field carries no checksum at all.
    if (peer_version_ != 0 && peer_version_ < kAdbVersionSkipChecksum &&
        AdbFrameChecksum(reinterpret_cast<const uint8_t*>(payload->data()), payload->size()) !=
            frame->data_check) {
        ADB_LOG_ERROR("Frame checksum mismatch");
        return false;
    }
    return true;
}

bool AdbConnection::Connect() {
    if (!stls_upgraded_) {
        ADB_LOG_INFO("Connect: sending CNXN");
        if (!SendFrame(kAdbCommandCnxn, kAdbVersion, kLocalMaxPayload, kBanner, sizeof(kBanner))) {
            return false;
        }
    }
    // After the STLS upgrade the device CNXN comes on its own; official adb
    // sends no CNXN of its own inside TLS.
    for (int round = 0; round < kMaxAuthRounds; round++) {
        AdbFrame frame;
        std::string payload;
        if (!ReadFrame(&frame, &payload)) {
            return false;
        }
        ADB_LOG_INFO("Connect: got cmd=0x%08x arg0=%u arg1=%u len=%u", frame.command, frame.arg0,
                     frame.arg1, frame.data_length);
        if (frame.command == kAdbCommandCnxn) {
            // adbd is done with authentication and is ready for services.
            peer_version_ = frame.arg0;
            peer_max_payload_ = frame.arg1;
            if (peer_max_payload_ == 0) {
                ADB_LOG_ERROR("Device banner has no payload size");
                return false;
            }
            return true;
        }
        if (frame.command != kAdbCommandAuth) {
            ADB_LOG_ERROR("Expected AUTH or CNXN, got 0x%08x", frame.command);
            return false;
        }
        if (frame.arg0 == kAdbAuthToken) {
            if (payload.size() != 20) {
                ADB_LOG_ERROR("AUTH token is %u bytes, expected 20",
                              static_cast<unsigned>(payload.size()));
                return false;
            }
            uint8_t signature[kSignatureSize];
            if (!signer_ || !signer_(reinterpret_cast<const uint8_t*>(payload.data()), signature)) {
                return false;
            }
            if (!SendFrame(kAdbCommandAuth, kAdbAuthSignature, 0, signature, sizeof(signature))) {
                return false;
            }
        } else if (frame.arg0 == kAdbAuthPublicKey) {
            // adbd only asks for the key when the signature was not accepted,
            // i.e. pairing did not register this key after all.
            if (public_key_.empty()) {
                return false;
            }
            if (!SendFrame(kAdbCommandAuth, kAdbAuthPublicKey, 0, public_key_.data(),
                           public_key_.size())) {
                return false;
            }
        } else {
            ADB_LOG_ERROR("Unexpected AUTH type %u", frame.arg0);
            return false;
        }
    }
    ADB_LOG_ERROR("adbd kept asking for authentication");
    return false;
}

bool AdbConnection::RunService(const std::string& service, const std::string& input,
                               std::string* output) {
    if (peer_max_payload_ == 0) {
        return false;
    }
    uint32_t local_id = next_local_id_++;
    std::string name = service;
    name.push_back('\0');
    if (!SendFrame(kAdbCommandOpen, local_id, 0, name.data(), name.size())) {
        return false;
    }

    const uint32_t chunk =
        peer_max_payload_ < kLocalMaxPayload ? peer_max_payload_ : kLocalMaxPayload;
    uint32_t remote_id = 0;
    size_t sent = 0;
    bool awaiting_ack = false;

    while (true) {
        AdbFrame frame;
        std::string payload;
        if (!ReadFrame(&frame, &payload)) {
            return false;
        }
        ADB_LOG_INFO("RunService: got cmd=0x%08x arg0=%u arg1=%u len=%u local_id=%u", frame.command,
                     frame.arg0, frame.arg1, frame.data_length, local_id);
        if (frame.arg1 != local_id) {
            ADB_LOG_DEBUG("Frame for stream %u (expected %u), cmd=0x%08x", frame.arg1, local_id,
                          frame.command);
            // A stream opened earlier closes a beat late; ignore the stale
            // CLSE and keep waiting for this stream's frames.
            continue;
        }
        if (frame.command == kAdbCommandWrite) {
            // adbd normally acknowledges the open first, but adopt its id from
            // the data frame if it did not.
            if (remote_id == 0) {
                remote_id = frame.arg0;
                if (remote_id == 0) {
                    return false;
                }
            }
            if (output != nullptr) {
                output->append(payload);
            }
            if (!SendFrame(kAdbCommandOkay, local_id, remote_id, nullptr, 0)) {
                return false;
            }
        } else if (frame.command == kAdbCommandOkay) {
            if (remote_id == 0) {
                remote_id = frame.arg0;
                if (remote_id == 0) {
                    return false;
                }
            }
            awaiting_ack = false;
        } else if (frame.command == kAdbCommandClose) {
            // adbd closing its side is the normal end of a shell command; the
            // host drops the stream without answering, as AOSP's adb does.
            // CLSE(0, ...) before OKAY means the service itself was refused.
            return remote_id != 0;
        } else {
            ADB_LOG_ERROR("Unexpected command 0x%08x during a service", frame.command);
            return false;
        }

        if (!awaiting_ack && sent < input.size()) {
            const size_t size = input.size() - sent < chunk ? input.size() - sent : chunk;
            if (!SendFrame(kAdbCommandWrite, local_id, remote_id, input.data() + sent, size)) {
                return false;
            }
            sent += size;
            awaiting_ack = true;
        }
    }
}
