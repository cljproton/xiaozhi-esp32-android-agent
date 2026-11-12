#ifndef ADB_FRAME_H
#define ADB_FRAME_H

// ADB wire framing, see system/core/adb/adb.h in AOSP. Every frame is a 24 byte
// little-endian header followed by data_length payload bytes.

#include <cstddef>
#include <cstdint>

#include "adb_io.h"

constexpr uint32_t kAdbCommandSync = 0x434e5953;  // "SYNC"
constexpr uint32_t kAdbCommandCnxn = 0x4e584e43;  // "CNXN"
constexpr uint32_t kAdbCommandOpen = 0x4e45504f;  // "OPEN"
constexpr uint32_t kAdbCommandOkay = 0x59414b4f;  // "OKAY"
constexpr uint32_t kAdbCommandClose = 0x45534c43; // "CLSE"
constexpr uint32_t kAdbCommandWrite = 0x45545257; // "WRTE"
constexpr uint32_t kAdbCommandAuth = 0x48545541;  // "AUTH"
constexpr uint32_t kAdbCommandStls = 0x534c5453;  // "STLS"

// A_AUTH arguments.
constexpr uint32_t kAdbAuthToken = 1;
constexpr uint32_t kAdbAuthSignature = 2;
constexpr uint32_t kAdbAuthPublicKey = 3;

// Official adb (v37) declares 0x01000001 and this payload limit; MIUI adbd
// misbehaves around OPEN with the smaller/older client identity we used before.
constexpr uint32_t kAdbVersion = 0x01000001;
constexpr uint32_t kAdbVersionSkipChecksum = 0x01000001;

// What we advertise in CNXN. adbd never sends more than the host's value.
constexpr uint32_t kAdbMaxPayload = 1024 * 1024;

constexpr size_t kAdbFrameSize = 24;

// Verbatim banner of the official adb client, sniffed from a live connection.
constexpr char kAdbBanner[] =
    "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,"
    "fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,"
    "sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,"
    "devicetracker_proto_format,devraw,app_info,server_status,track_mdns";

struct AdbFrame {
    uint32_t command = 0;
    uint32_t arg0 = 0;
    uint32_t arg1 = 0;
    uint32_t data_length = 0;
    uint32_t data_check = 0;
    uint32_t magic = 0;
};

// Serialises |frame|, filling in magic.
void AdbFrameEncode(AdbFrame frame, uint8_t out[kAdbFrameSize]);

// Returns false when magic does not match command (a stream desync).
bool AdbFrameDecode(const uint8_t in[kAdbFrameSize], AdbFrame* frame);

uint32_t AdbFrameChecksum(const uint8_t* data, size_t len);

// Runs the plaintext half of the wireless debugging handshake: send CNXN, wait
// for the phone's STLS, answer it. The caller starts TLS on the same stream
// afterwards, because adbd only switches to TLS once this exchange is done.
bool AdbRequestStls(AdbStream* stream);

#endif  // ADB_FRAME_H
