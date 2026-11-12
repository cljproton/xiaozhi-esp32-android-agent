#ifndef ADB_PAIRING_H
#define ADB_PAIRING_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "adb_io.h"

// The pairing protocol runs over a TLS 1.3 connection to adbd's pairing
// server, which is just a byte stream.
using AdbPairingStream = AdbStream;

// Runs the client half of ADB wireless pairing.
//
// |pairing_code| is the six digit code the phone dialog shows and
// |keying_material| the 64 bytes exported from the TLS session with the
// "adb-label" label; together they make up the SPAKE2 password. On success
// |peer_public_key| receives the phone's own ADB public key, which every later
// connection has to be verified against.
bool AdbPairingRun(AdbPairingStream* stream, const std::string& pairing_code,
                   const uint8_t keying_material[64], const std::string& our_public_key,
                   std::string* peer_public_key);

#endif  // ADB_PAIRING_H
