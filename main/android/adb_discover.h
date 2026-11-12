#ifndef ADB_DISCOVER_H
#define ADB_DISCOVER_H

#include <cstdint>
#include <string>
#include <vector>

// One wireless debugging service found on the network.
struct AdbCandidate {
    std::string host;
    uint16_t port = 0;
};

// Finds the ADB-over-TLS devices on the network through mDNS
// (_adb-tls-connect._tcp, the service adbd announces while "wireless
// debugging" is on). The record matching |prefer_host| comes first when it is
// there; every other record follows in mDNS order. Records are only candidates:
// the caller verifies each by connecting, because a service record survives in
// caches after the phone's port has rotated.
bool DiscoverAdbDevices(const std::string& prefer_host, std::vector<AdbCandidate>* candidates,
                        std::string* error);

#endif
