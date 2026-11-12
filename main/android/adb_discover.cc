#include "adb_discover.h"

#include <cstdio>

#include <esp_log.h>

#include "mdns.h"

namespace {

constexpr char kTag[] = "AdbDiscover";
// adbd announces its TLS control channel under this service while the phone's
// "wireless debugging" switch is on.
constexpr const char* kServiceType = "_adb-tls-connect";
constexpr const char* kProto = "_tcp";
constexpr uint32_t kQueryTimeoutMs = 4000;
constexpr size_t kMaxResults = 8;

bool mdns_started = false;

std::string FirstIpv4(const mdns_result_t* result) {
    for (const mdns_ip_addr_t* addr = result->addr; addr != nullptr; addr = addr->next) {
        if (addr->addr.type == ESP_IPADDR_TYPE_V4) {
            // lwIP stores the IPv4 bytes in the low four positions.
            const uint32_t raw = addr->addr.u_addr.ip4.addr;
            char text[16];
            std::snprintf(text, sizeof(text), "%u.%u.%u.%u", (unsigned)(raw & 0xFF),
                          (unsigned)((raw >> 8) & 0xFF), (unsigned)((raw >> 16) & 0xFF),
                          (unsigned)((raw >> 24) & 0xFF));
            return text;
        }
    }
    return "";
}

}  // namespace

bool DiscoverAdbDevices(const std::string& prefer_host, std::vector<AdbCandidate>* candidates,
                        std::string* error) {
    candidates->clear();
    if (!mdns_started) {
        const esp_err_t started = mdns_init();
        if (started != ESP_OK) {
            *error = "网络发现服务启动失败";
            return false;
        }
        mdns_started = true;
    }
    mdns_result_t* results = nullptr;
    const esp_err_t err =
        mdns_query_ptr(kServiceType, kProto, kQueryTimeoutMs, kMaxResults, &results);
    if (err != ESP_OK || results == nullptr) {
        *error = "没有发现安卓设备的无线调试服务，请检查平板的「无线调试」是否打开";
        return false;
    }
    // Every record with an IPv4 is a candidate. A stale record can only be
    // told apart from a live one by connecting to it, so that decision
    // belongs to the caller, not here.
    for (const mdns_result_t* result = results; result != nullptr; result = result->next) {
        const std::string ip = FirstIpv4(result);
        if (ip.empty()) {
            continue;
        }
        AdbCandidate candidate{ip, result->port};
        if (!prefer_host.empty() && ip == prefer_host) {
            candidates->insert(candidates->begin(), candidate);
        } else {
            candidates->push_back(candidate);
        }
    }
    mdns_query_results_free(results);
    if (candidates->empty()) {
        *error = "发现了无线调试服务但没有可用地址";
        return false;
    }
    ESP_LOGI(kTag, "Discovered %u wireless debugging service(s)", (unsigned)candidates->size());
    for (const AdbCandidate& candidate : *candidates) {
        ESP_LOGI(kTag, "Candidate %s:%u", candidate.host.c_str(), candidate.port);
    }
    return true;
}
