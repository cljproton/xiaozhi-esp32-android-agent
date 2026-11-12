#include "android_phone.h"

#include <esp_log.h>
#include <chrono>
#include <mutex>
#include <thread>

#include "adb_crypto.h"
#include "adb_discover.h"
#include "adb_shell.h"
#include "board.h"
#include "display/display.h"
#include "settings.h"

namespace {

constexpr char kTag[] = "AndroidPhone";
constexpr int kHeartbeatIntervalSec = 15;

}  // namespace

AndroidPhone& AndroidPhone::Get() {
    static AndroidPhone phone;
    return phone;
}

AndroidPhone::AndroidPhone() {
    // Started once and never restarted: reconnections must not churn the
    // thread they run on (see HeartbeatLoop).
    heartbeat_thread_ = std::thread([this]() { HeartbeatLoop(); });
}

AndroidPhone::~AndroidPhone() {
    heartbeat_desired_.store(false);
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
}

void AndroidPhone::Disconnect() {
    // The connection holds a pointer to the stream, so it has to go first.
    StopHeartbeat();
    bool had_connection;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        had_connection = connection_ != nullptr;
        connection_.reset();
        stream_.reset();
        host_.clear();
        port_ = 0;
        width_ = 0;
        height_ = 0;
    }
    auto* display = Board::GetInstance().GetDisplay();
    if (display) {
        display->SetAndroidConnected(false);
        // Reconnect attempts that fail while already down would otherwise pop
        // this up again every heartbeat interval.
        if (had_connection) {
            display->ShowNotification("Android disconnected", 3000);
        }
    }
}

bool AndroidPhone::Open(const std::string& host, uint16_t port, std::string* error) {
    ESP_LOGI("AndroidPhone", "Open: host=%s port=%u", host.c_str(), port);
    AdbIdentity& identity = AdbIdentity::Get();
    if (!identity.EnsureReady()) {
        *error = "Cannot load the ADB key";
        ESP_LOGE("AndroidPhone", "Open: EnsureReady failed");
        return false;
    }

    Disconnect();
    auto stream = std::make_unique<AdbTlsStream>();
    ESP_LOGI("AndroidPhone", "Open: calling stream->Connect with upgrade_stls=true");
    // adbd checks the client certificate against the key list from pairing, so
    // the control port needs the same certificate as the pairing port.
    if (!stream->Connect(host, port, identity.certificate(), identity.private_key(),
                         /*upgrade_stls=*/true)) {
        *error = "Cannot reach the phone at " + host + ":" + std::to_string(port) +
                 ", is wireless debugging still on?";
        ESP_LOGE("AndroidPhone", "Open: stream->Connect failed");
        return false;
    }
    ESP_LOGI("AndroidPhone", "Open: stream->Connect succeeded, creating AdbConnection");

    AdbIdentity* key = &identity;
    auto connection = std::make_unique<AdbConnection>(
        stream.get(),
        [key](const uint8_t token[20], uint8_t signature[AdbConnection::kSignatureSize]) {
            return key->SignAuthToken(token, signature);
        },
        identity.encoded_public_key(), /*stls_upgraded=*/true);
    if (!connection->Connect()) {
        *error = "The phone refused the ADB key, pair again";
        ESP_LOGE("AndroidPhone", "Open: connection->Connect failed");
        return false;
    }
    ESP_LOGI("AndroidPhone", "Open: connection->Connect succeeded");

    {
        std::lock_guard<std::mutex> lock(mutex_);
        stream_ = std::move(stream);
        connection_ = std::move(connection);
        host_ = host;
        port_ = port;
        width_ = 0;
        height_ = 0;
    }
    ESP_LOGI(kTag, "Connected to phone at %s:%u", host.c_str(), port);
    auto* display = Board::GetInstance().GetDisplay();
    if (display) {
        display->ShowNotification("Android connected", 3000);
        display->SetAndroidConnected(true);
    }
    StartHeartbeat();
    // 平板自动锁屏时 MIUI 会杀掉无线调试（mDNS 记录也会变陈旧），长任务必然中途掉线。
    // 充电时保持屏幕常亮即可避免；平板没插电时此命令无效，需用户自己充电。失败不影响连接。
    std::string stayon_err;
    if (!RunCommand("svc power stayon true", nullptr, &stayon_err)) {
        ESP_LOGW(kTag, "stayon true failed: %s", stayon_err.c_str());
    }
    return true;
}

bool AndroidPhone::Pair(const std::string& host, uint16_t port, const std::string& code,
                        std::string* error) {
    std::string peer_key;
    if (!AdbPairWithPhone(host, port, code, &peer_key)) {
        *error = "Pairing failed, check the code and that the pairing dialog is still open";
        return false;
    }
    Settings settings("android", true);
    settings.SetString("host", host);
    ESP_LOGI(kTag, "Paired with %s, phone key is %u bytes", host.c_str(),
             static_cast<unsigned>(peer_key.size()));
    return true;
}

bool AndroidPhone::Connect(const std::string& host, uint16_t port, std::string* error) {
    if (!Open(host, port, error)) {
        return false;
    }
    Settings settings("android", true);
    settings.SetString("host", host);
    settings.SetInt("port", port);
    return true;
}

bool AndroidPhone::Discover(std::string* error) {
    std::string stored;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stored = host_;
    }
    std::vector<AdbCandidate> candidates;
    if (!DiscoverAdbDevices(stored, &candidates, error)) {
        return false;
    }
    // The remembered address first, then every other record: mDNS keeps serving
    // a record after the phone's port has rotated, so each candidate has to be
    // verified by connecting to it.
    for (const AdbCandidate& candidate : candidates) {
        std::string connect_error;
        if (Connect(candidate.host, candidate.port, &connect_error)) {
            return true;
        }
        ESP_LOGW(kTag, "Candidate %s:%u refused: %s", candidate.host.c_str(), candidate.port,
                 connect_error.c_str());
    }
    *error =
        "发现了 " + std::to_string(candidates.size()) +
        " 个无线调试服务，但没有一个能连上，端口可能已经轮换，请重新打开「无线调试」后告诉我新端口";
    return false;
}

bool AndroidPhone::EnsureConnected(std::string* error) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connection_ != nullptr) {
            return true;
        }
    }
    Settings settings("android");
    const std::string host = settings.GetString("host", "");
    const auto port = static_cast<uint16_t>(settings.GetInt("port", 5555));
    if (!host.empty() && Open(host, port, error)) {
        return true;
    }
    // The wireless debugging port changes whenever the switch is toggled, so
    // a stored address that no longer answers is normal: look the device up
    // again instead of telling the user to retype the port.
    ESP_LOGW(kTag, "Stored address unusable, discovering over mDNS");
    return Discover(error);
}

bool AndroidPhone::RunCommand(const std::string& command, std::string* output, std::string* error) {
    for (int attempt = 0; attempt < 2; attempt++) {
        if (!EnsureConnected(error)) {
            return false;
        }
        bool ok = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (connection_) {
                ok = connection_->RunService("exec:" + command, "", output);
            }
        }
        if (ok) {
            return true;
        }
        if (attempt == 0) {
            ESP_LOGW(kTag, "RunCommand dropped, reconnecting and retrying: %s", command.c_str());
            Disconnect();
            continue;
        }
        *error = "The connection to the phone dropped, try again";
        return false;
    }
    return false;
}

bool AndroidPhone::ScreenSize(int* width, int* height, std::string* error) {
    int cached_width = 0, cached_height = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cached_width = width_;
        cached_height = height_;
    }
    if (cached_width == 0 || cached_height == 0) {
        std::string output;
        if (!RunCommand("wm size", &output, error)) {
            return false;
        }
        int w = 0, h = 0;
        if (!adb_shell::ParseScreenSize(output, &w, &h)) {
            *error = "The phone did not report its screen size";
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            width_ = w;
            height_ = h;
            cached_width = w;
            cached_height = h;
        }
    }
    *width = cached_width;
    *height = cached_height;
    return true;
}

void AndroidPhone::StartHeartbeat() { heartbeat_desired_.store(true); }

void AndroidPhone::StopHeartbeat() { heartbeat_desired_.store(false); }

void AndroidPhone::HeartbeatLoop() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(kHeartbeatIntervalSec));
        if (!heartbeat_desired_.load()) {
            continue;
        }
        std::string output, error;
        if (RunCommand("echo heartbeat", &output, &error)) {
            continue;
        }
        // RunCommand already tore the dead connection down and tried one
        // reconnect (stored address, then mDNS discovery); the red dot is
        // showing. Keep the daemon alive and let the next interval retry, so
        // recovery does not wait for the next voice command.
        ESP_LOGW(kTag, "Heartbeat failed: %s, will retry", error.c_str());
    }
}
