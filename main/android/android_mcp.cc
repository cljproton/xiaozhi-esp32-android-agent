#include "android_phone.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <esp_log.h>
#include <esp_pthread.h>
#include <esp_timer.h>

#include "adb_pin.h"
#include "adb_shell.h"
#include "application.h"
#include "board.h"
#include "mcp_server.h"
#include "settings.h"
#include "system_info.h"

namespace {

constexpr char kTag[] = "AndroidMcp";

// What the model read is stale after this long: the screen may have changed, and
// acting on the old list would tap the wrong place. The model takes 9-11s to
// think and speak between calls, so a short window only breeds "look again"
// round trips; the user stays off the tablet while the task runs.
constexpr int64_t kFrameTtlMs = 60 * 1000;
// Two reads within this window tell the model nothing new and cost a dump each.
constexpr int64_t kLookMinIntervalMs = 2 * 1000;
// Coordinates the model sends are 0..1000 over the screen in both directions.
constexpr int kCoordinateMax = 1000;
// A phone screen has more controls than this, but the ones past it are not worth
// the tokens: the model can scroll and look again.
constexpr size_t kMaxControlLines = 40;
// What the assistant did on the phone, newest last. Counts are small on purpose:
// this is for the user to glance at, not a forensic log.
constexpr int kAuditLines = 48;
constexpr int kAuditLineSize = 72;

int64_t frame_time_ms_ = 0;
bool frame_fresh_ = false;
// Focus package of the cached frame. Look only serves the cache when the
// freshly checked focus still matches it.
std::string frame_focus_;
// When the model last received a look, for the two-second repeat guard. Not
// the frame time: a prefetch-written frame is new, not a repeat look.
int64_t last_look_ms_ = 0;
// Controls of the last look, so tap can name one instead of aiming at pixels.
std::vector<adb_shell::UiNode> frame_nodes;
char audit_lines[kAuditLines][kAuditLineSize];
int audit_next = 0;
int audit_count = 0;
// Tool calls now run on their own thread; this guards the shared state above.
std::mutex state_mutex_;

int64_t NowMs() { return esp_timer_get_time() / 1000; }

// Keeps the idle timer from shutting the device down while a tool is using the
// phone. Cheap enough to do on every call.
void KeepAwake() { Board::GetInstance().SetPowerSaveLevel(PowerSaveLevel::PERFORMANCE); }

// One line per tool call, with the app it hit. Uptime instead of a clock: the
// device has no reliable wall time.
// shortcut: the record lives in RAM only and is lost on reboot; move it to NVS
// when it has to survive a power cycle.
void RecordAudit(const char* action, const std::string& package, const char* result) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    std::snprintf(audit_lines[audit_next], kAuditLineSize, "%llds %s %s %s",
                  static_cast<long long>(NowMs() / 1000), action,
                  package.empty() ? "unknown" : package.c_str(), result);
    audit_next = (audit_next + 1) % kAuditLines;
    if (audit_count < kAuditLines) {
        ++audit_count;
    }
}

// The last |count| lines, oldest first.
std::string AuditReport(int count) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    if (audit_count == 0) {
        return "Nothing recorded yet";
    }
    if (count > audit_count) {
        count = audit_count;
    }
    std::string text;
    for (int i = audit_count - count; i < audit_count; ++i) {
        text += audit_lines[(audit_next - audit_count + i + kAuditLines) % kAuditLines];
        text += '\n';
    }
    return text;
}

void ClearAudit() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    audit_next = 0;
    audit_count = 0;
}

// Packages the user blocked themselves, on top of the built in list in
// adb_shell.h. Kept in NVS so they survive a reboot.
constexpr char kBlockedKey[] = "blocked";

// Pairing hands the phone to whatever address and code were spoken, and a wrong
// digit can point at another device. So the details are read back to the user
// first: the first call only records them, and nothing is attempted until a
// second call repeats them with confirm=true.
bool pair_pending = false;
std::string pair_pending_host;
std::string pair_pending_code;
uint16_t pair_pending_port = 0;

// Loaded once, then kept in sync with NVS by BlockedListSet.
std::string& BlockedList() {
    static std::string list;
    static bool loaded = false;
    if (!loaded) {
        Settings settings("android");
        list = settings.GetString(kBlockedKey);
        loaded = true;
    }
    return list;
}

void BlockedListSet(const std::string& list) {
    Settings settings("android", true);
    settings.SetString(kBlockedKey, list);
    BlockedList() = list;
}

// When the model last marked the whole task complete (self.android.done).
// A goodbye within the window after this is the natural end of a finished
// task, not a server cut, so auto-resume skips it.
int64_t done_ms_ = 0;

// The model forgets what it typed whenever a session is cut and resumed: the
// only memory of the essay text it can rely on is what the device stored.
// One NVS string, newest text appended, trimmed from the front past the cap.
constexpr char kRecentKey[] = "recent";
constexpr size_t kRecentMaxBytes = 3000;

std::string& RecentText() {
    static std::string text;
    static bool loaded = false;
    if (!loaded) {
        Settings settings("android");
        text = settings.GetString(kRecentKey);
        loaded = true;
    }
    return text;
}

// When the model last read the recent-typing buffer, and what it got: a
// repeated read within a few seconds returns the same text without a new
// round of thinking in between.
int64_t last_recent_read_ms_ = 0;
std::string last_recent_read_;

// When the recent-typing buffer was last written: a launch that starts a
// new task resets a stale buffer instead of piling onto old sessions' text.
int64_t recent_last_write_ms_ = 0;

// Called after every successful typing tool call. A newline between calls
// keeps word boundaries visible even when none was typed.
void RecordTypedText(const std::string& text) {
    if (text.empty()) {
        return;
    }
    recent_last_write_ms_ = NowMs();
    // A repeated recent read must not hand back text older than this write
    last_recent_read_ms_ = 0;
    std::string& recent = RecentText();
    recent += text;
    recent += '\n';
    if (recent.size() > kRecentMaxBytes) {
        // Cut whole characters off the front: a half code point would make
        // the string the server receives invalid UTF-8.
        std::string tail = recent.substr(recent.size() - kRecentMaxBytes);
        size_t start = 0;
        while (start < tail.size() && (static_cast<unsigned char>(tail[start]) & 0xc0) == 0x80) {
            start++;
        }
        recent = tail.substr(start);
    }
    Settings settings("android", true);
    settings.SetString(kRecentKey, recent);
}

// A launch opens the app for the current task. When the recent-typing buffer
// is stale (over 10 minutes since its last write: essays left by past test
// runs and sessions confused the model into reading three "current" essays),
// reset it so only the current task's text remains; a re-launch during a
// running task keeps the text and just appends a boundary marker.
void RecordTaskStart() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    if (recent_last_write_ms_ != 0 && NowMs() - recent_last_write_ms_ > 600 * 1000) {
        RecentText().clear();
        Settings settings("android", true);
        settings.SetString(kRecentKey, "");
    }
    RecordTypedText("==== 新任务开始 ====");
}

// Screen privacy gate. Refuses before the tool does anything when the app in
// front is one of the private ones, or one the user blocked themselves, and
// records what every call hit either way. A package name that cannot be read
// counts as safe: what the phone shows is then unknown to the gate, but the
// action is still recorded as "unknown".
std::string SensitiveFocusError(const char* action, std::string* focus = nullptr) {
    std::string output;
    std::string error;
    std::string package;
    if (AndroidPhone::Get().RunCommand(adb_shell::FocusCommand(), &output, &error)) {
        package = adb_shell::ParseFocusPackage(output);
    } else {
        ESP_LOGW(kTag, "FocusCommand failed: error=%s", error.c_str());
    }
    ESP_LOGI(kTag, "FocusCommand raw output: '%s'", output.c_str());
    if (focus != nullptr) {
        *focus = package;
    }
    if (!adb_shell::IsSensitivePackage(package) &&
        !adb_shell::ListContains(BlockedList(), package)) {
        RecordAudit(action, package, "ok");
        return "";
    }
    RecordAudit(action, package, "blocked");
    ESP_LOGW(kTag, "Refused %s on private app %s", action, package.c_str());
    return "The phone is showing a private app (" + package +
           "), so nothing was shown or touched. Ask the user to switch to the app they meant.";
}

// Launch gates on the app being opened, not the one on screen: entering a
// private app is refused even when the harmless launcher is showing.
std::string SensitiveTargetError(const char* action, const std::string& package) {
    if (adb_shell::IsSensitivePackage(package) || adb_shell::ListContains(BlockedList(), package)) {
        RecordAudit(action, package, "blocked");
        ESP_LOGW(kTag, "Refused %s of private app %s", action, package.c_str());
        return "That app is on the private list, so it will not be opened.";
    }
    RecordAudit(action, package, "ok");
    return "";
}

// The server never shows the model a picture, but it does run a vision service
// for the camera. A screen with no readable controls is sent there and only the
// words come back. Empty when that service is missing or fails.
std::string DescribeScreenshot() {
    const std::string url = ServerVisionUrl();
    if (url.empty()) {
        return "";
    }
    std::string png;
    std::string error;
    if (!AndroidPhone::Get().RunCommand("screencap -p", &png, &error) || png.empty()) {
        return "";
    }
    auto& board = Board::GetInstance();
    auto http = board.GetNetwork()->CreateHttp(3);
    const std::string boundary = "----ESP32_ANDROID";
    const std::string token = ServerVisionToken();
    http->SetHeader("Device-Id", SystemInfo::GetMacAddress().c_str());
    http->SetHeader("Client-Id", board.GetUuid().c_str());
    if (!token.empty()) {
        http->SetHeader("Authorization", "Bearer " + token);
    }
    http->SetHeader("Content-Type", "multipart/form-data; boundary=" + boundary);
    http->SetHeader("Transfer-Encoding", "chunked");
    if (auto opened = http->Open("POST", url); !opened) {
        ESP_LOGW(kTag, "Vision open failed: %s", opened.error().ToString().c_str());
        return "";
    }
    const std::string question =
        "这是一张安卓平板截图。用一段中文说明当前是什么界面，并列出可以点击的东西大概在屏幕的"
        "上下左右哪个位置。只说看到的，不要猜。";
    std::string head = "--" + boundary +
                       "\r\nContent-Disposition: form-data; name=\"question\"\r\n\r\n" + question +
                       "\r\n--" + boundary +
                       "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"screen.png\""
                       "\r\nContent-Type: image/png\r\n\r\n";
    const std::string tail = "\r\n--" + boundary + "--\r\n";
    bool written = head.size() > 0;
    written = written && http->Write(head.data(), head.size()).has_value();
    // A screenshot is megabytes; a single write call would have to buffer it.
    constexpr size_t kUploadChunk = 8192;
    for (size_t offset = 0; written && offset < png.size(); offset += kUploadChunk) {
        const size_t size = std::min(kUploadChunk, png.size() - offset);
        written = http->Write(png.data() + offset, size).has_value();
    }
    written = written && http->Write(tail.data(), tail.size()).has_value();
    // The body is sent chunked, so a zero length write is what ends it.
    written = written && http->Write("", 0).has_value();
    if (!written) {
        ESP_LOGW(kTag, "Vision upload failed");
        http->Close();
        return "";
    }
    auto status = http->GetStatusCode();
    if (!status || *status != 200) {
        ESP_LOGW(kTag, "Vision status %d", status ? *status : -1);
        http->Close();
        return "";
    }
    std::string answer = http->ReadAll();
    http->Close();
    adb_shell::TruncateUtf8(&answer, 1500);
    return answer;
}

// Opens |package| through monkey, falling back to resolving the launcher
// activity when the ROM refuses monkey. Empty string on success, else a
// user-presentable error.
std::string LaunchPackage(const std::string& package) {
    std::string output;
    std::string error;
    if (AndroidPhone::Get().RunCommand(adb_shell::LaunchCommand(package), &output, &error) &&
        output.find("Events injected") != std::string::npos) {
        return "";
    }
    std::string resolved;
    if (!AndroidPhone::Get().RunCommand("cmd package resolve-activity --brief " + package,
                                        &resolved, &error)) {
        return "Could not launch " + package + ": " + error;
    }
    const std::string activity = adb_shell::LastNonEmptyLine(resolved);
    if (activity.find('/') == std::string::npos) {
        return package + " is not installed, or has no launcher activity";
    }
    if (!AndroidPhone::Get().RunCommand("am start -n " + activity, nullptr, &error)) {
        return "Could not launch " + package + ": " + error;
    }
    return "";
}

// Every action invalidates the screen the model last read: the next tap has to
// be aimed at the current screen, not at the one from before the action.
void InvalidateFrame() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    frame_fresh_ = false;
    frame_focus_.clear();
    frame_nodes.clear();
}

void StoreFrame(const std::string& focus, const std::vector<adb_shell::UiNode>& nodes) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    frame_nodes = nodes;
    frame_time_ms_ = NowMs();
    frame_fresh_ = true;
    frame_focus_ = focus;
}

// How long a prefetched frame stays servable: past this the user may have
// touched the tablet and the cache would aim the next tap at a dead screen.
constexpr int64_t kPrefetchTtlMs = 8 * 1000;
constexpr int kPrefetchDelayMs = 800;
// A cold app start takes seconds before its first screen is drawn.
constexpr int kLaunchPrefetchDelayMs = 2500;

// After an action the screen has moved on, and the next look would pay ~10s
// for a fresh uiautomator dump. Fetch it in the background instead: the look
// after a tap then returns in under a second. Everything that fails just
// leaves the cache empty, and look falls back to the full path.
void SchedulePrefetch(int delay_ms = kPrefetchDelayMs) {
    auto& phone = AndroidPhone::Get();
    if (!phone.connected()) {
        return;
    }
    const esp_pthread_cfg_t default_cfg = esp_pthread_get_default_config();
    esp_pthread_cfg_t cfg = default_cfg;
    cfg.stack_size = 16 * 1024;
    esp_pthread_set_cfg(&cfg);
    std::thread([delay_ms]() {
        // Let the tap animation settle so the dump shows the settled screen.
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        KeepAwake();
        std::string output;
        std::string error;
        if (!AndroidPhone::Get().RunCommand(adb_shell::FocusCommand(), &output, &error)) {
            return;
        }
        const std::string focus = adb_shell::ParseFocusPackage(output);
        // Never cache a private app's screen: a cache hit must not shortcut
        // the privacy gate. Unreadable focus goes uncached too, look then
        // takes the full path where the gate decides.
        if (focus.empty() || adb_shell::IsSensitivePackage(focus) ||
            adb_shell::ListContains(BlockedList(), focus)) {
            return;
        }
        if (!AndroidPhone::Get().RunCommand(adb_shell::UiDumpCommand(), &output, &error)) {
            return;
        }
        // Games and video expose no controls; look handles those with the
        // screenshot path, there is nothing to prefetch.
        std::vector<adb_shell::UiNode> nodes = adb_shell::ParseUiNodes(output);
        if (nodes.empty()) {
            return;
        }
        StoreFrame(focus, nodes);
        ESP_LOGI(kTag, "Prefetched frame for %s (%u controls)", focus.c_str(),
                 (unsigned)nodes.size());
    }).detach();
    esp_pthread_set_cfg(&default_cfg);
}

std::string FreshFrameError() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    if (!frame_fresh_) {
        return "Call self.android.look first and act on what it lists";
    }
    if (NowMs() - frame_time_ms_ > kFrameTtlMs) {
        return "What you read is more than a minute old, call self.android.look again";
    }
    return "";
}

int Scale(int value, int size) { return value * size / kCoordinateMax; }

// Screen size of the connected phone, or an error the tool can pass on.
bool ScreenSize(int* width, int* height, std::string* error) {
    return AndroidPhone::Get().ScreenSize(width, height, error);
}

int IntProperty(const PropertyList& properties, const char* name) {
    return properties[name].value<int>();
}

}  // namespace

// True when the model marked the current task done within the last 2 minutes.
// Called from the protocol's goodbye handler to skip the natural end of a
// finished task.
bool AndroidTaskDoneRecently() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return done_ms_ != 0 && NowMs() - done_ms_ < 120 * 1000;
}

// The ADBKeyboard input method lets any Unicode text be committed through a
// broadcast. Its IME id, and the remembered default the tablet had before.
constexpr char kAdbIme[] = "com.android.adbkeyboard/.AdbIME";
constexpr char kFallbackIme[] =
    "com.google.android.inputmethod.latin/com.android.inputmethod.latin.LatinIME";
// Input-method switches come from tool threads; guarded like the frame state.
std::mutex ime_mutex_;
std::string default_ime_;
bool ime_switched_ = false;

// Switches the input method to ADBKeyboard. The first call remembers the IME
// that was in front, so RestoreIme can put it back when the typing is done.
std::string EnsureAdbIme() {
    std::lock_guard<std::mutex> lock(ime_mutex_);
    if (ime_switched_) {
        return "";
    }
    std::string output;
    std::string error;
    if (!AndroidPhone::Get().RunCommand("settings get secure default_input_method", &output,
                                        &error)) {
        return "Could not read the current input method: " + error;
    }
    output = adb_shell::BatchTrim(output);
    default_ime_ = output == kAdbIme ? kFallbackIme : output;
    if (default_ime_.find('/') == std::string::npos) {
        return "The tablet reports no usable default input method";
    }
    if (default_ime_ != kAdbIme) {
        if (!AndroidPhone::Get().RunCommand(std::string("ime enable ") + kAdbIme, nullptr,
                                            &error) ||
            !AndroidPhone::Get().RunCommand(std::string("ime set ") + kAdbIme, nullptr, &error)) {
            return "Could not switch to the ADBKeyboard input method: " + error;
        }
        // The input connection of a freshly switched keyboard takes a moment
        // to bind; a broadcast sent right away can land nowhere.
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    ime_switched_ = true;
    ESP_LOGI(kTag, "Input method switched to ADBKeyboard (was %s)", default_ime_.c_str());
    return "";
}

// Puts the original input method back. Fails soft: a stuck keyboard is worse
// than no keyboard, but it must not fail the tool call that already typed.
void RestoreIme() {
    std::lock_guard<std::mutex> lock(ime_mutex_);
    if (!ime_switched_) {
        return;
    }
    ime_switched_ = false;
    std::string error;
    if (!AndroidPhone::Get().RunCommand(std::string("ime set ") + default_ime_, nullptr, &error)) {
        ESP_LOGW(kTag, "RestoreIme failed: %s", error.c_str());
    }
}

// Helper: ensure phone is connected, or return a user-facing message asking to connect.
static std::string EnsurePhoneConnected(const char* action) {
    auto& phone = AndroidPhone::Get();
    // Ensures, and reconnects when needed, instead of trusting a flag: another
    // thread may be mid-reconnect, and a bare flag check would report the
    // phone as gone while it is one second from being back.
    std::string error;
    if (!phone.EnsureConnected(&error)) {
        ESP_LOGW(kTag, "%s: phone not connected: %s", action, error.c_str());
        return "安卓手机未连接，请打开平板的「无线调试」开关，然后说「连接安卓」。";
    }
    return "";
}

// NVS keys for connection info (wireless debugging screen IP:port)
static constexpr char kConnHostKey[] = "host";
static constexpr char kConnPortKey[] = "port";

// NVS keys for pairing info (pairing dialog IP:port + code)
static constexpr char kPairHostKey[] = "pair_host";
static constexpr char kPairPortKey[] = "pair_port";
static constexpr char kPairCodeKey[] = "pair_code";

// Get stored connection info.
static std::string GetConnInfo() {
    Settings settings("android");
    std::string host = settings.GetString(kConnHostKey, "");
    if (host.empty()) {
        return "连接地址: 未设置";
    }
    uint16_t port = static_cast<uint16_t>(settings.GetInt(kConnPortKey, 5555));
    return "连接地址: " + host + ":" + std::to_string(port);
}

// Set connection info.
static void SetConnInfo(const std::string& host, uint16_t port) {
    Settings settings("android", true);
    settings.SetString(kConnHostKey, host);
    settings.SetInt(kConnPortKey, port);
}

// Get stored pairing info.
static std::string GetPairInfo() {
    Settings settings("android");
    std::string host = settings.GetString(kPairHostKey, "");
    if (host.empty()) {
        return "配对信息: 未配对";
    }
    uint16_t port = static_cast<uint16_t>(settings.GetInt(kPairPortKey, 0));
    std::string code = settings.GetString(kPairCodeKey, "");
    return "配对信息: " + host + ":" + std::to_string(port) +
           (code.empty() ? "" : " (配对码已保存)");
}

// Save pairing info to NVS.
static void SavePairInfo(const std::string& host, uint16_t port, const std::string& code) {
    Settings settings("android", true);
    settings.SetString(kPairHostKey, host);
    settings.SetInt(kPairPortKey, port);
    settings.SetString(kPairCodeKey, code);
}

// Clear pairing info.
static void ClearPairInfo() {
    Settings settings("android", true);
    settings.SetString(kPairHostKey, "");
    settings.SetInt(kPairPortKey, 0);
    settings.SetString(kPairCodeKey, "");
}

void RegisterAndroidTools() {
    auto& mcp_server = McpServer::GetInstance();
    auto& phone = AndroidPhone::Get();

    mcp_server.AddTool(
        "self.android.pair",
        "Pair with an Android phone over Wi-Fi so it can be controlled by voice.\n"
        "The user opens Settings - Developer options - Wireless debugging - Pair device with "
        "pairing code, reads the six digit code aloud and says the IP address and pairing port "
        "shown in that dialog. Only needed once per phone.\n"
        "The first call pairs nothing: it returns the details, read them back to the user and wait "
        "for a yes. Only then call it again with the same host, port, code and confirm=true.\n"
        "After pairing, say connect: self.android.connect finds the device on the network by "
        "itself.",
        PropertyList({Property("host", kPropertyTypeString).SetMaxLength(64),
                      Property("port", kPropertyTypeInteger, 1, 65535),
                      Property("code", kPropertyTypeString).SetMaxLength(16),
                      Property("confirm", kPropertyTypeBoolean, false)}),
        [&phone](const PropertyList& properties) -> ToolResult {
            const std::string host = properties["host"].value<std::string>();
            const auto port = static_cast<uint16_t>(IntProperty(properties, "port"));
            const std::string code =
                AdbNormalizePairingCode(properties["code"].value<std::string>());
            if (code.empty()) {
                return std::unexpected("That is not a six digit pairing code, ask the user again");
            }

            // Check if already paired (has pair_host in NVS)
            Settings settings("android");
            std::string existing_host = settings.GetString(kPairHostKey, "");
            if (!existing_host.empty()) {
                // Already paired, check if trying to pair with same device
                uint16_t existing_port = static_cast<uint16_t>(settings.GetInt(kPairPortKey, 0));
                if (existing_host == host && existing_port == port) {
                    return "已配对该设备：" + host + ":" + std::to_string(port) +
                           "，无需重复配对。";
                }
                // Different device - warn but allow
                return "已配对其他设备：" + existing_host + ":" + std::to_string(existing_port) +
                       "。如需配对新设备，请先用 self.android.status {action: clear_pair} "
                       "清除配对记录。";
            }

            const bool confirmed = properties["confirm"].value<bool>();
            const bool repeated = pair_pending && pair_pending_host == host &&
                                  pair_pending_port == port && pair_pending_code == code;
            if (!confirmed || !repeated) {
                pair_pending = true;
                pair_pending_host = host;
                pair_pending_port = port;
                pair_pending_code = code;
                return std::string(
                           "Read this to the user in Chinese and ask whether it is right: "
                           "要配对的设备 ") +
                       host + "，端口 " + std::to_string(port) + "，配对码 " + code +
                       "。Nothing is paired yet. Only after the user says it is correct, call "
                       "self.android.pair again with the same host, port, code and confirm=true.";
            }
            pair_pending = false;
            KeepAwake();
            std::string error;
            if (!phone.Pair(host, port, code, &error)) {
                return std::unexpected(error);
            }
            SavePairInfo(host, port, code);
            return std::string("Paired with ") + host +
                   ". Now call self.android.connect with the IP address and port from the "
                   "Wireless debugging screen";
        });

    mcp_server.AddTool(
        "self.android.connect",
        "Connect to the Android phone. With no arguments it finds the device on the Wi-Fi "
        "network automatically, as long as wireless debugging is switched on. Or pass the IP "
        "address and port shown on the Wireless debugging screen, for example 192.168.1.20 and "
        "41235, when automatic discovery fails. Later calls reconnect on their own.",
        PropertyList({Property("host", kPropertyTypeString, std::string("")).SetMaxLength(64),
                      // 0 means "find the device automatically", so it must be
                      // inside the declared range: the default is checked.
                      Property("port", kPropertyTypeInteger, 0, 0, 65535)}),
        [&phone](const PropertyList& properties) -> ToolResult {
            KeepAwake();
            std::string error;
            const std::string host = properties["host"].value<std::string>();
            const auto port = static_cast<uint16_t>(IntProperty(properties, "port"));
            // An explicit address that no longer answers usually means the
            // phone's wireless debugging port changed: look the device up
            // again before giving up.
            if (!host.empty() && port != 0 && phone.Connect(host, port, &error)) {
                return std::string("Connected to ") + host;
            }
            // No address given, or the given one is dead: the remembered one
            // first (fails in seconds), then a live mDNS lookup over every
            // record, each verified by connecting.
            if (phone.EnsureConnected(&error)) {
                return std::string("Connected");
            }
            return std::unexpected(error);
        });

    mcp_server.AddTool(
        "self.android.status",
        "Show or update Android connection/pairing info, or read back what has been typed on "
        "the phone.\n"
        "action: show | set_conn | clear_pair | recent\n"
        "host/port: for set_conn (connection IP:port from Wireless debugging screen)\n"
        "recent: the text typed in past tool calls, newest last. Read this when resuming a "
        "writing task you no longer remember, then look and continue after the cursor.\n"
        "Examples:\n"
        "  self.android.status {action: show}\n"
        "  self.android.status {action: recent}\n"
        "  self.android.status {action: set_conn, host: 192.168.1.165, port: 44293}\n"
        "  self.android.status {action: clear_pair}",
        PropertyList({Property("action", kPropertyTypeString).SetMaxLength(16),
                      Property("host", kPropertyTypeString).SetMaxLength(64),
                      Property("port", kPropertyTypeInteger, 1, 65535)}),
        [](const PropertyList& properties) -> ToolResult {
            const std::string action = properties["action"].value<std::string>();
            if (action == "show") {
                return GetConnInfo() + "\n" + GetPairInfo();
            }
            if (action == "recent") {
                std::lock_guard<std::mutex> lock(state_mutex_);
                if (last_recent_read_ms_ != 0 && NowMs() - last_recent_read_ms_ < 5000) {
                    return "Same text as you just read:\n" + last_recent_read_;
                }
                last_recent_read_ms_ = NowMs();
                std::string recent = RecentText();
                // Recent buffer may contain stale essays from past sessions. Only return
                // text after the last task-start marker so the model sees the current
                // task's typed content, not a pile of old sessions.
                constexpr char kTaskStartMarker[] = "==== 新任务开始 ====";
                size_t pos = recent.rfind(kTaskStartMarker);
                if (pos != std::string::npos) {
                    recent = recent.substr(pos + strlen(kTaskStartMarker));
                    // Drop leading newlines from the marker
                    size_t first = recent.find_first_not_of('\n');
                    if (first != std::string::npos) {
                        recent = recent.substr(first);
                    } else {
                        recent.clear();
                    }
                }
                last_recent_read_ = recent;
                return last_recent_read_.empty() ? std::string("Nothing has been typed yet")
                                                 : last_recent_read_;
            }
            if (action == "set_conn") {
                const std::string host = properties["host"].value<std::string>();
                const auto port = static_cast<uint16_t>(IntProperty(properties, "port"));
                if (host.empty() || port == 0) {
                    return std::unexpected("set_conn 需要 host 和 port");
                }
                SetConnInfo(host, port);
                return "已更新连接地址为 " + host + ":" + std::to_string(port);
            }
            if (action == "clear_pair") {
                ClearPairInfo();
                return "已清除配对记录，下次需重新配对";
            }
            return std::unexpected("未知 action: " + action +
                                   "，可用: show, set_conn, clear_pair, recent");
        });

    mcp_server.AddTool(
        "self.android.look",
        "Read the screen of the Android phone the user is holding: the app in front and a numbered "
        "list of the controls on it. Always look before an action, and look again after one. Give "
        "the numbers to self.android.tap, or x/y 0..1000 over the screen when no controls are "
        "listed.",
        PropertyList(), [](const PropertyList& properties) -> ToolResult {
            KeepAwake();
            const std::string conn_err = EnsurePhoneConnected("look");
            if (!conn_err.empty()) {
                return std::unexpected(conn_err);
            }
            {
                std::lock_guard<std::mutex> lock(state_mutex_);
                if (last_look_ms_ != 0 && NowMs() - last_look_ms_ < kLookMinIntervalMs) {
                    return std::unexpected(
                        "You looked less than two seconds ago, what you already have is still "
                        "current");
                }
            }
            std::string focus;
            const std::string private_app = SensitiveFocusError("look", &focus);
            if (!private_app.empty()) {
                return std::unexpected(private_app);
            }
            // The cache from a prefetch after the last action: only good while
            // the app in front is still the one the frame was read from.
            std::vector<adb_shell::UiNode> cached;
            bool cache_hit = false;
            {
                std::lock_guard<std::mutex> lock(state_mutex_);
                if (frame_fresh_ && frame_focus_ == focus && !frame_nodes.empty() &&
                    NowMs() - frame_time_ms_ < kPrefetchTtlMs) {
                    cached = frame_nodes;
                    cache_hit = true;
                    last_look_ms_ = NowMs();
                }
            }
            if (cache_hit) {
                ESP_LOGI(kTag, "Look served from prefetch cache (%u controls)",
                         (unsigned)cached.size());
                int width = 0;
                int height = 0;
                std::string size_error;
                ScreenSize(&width, &height, &size_error);
                return adb_shell::FormatUiNodes(cached, width, height, focus, kMaxControlLines) +
                       "Tap with self.android.tap index=N, or x/y 0..1000 when nothing is listed. "
                       "Never act one call at a time: put the next several certain steps in ONE "
                       "self.android.batch call. A writing task is only done when the whole text "
                       "is on the page (a short essay is 200+ characters) and saved; do not "
                       "finish early or say goodbye before that. When it is done, call "
                       "self.android.done.";
            }
            std::string error;
            std::string dump;
            if (!AndroidPhone::Get().RunCommand(adb_shell::UiDumpCommand(), &dump, &error)) {
                return std::unexpected(error);
            }
            std::vector<adb_shell::UiNode> nodes = adb_shell::ParseUiNodes(dump);
            // Games, video and anything drawn by hand expose no controls. The
            // server's vision service can still say what is on the screen, even
            // though the model itself cannot see a picture.
            if (nodes.empty()) {
                const std::string described = DescribeScreenshot();
                if (!described.empty()) {
                    StoreFrame(focus, {});
                    return std::string("No controls on this screen. What is on it: ") + described;
                }
            }
            int width = 0;
            int height = 0;
            std::string size_error;
            ScreenSize(&width, &height, &size_error);
            StoreFrame(focus, nodes);
            {
                std::lock_guard<std::mutex> lock(state_mutex_);
                last_look_ms_ = NowMs();
            }
            return adb_shell::FormatUiNodes(nodes, width, height, focus, kMaxControlLines) +
                   "Tap with self.android.tap index=N, or x/y 0..1000 when nothing is listed. "
                   "Never act one call at a time: put the next several certain steps in ONE "
                   "self.android.batch call. A writing task is only done when the whole text "
                   "is on the page (a short essay is 200+ characters) and saved; do not "
                   "finish early or say goodbye before that. When it is done, call "
                   "self.android.done.";
        });

    mcp_server.AddTool(
        "self.android.tap",
        "Tap something on the phone screen. Pass index=N to tap control N from the last "
        "self.android.look, which is what you normally want; or x and y, 0..1000 from the top "
        "left, when the screen listed no controls. x and y are percents of the screen width and "
        "height, never pixel values. What you read is used up by the tap, so call "
        "self.android.look again before the next action.",
        PropertyList({Property("index", kPropertyTypeInteger, 0, 0, kCoordinateMax),
                      Property("x", kPropertyTypeInteger, 0, 0, kCoordinateMax),
                      Property("y", kPropertyTypeInteger, 0, 0, kCoordinateMax)}),
        [](const PropertyList& properties) -> ToolResult {
            KeepAwake();
            const std::string conn_err = EnsurePhoneConnected("tap");
            if (!conn_err.empty()) {
                return std::unexpected(conn_err);
            }
            const std::string stale = FreshFrameError();
            if (!stale.empty()) {
                return std::unexpected(stale);
            }
            int x = 0;
            int y = 0;
            const int index = IntProperty(properties, "index");
            if (index > 0) {
                std::lock_guard<std::mutex> lock(state_mutex_);
                if (static_cast<size_t>(index) > frame_nodes.size()) {
                    return std::unexpected("There is no control " + std::to_string(index) +
                                           ", call self.android.look again");
                }
                const adb_shell::UiNode& node = frame_nodes[index - 1];
                x = (node.x1 + node.x2) / 2;
                y = (node.y1 + node.y2) / 2;
            } else {
                const int raw_x = IntProperty(properties, "x");
                const int raw_y = IntProperty(properties, "y");
                if (raw_x == 0 && raw_y == 0) {
                    return std::unexpected(
                        "Pass index=N to tap a listed control, or x and y to tap a point");
                }
                int width = 0;
                int height = 0;
                std::string size_error;
                if (!ScreenSize(&width, &height, &size_error)) {
                    return std::unexpected(size_error);
                }
                x = Scale(raw_x, width);
                y = Scale(raw_y, height);
            }
            std::string error;
            const std::string private_app = SensitiveFocusError("tap");
            if (!private_app.empty()) {
                return std::unexpected(private_app);
            }
            if (!AndroidPhone::Get().RunCommand(adb_shell::TapCommand(x, y), nullptr, &error)) {
                return std::unexpected(error);
            }
            InvalidateFrame();
            SchedulePrefetch();
            return true;
        });

    mcp_server.AddTool(
        "self.android.swipe",
        "Swipe on the phone screen, for scrolling and unlocking. Start and end points use the "
        "coordinates of the last look, 0..1000 from the top left; these are percents of the "
        "screen width and height, never pixel values. duration_ms is how long "
        "the finger takes, 100..3000.",
        PropertyList({Property("x1", kPropertyTypeInteger, 0, kCoordinateMax),
                      Property("y1", kPropertyTypeInteger, 0, kCoordinateMax),
                      Property("x2", kPropertyTypeInteger, 0, kCoordinateMax),
                      Property("y2", kPropertyTypeInteger, 0, kCoordinateMax),
                      Property("duration_ms", kPropertyTypeInteger, 300, 100, 3000)}),
        [](const PropertyList& properties) -> ToolResult {
            KeepAwake();
            const std::string conn_err = EnsurePhoneConnected("swipe");
            if (!conn_err.empty()) {
                return std::unexpected(conn_err);
            }
            const std::string stale = FreshFrameError();
            if (!stale.empty()) {
                return std::unexpected(stale);
            }
            int width = 0;
            int height = 0;
            std::string error;
            if (!ScreenSize(&width, &height, &error)) {
                return std::unexpected(error);
            }
            const std::string command =
                adb_shell::SwipeCommand(Scale(IntProperty(properties, "x1"), width),
                                        Scale(IntProperty(properties, "y1"), height),
                                        Scale(IntProperty(properties, "x2"), width),
                                        Scale(IntProperty(properties, "y2"), height),
                                        IntProperty(properties, "duration_ms"));
            const std::string private_app = SensitiveFocusError("swipe");
            if (!private_app.empty()) {
                return std::unexpected(private_app);
            }
            if (!AndroidPhone::Get().RunCommand(command, nullptr, &error)) {
                return std::unexpected(error);
            }
            InvalidateFrame();
            SchedulePrefetch();
            return true;
        });

    mcp_server.AddTool(
        "self.android.type",
        "Type text into the focused input field of the phone. ASCII text goes as typed; "
        "Chinese characters are committed through the phone's input method and work too, so "
        "just send the real Chinese text, for example 我的梦想. A new line is key enter, not "
        "part of the text. When resuming a writing task, read what was already typed once "
        "with self.android.status {action: recent}, look, then continue after the cursor "
        "instead of starting over.",
        PropertyList({Property("text", kPropertyTypeString).SetMaxLength(200)}),
        [](const PropertyList& properties) -> ToolResult {
            KeepAwake();
            const std::string conn_err = EnsurePhoneConnected("type");
            if (!conn_err.empty()) {
                return std::unexpected(conn_err);
            }
            const std::string text = properties["text"].value<std::string>();
            std::string error;
            if (adb_shell::IsTypeable(text)) {
                const std::string private_app = SensitiveFocusError("type");
                if (!private_app.empty()) {
                    return std::unexpected(private_app);
                }
                if (!AndroidPhone::Get().RunCommand(adb_shell::TextCommand(text), nullptr,
                                                    &error)) {
                    return std::unexpected(error);
                }
                RecordTypedText(text);
                InvalidateFrame();
                SchedulePrefetch();
                return true;
            }
            // Anything else, usually Chinese: commit through the ADBKeyboard
            // broadcast, then put the tablet's own keyboard back.
            if (!adb_shell::IsBroadcastable(text)) {
                return std::unexpected(
                    "Text is empty, or carries control characters it cannot contain");
            }
            const std::string private_app = SensitiveFocusError("type");
            if (!private_app.empty()) {
                return std::unexpected(private_app);
            }
            const std::string ime_error = EnsureAdbIme();
            if (!ime_error.empty()) {
                return std::unexpected(ime_error);
            }
            if (!AndroidPhone::Get().RunCommand(adb_shell::BroadcastTextCommand(text), nullptr,
                                                &error)) {
                RestoreIme();
                return std::unexpected(error);
            }
            RecordTypedText(text);
            RestoreIme();
            InvalidateFrame();
            SchedulePrefetch();
            return true;
        });

    mcp_server.AddTool(
        "self.android.key",
        "Press a hardware key on the phone. Valid names: back, home, recent, enter, delete, tab, "
        "escape, menu, power, wakeup, sleep, volume_up, volume_down, search, page_up, page_down.",
        PropertyList({Property("key", kPropertyTypeString).SetMaxLength(20)}),
        [](const PropertyList& properties) -> ToolResult {
            KeepAwake();
            const std::string conn_err = EnsurePhoneConnected("key");
            if (!conn_err.empty()) {
                return std::unexpected(conn_err);
            }
            const std::string name = properties["key"].value<std::string>();
            const int* code = adb_shell::KeyCode(name);
            if (code == nullptr) {
                return std::unexpected("Unknown key '" + name + "'");
            }
            const std::string private_app = SensitiveFocusError("key");
            if (!private_app.empty()) {
                return std::unexpected(private_app);
            }
            std::string error;
            if (!AndroidPhone::Get().RunCommand(adb_shell::KeyCommand(*code), nullptr, &error)) {
                return std::unexpected(error);
            }
            InvalidateFrame();
            SchedulePrefetch();
            return true;
        });

    mcp_server.AddTool(
        "self.android.batch",
        "Run several phone steps in one call, one step per line, run in order. Steps:\n"
        "  tap 3                     tap control 3 from the last self.android.look\n"
        "  tap 500 800               tap a point, 0..1000 over the screen\n"
        "  type text                ASCII as typed, or Chinese characters (sent through the "
        "phone's input method)\n"
        "  key back                  press a key: back, home, enter, ...\n"
        "  swipe x1 y1 x2 y2 ms      0..1000 coordinates, ms 50..3000\n"
        "  launch com.example.app    open an app\n"
        "  wait 1500                 pause, at most 5000\n"
        "One call has a 35 second budget and stops at the first failure, then reports what "
        "finished plus the fresh screen state in look format, so continue from that without "
        "calling look first. Plan like this: when the screen is known and the next 10-20 steps "
        "are certain, send them all in one batch; when unsure what the screen shows, send "
        "2-3 steps. Chinese text can go straight into a type step, so writing an essay is "
        "type steps plus taps for the interface. A writing task is finished only when the "
        "whole text is typed and saved, so keep batching until then; before continuing a "
        "half-finished task, read what was already typed with self.android.status "
        "{action: recent} once, then look and continue after the cursor. When everything "
        "is complete and saved, call self.android.done before saying goodbye.",
        PropertyList({Property("steps", kPropertyTypeString).SetMaxLength(2000)}),
        [](const PropertyList& properties) -> ToolResult {
            KeepAwake();
            const std::string conn_err = EnsurePhoneConnected("batch");
            if (!conn_err.empty()) {
                return std::unexpected(conn_err);
            }
            std::vector<adb_shell::BatchStep> steps;
            std::string error;
            if (!adb_shell::ParseBatchSteps(properties["steps"].value<std::string>(), &steps,
                                            &error)) {
                return std::unexpected(error);
            }
            // Privacy checked once up front and again after every launch: the
            // steps in between cannot move the app in front on their own.
            // shortcut: a tap that navigates into a private app inside the
            // same app window is not caught mid-batch; add a per-step focus
            // check if that ever becomes a real path.
            std::string focus;
            const std::string private_app = SensitiveFocusError("batch", &focus);
            if (!private_app.empty()) {
                return std::unexpected(private_app);
            }
            int width = 0;
            int height = 0;
            std::string size_error;
            const bool have_size = ScreenSize(&width, &height, &size_error);
            // 官方服务器的工具调用超时是 300s（issue #1102），真正的上限是
            // 60-70s 无语音断会话：35s 步骤 + 末尾读屏，加上轮首 TTS 也
            // 不会越线。
            const int64_t deadline = NowMs() + 35000;
            int done = 0;
            std::string stop;
            for (size_t i = 0; i < steps.size(); i++) {
                if (NowMs() >= deadline) {
                    stop = "the 22 second batch budget ran out";
                    break;
                }
                const adb_shell::BatchStep& step = steps[i];
                std::string command;
                switch (step.op) {
                    case adb_shell::BatchStep::Op::kTapIndex: {
                        std::lock_guard<std::mutex> lock(state_mutex_);
                        if (!frame_fresh_ || NowMs() - frame_time_ms_ > kFrameTtlMs ||
                            static_cast<size_t>(step.index) > frame_nodes.size()) {
                            stop = "control " + std::to_string(step.index) +
                                   " is not on the screen of the last look, look and batch again";
                            break;
                        }
                        const adb_shell::UiNode& node = frame_nodes[step.index - 1];
                        command =
                            adb_shell::TapCommand((node.x1 + node.x2) / 2, (node.y1 + node.y2) / 2);
                        break;
                    }
                    case adb_shell::BatchStep::Op::kTapXY:
                        if (!have_size) {
                            stop = size_error;
                            break;
                        }
                        command =
                            adb_shell::TapCommand(Scale(step.x, width), Scale(step.y, height));
                        break;
                    case adb_shell::BatchStep::Op::kType:
                        if (adb_shell::IsTypeable(step.text)) {
                            command = adb_shell::TextCommand(step.text);
                        } else {
                            // Chinese text: commit through the ADBKeyboard
                            // broadcast instead of `input text`.
                            const std::string ime_error = EnsureAdbIme();
                            if (!ime_error.empty()) {
                                stop = ime_error;
                                break;
                            }
                            if (!AndroidPhone::Get().RunCommand(
                                    adb_shell::BroadcastTextCommand(step.text), nullptr, &error)) {
                                stop = error;
                                break;
                            }
                            RecordTypedText(step.text);
                            done++;
                            continue;
                        }
                        break;
                    case adb_shell::BatchStep::Op::kKey:
                        command = adb_shell::KeyCommand(step.key_code);
                        break;
                    case adb_shell::BatchStep::Op::kSwipe:
                        if (!have_size) {
                            stop = size_error;
                            break;
                        }
                        command = adb_shell::SwipeCommand(
                            Scale(step.x, width), Scale(step.y, height), Scale(step.x2, width),
                            Scale(step.y2, height), step.duration_ms);
                        break;
                    case adb_shell::BatchStep::Op::kLaunch: {
                        const std::string refused = SensitiveTargetError("launch", step.text);
                        if (!refused.empty()) {
                            stop = refused;
                            break;
                        }
                        const std::string launch_error = LaunchPackage(step.text);
                        if (launch_error.empty()) {
                            RecordTaskStart();
                            done++;
                            continue;
                        }
                        stop = launch_error;
                        break;
                    }
                    case adb_shell::BatchStep::Op::kWait: {
                        const int64_t left = deadline - NowMs();
                        const int ms = static_cast<int>(
                            std::min<int64_t>(step.duration_ms, std::max<int64_t>(left, 0)));
                        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
                        done++;
                        continue;
                    }
                }
                if (!stop.empty()) {
                    break;
                }
                if (!AndroidPhone::Get().RunCommand(command, nullptr, &error)) {
                    stop = error;
                    break;
                }
                if (steps[i].op == adb_shell::BatchStep::Op::kType) {
                    RecordTypedText(steps[i].text);
                }
                done++;
            }
            std::string result = "Batch: " + std::to_string(done) + "/" +
                                 std::to_string(steps.size()) + " steps done" +
                                 (stop.empty() ? "" : ", stopped: " + stop) + "\n";
            // What the screen shows now, in look format: the next batch reads
            // its control numbers from here. This read runs even when the
            // budget is out, it is what lets the next batch continue. The
            // frame is stored, so index taps in the next batch work. The
            // tablet's own keyboard is put back first so the resting screen
            // is what the dump shows.
            RestoreIme();
            std::string dump;
            if (AndroidPhone::Get().RunCommand(adb_shell::FocusCommand(), &dump, &error)) {
                const std::string new_focus = adb_shell::ParseFocusPackage(dump);
                if (adb_shell::IsSensitivePackage(new_focus) ||
                    adb_shell::ListContains(BlockedList(), new_focus)) {
                    result += "The phone is now showing a private app (" + new_focus +
                              "), so nothing more was read.";
                } else if (!AndroidPhone::Get().RunCommand(adb_shell::UiDumpCommand(), &dump,
                                                           &error)) {
                    result += "Could not read the screen after the batch: " + error;
                } else {
                    const std::vector<adb_shell::UiNode> nodes = adb_shell::ParseUiNodes(dump);
                    StoreFrame(new_focus, nodes);
                    {
                        std::lock_guard<std::mutex> lock(state_mutex_);
                        last_look_ms_ = NowMs();
                    }
                    result +=
                        adb_shell::FormatUiNodes(nodes, width, height, new_focus, kMaxControlLines);
                }
            } else {
                result += "Could not read the screen after the batch: " + error;
            }
            return result;
        });

    mcp_server.AddTool(
        "self.android.done",
        "Mark the current phone task as fully complete, whatever it was: text typed and "
        "saved, an app closed, a setting changed. Call it right before saying goodbye at "
        "the end of ANY phone task, small ones included, so a goodbye that follows is "
        "known to be the natural end of the task instead of an interruption.",
        PropertyList(), [](const PropertyList& properties) -> ToolResult {
            std::lock_guard<std::mutex> lock(state_mutex_);
            done_ms_ = NowMs();
            return true;
        });

    mcp_server.AddTool(
        "self.android.launch",
        "Open an app on the Android phone by its package name, for example com.android.chrome.\n"
        "Use the package shown in the focus line of the last self.android.look, or a package you "
        "are sure of; never guess one. If you only know the app by its name, ask the user to "
        "open it once so a look can show the package, then use launch afterwards.",
        PropertyList({Property("package", kPropertyTypeString).SetMaxLength(128)}),
        [](const PropertyList& properties) -> ToolResult {
            KeepAwake();
            const std::string conn_err = EnsurePhoneConnected("launch");
            if (!conn_err.empty()) {
                return std::unexpected(conn_err);
            }
            const std::string package = properties["package"].value<std::string>();
            if (!adb_shell::IsPackageName(package)) {
                return std::unexpected("'" + package +
                                       "' is not a package name like com.example.app");
            }
            const std::string private_app = SensitiveTargetError("launch", package);
            if (!private_app.empty()) {
                return std::unexpected(private_app);
            }
            const std::string launch_error = LaunchPackage(package);
            if (!launch_error.empty()) {
                return std::unexpected(launch_error);
            }
            // 新任务通常以 launch 开场：重置/标记 recent 缓冲，续接后 LLM
            // 读 recent 只会看到当前任务的文本
            RecordTaskStart();
            InvalidateFrame();
            SchedulePrefetch(kLaunchPrefetchDelayMs);
            return true;
        });

    mcp_server.AddTool(
        "self.android.block",
        "Keep an app out of the assistant's reach, or take it back out. This is on top of the "
        "built in list (banks, brokers, exchanges, messages, photos, passwords and the system UI). "
        "action is add, remove, list or current; package looks like com.example.app. Ask the user "
        "which app they mean. current reads the package of the app on screen, so the user can open "
        "an app and say block this one. Read the list back so they can hear what is blocked.",
        PropertyList({Property("action", kPropertyTypeString, std::string("list")).SetMaxLength(8),
                      Property("package", kPropertyTypeString, std::string("")).SetMaxLength(127)}),
        [](const PropertyList& properties) -> ToolResult {
            const std::string action = properties["action"].value<std::string>();
            const std::string package = properties["package"].value<std::string>();
            const std::string list = BlockedList();
            if (action == "list") {
                return list.empty() ? std::string("No app is blocked by the user") : list;
            }
            if (action == "current") {
                std::string output;
                std::string error;
                if (!AndroidPhone::Get().RunCommand(adb_shell::FocusCommand(), &output, &error)) {
                    return std::unexpected(error);
                }
                const std::string front = adb_shell::ParseFocusPackage(output);
                if (front.empty()) {
                    return std::unexpected("Could not read which app is on screen");
                }
                return front;
            }
            // Package names are lower case; the user reading one aloud from a
            // screen may not be.
            std::string name = package;
            for (char& c : name) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (!adb_shell::IsPackageName(name)) {
                return std::unexpected("'" + package +
                                       "' is not a package name like com.example.app");
            }
            if (action == "add") {
                const std::string added = adb_shell::ListAdd(list, name);
                // NVS strings stop at 4000 bytes; far more apps than anyone
                // will block, so say so instead of failing the write.
                if (added.size() > 1000) {
                    return std::unexpected("The block list is full, remove an app first");
                }
                BlockedListSet(added);
                RecordAudit("block", name, "ok");
                return std::string("Blocked ") + name;
            }
            if (action == "remove") {
                BlockedListSet(adb_shell::ListRemove(list, name));
                RecordAudit("unblock", name, "ok");
                return std::string("Unblocked ") + name;
            }
            return std::unexpected("action must be add, remove or list");
        });

    mcp_server.AddUserOnlyTool(
        "self.android.audit",
        "Show or clear the record of what the assistant did on the phone: every look and action "
        "with the app it hit, and the calls that were refused because the app was private.",
        PropertyList({Property("action", kPropertyTypeString, std::string("read")).SetMaxLength(8),
                      Property("count", kPropertyTypeInteger, 20, 1, kAuditLines)}),
        [](const PropertyList& properties) -> ToolResult {
            const std::string action = properties["action"].value<std::string>();
            if (action == "clear") {
                ClearAudit();
                return std::string("Cleared");
            }
            if (action != "read") {
                return std::unexpected("action must be read or clear");
            }
            return AuditReport(IntProperty(properties, "count"));
        });

    // Each call does several seconds of ADB round trips; run them off the main
    // loop or the TTS/voice-control loop stalls for the whole call.
    mcp_server.SetToolsOffMainLoop("self.android.");

    ESP_LOGI(kTag, "Android control tools registered");
}
