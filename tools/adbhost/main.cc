// Host harness for the Android control code in main/android: same protocol
// sources, same adb_shell helpers, but reachable from a terminal with gdb and a
// full byte trace. Only the platform layer (logging, NVS, CSPRNG) is swapped.
#include <unistd.h>

#include <chrono>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <esp_log.h>
#include <esp_random.h>
#include <psa/crypto.h>

#include "adb_connection.h"
#include "adb_crypto.h"
#include "adb_net.h"
#include "adb_shell.h"
#include "settings.h"
#include "trace_stream.h"

int adbhost_log_level = 4;
static auto g_start = std::chrono::steady_clock::now();

void adbhost_log(char level, const char* tag, const char* format, ...) {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - g_start)
                        .count();
    std::fprintf(stderr, "%c (%lld) %s: ", level, static_cast<long long>(ms), tag);
    va_list args;
    va_start(args, format);
    std::vfprintf(stderr, format, args);
    va_end(args);
    std::fputc('\n', stderr);
}

void esp_fill_random(void* buffer, size_t length) {
    auto* out = static_cast<uint8_t*>(buffer);
    size_t done = 0;
    while (done < length) {
        const size_t chunk = length - done > 256 ? 256 : length - done;
        if (getentropy(out + done, chunk) != 0) {
            std::abort();
        }
        done += chunk;
    }
}

// Keep the keys next to the binary so a rebuild or a reboot of the machine does
// not lose the pairing, whatever directory the harness is started from.
static void SetDefaultNvsDir() {
    if (std::getenv("ADBHOST_NVS") != nullptr) {
        return;
    }
    char path[PATH_MAX];
    const ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length <= 0) {
        return;
    }
    path[length] = '\0';
    std::string exe(path);
    const size_t slash = exe.rfind('/');
    if (slash == std::string::npos) {
        return;
    }
    const std::string dir = exe.substr(0, slash) + "/nvs";
    setenv("ADBHOST_NVS", dir.c_str(), 1);
}

namespace {

constexpr char kNamespace[] = "android";
constexpr size_t kMaxDumpPreview = 400;

struct Options {
    bool trace = false;
    std::string host;
    uint16_t port = 0;
};

class Session {
public:
    bool Open(const std::string& host, uint16_t port, bool trace, std::string* error) {
        trace_flag_ = trace;
        trace_.reset();
        connection_.reset();
        tls_.reset();

        AdbIdentity& identity = AdbIdentity::Get();
        if (!identity.EnsureReady()) {
            *error = "cannot load or create the ADB key";
            return false;
        }
        // Use STLS upgrade directly like the device firmware (upgrade_stls=true)
        tls_ = std::make_unique<AdbTlsStream>();
        bool connected = tls_->Connect(host, port, identity.certificate(), identity.private_key(),
                                       /*upgrade_stls=*/true);
        if (!connected) {
            *error = "TLS connect failed (STLS upgrade)";
            tls_.reset();
            return false;
        }
        trace_ = std::make_unique<adbhost::TraceStream>(tls_.get(), trace);
        AdbIdentity* key = &identity;
        connection_ = std::make_unique<AdbConnection>(
            trace_.get(),
            [key](const uint8_t token[20], uint8_t signature[AdbConnection::kSignatureSize]) {
                return key->SignAuthToken(token, signature);
            },
            identity.encoded_public_key(), /*stls_upgraded=*/true);
        if (!connection_->Connect()) {
            *error = "ADB channel handshake failed";
            connection_.reset();
            trace_.reset();
            tls_.reset();
            return false;
        }
        host_ = host;
        port_ = port;
        return true;
    }

    bool Shell(const std::string& command, std::string* output, std::string* error) {
        if (!connection_) {
            *error = "not connected";
            return false;
        }
        if (!connection_->RunService("exec:" + command, "", output)) {
            connection_.reset();
            trace_.reset();
            tls_.reset();
            *error = "connection dropped";
            return false;
        }
        return true;
    }

    bool ScreenSize(int* width, int* height, std::string* error) {
        if (width_ == 0) {
            std::string output;
            if (!Shell("wm size", &output, error)) {
                return false;
            }
            if (!adb_shell::ParseScreenSize(output, &width_, &height_)) {
                *error = "phone did not report its screen size: " + output;
                return false;
            }
        }
        *width = width_;
        *height = height_;
        return true;
    }

    bool connected() const { return connection_ != nullptr; }

private:
    std::unique_ptr<AdbTlsStream> tls_;
    std::unique_ptr<adbhost::TraceStream> trace_;
    std::unique_ptr<AdbConnection> connection_;
    std::string host_;
    uint16_t port_ = 0;
    bool trace_flag_ = false;
    int width_ = 0;
    int height_ = 0;
};

std::string StoredHost() {
    Settings settings(kNamespace);
    return settings.GetString("host", "");
}

uint16_t StoredPort() {
    Settings settings(kNamespace);
    return static_cast<uint16_t>(settings.GetInt("port", 5555));
}

void StoreAddress(const std::string& host, uint16_t port) {
    Settings settings(kNamespace, true);
    settings.SetString("host", host);
    settings.SetInt("port", port);
}

bool ResolveAddress(Options* options) {
    if (options->host.empty()) {
        options->host = StoredHost();
        options->port = StoredPort();
    }
    if (options->host.empty() || options->port == 0) {
        std::fprintf(stderr, "no address: pass --host and --port once, it is remembered\n");
        return false;
    }
    return true;
}

std::string FocusPackage(Session* session, std::string* error) {
    std::string dump;
    if (!session->Shell(adb_shell::FocusCommand(), &dump, error)) {
        return "";
    }
    std::fprintf(stderr, "focus dump: %zu bytes, first line '%s'\n", dump.size(),
                 dump.substr(0, dump.find('\n')).c_str());
    return adb_shell::ParseFocusPackage(dump);
}

int CommandStatus() {
    Settings settings(kNamespace);
    const std::string host = settings.GetString("host", "");
    std::printf("connection: %s\n",
                host.empty()
                    ? "unset"
                    : (host + ":" + std::to_string(settings.GetInt("port", 5555))).c_str());
    std::printf("pairing:    %s\n", settings.GetString("pair_host", "unpaired").c_str());
    return 0;
}

int CommandPair(Options* options, const std::string& code) {
    if (!ResolveAddress(options)) {
        return 2;
    }
    std::string peer_key;
    if (!AdbPairWithPhone(options->host, options->port, code, &peer_key)) {
        std::fprintf(stderr, "pairing failed\n");
        return 1;
    }
    Settings settings(kNamespace, true);
    settings.SetString("pair_host", options->host);
    settings.SetInt("pair_port", options->port);
    settings.SetString("pair_code", code);
    std::printf("paired with %s:%u, phone key %zu bytes\n", options->host.c_str(), options->port,
                peer_key.size());
    return 0;
}

int CommandLook(Session* session, size_t max_lines) {
    std::string error;
    const std::string package = FocusPackage(session, &error);
    if (!error.empty()) {
        std::fprintf(stderr, "focus failed: %s\n", error.c_str());
        return 1;
    }
    if (package.empty()) {
        std::fprintf(stderr, "no focus package parsed\n");
    } else if (adb_shell::IsSensitivePackage(package)) {
        std::fprintf(stderr, "refused: '%s' is on the private list\n", package.c_str());
        return 1;
    }
    std::string xml;
    if (!session->Shell(adb_shell::UiDumpCommand(), &xml, &error)) {
        std::fprintf(stderr, "ui dump failed: %s\n", error.c_str());
        return 1;
    }
    std::fprintf(stderr, "ui dump: %zu bytes\n", xml.size());
    if (xml.size() < kMaxDumpPreview) {
        std::fprintf(stderr, "ui dump body: %s\n", xml.c_str());
    }
    const std::vector<adb_shell::UiNode> nodes = adb_shell::ParseUiNodes(xml);
    int width = 0;
    int height = 0;
    if (!session->ScreenSize(&width, &height, &error)) {
        std::fprintf(stderr, "screen size failed: %s\n", error.c_str());
        return 1;
    }
    std::printf("%s", adb_shell::FormatUiNodes(nodes, width, height, package, max_lines).c_str());
    return 0;
}

int CommandTap(Session* session, int index, int raw_x, int raw_y) {
    std::string error;
    int x = 0;
    int y = 0;
    if (index > 0) {
        // Nothing remembers the last look here, so re-read the screen first.
        std::string xml;
        if (!session->Shell(adb_shell::UiDumpCommand(), &xml, &error)) {
            std::fprintf(stderr, "ui dump failed: %s\n", error.c_str());
            return 1;
        }
        const auto nodes = adb_shell::ParseUiNodes(xml);
        if (static_cast<size_t>(index) > nodes.size()) {
            std::fprintf(stderr, "no control %d, screen has %zu\n", index, nodes.size());
            return 1;
        }
        const auto& node = nodes[index - 1];
        x = (node.x1 + node.x2) / 2;
        y = (node.y1 + node.y2) / 2;
        std::printf("control %d \"%s\" -> %d,%d\n", index, node.label.c_str(), x, y);
    } else {
        int width = 0;
        int height = 0;
        if (!session->ScreenSize(&width, &height, &error)) {
            std::fprintf(stderr, "screen size failed: %s\n", error.c_str());
            return 1;
        }
        x = raw_x * width / 1000;
        y = raw_y * height / 1000;
    }
    std::string output;
    if (!session->Shell(adb_shell::TapCommand(x, y), &output, &error)) {
        std::fprintf(stderr, "tap failed: %s\n", error.c_str());
        return 1;
    }
    std::printf("tapped %d,%d\n", x, y);
    return 0;
}

int CommandShell(Session* session, const std::string& command, bool show_output) {
    std::string output;
    std::string error;
    if (!session->Shell(command, &output, &error)) {
        std::fprintf(stderr, "shell failed: %s\n", error.c_str());
        return 1;
    }
    if (show_output) {
        std::printf("%s", output.c_str());
        if (!output.empty() && output.back() != '\n') {
            std::printf("\n");
        }
    }
    std::fprintf(stderr, "shell ok: %zu bytes\n", output.size());
    return 0;
}

void Usage() {
    std::fprintf(stderr,
                 "usage: adbhost [--trace] [--log N] [--host H] [--port P] <command>\n"
                 "  pair --code 123456        pair with the phone's pairing dialog\n"
                 "  connect                   open the ADB channel to the stored address\n"
                 "  status                    show the stored address and pairing\n"
                 "  shell <cmd>               run one shell command\n"
                 "  look [--max N]            list the controls on screen\n"
                 "  tap --index N | --x X --y Y\n"
                 "  type <text> | key <name>  keyboard input\n"
                 "  stress <cmd> <count>      repeat a command on one connection\n");
}

}  // namespace

int main(int argc, char** argv) {
    SetDefaultNvsDir();
    if (const char* level = std::getenv("ADBHOST_LOG")) {
        adbhost_log_level = std::atoi(level);
    }
    // The device initializes PSA at boot; Mbed TLS here needs the same before it
    // can import the stored RSA key.
    if (psa_crypto_init() != PSA_SUCCESS) {
        std::fprintf(stderr, "psa_crypto_init failed\n");
        return 1;
    }
    Options options;
    std::string command;
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) {
        const std::string arg = argv[i];
        if (arg == "--trace") {
            options.trace = true;
        } else if (arg == "--log" && i + 1 < argc) {
            adbhost_log_level = std::atoi(argv[++i]);
        } else if (arg == "--host" && i + 1 < argc) {
            options.host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            options.port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (command.empty()) {
            command = arg;
        } else {
            args.push_back(arg);
        }
    }
    if (command.empty() || command == "help") {
        Usage();
        return 2;
    }
    if (command == "status") {
        return CommandStatus();
    }
    if (command == "pair") {
        const std::string code = args.empty() ? "000000" : args.back();
        return CommandPair(&options, code);
    }
    if (!ResolveAddress(&options)) {
        return 2;
    }

    Session session;
    std::string error;
    if (!session.Open(options.host, options.port, options.trace, &error)) {
        std::fprintf(stderr, "open failed: %s\n", error.c_str());
        return 1;
    }
    StoreAddress(options.host, options.port);

    if (command == "connect") {
        std::printf("connected to %s:%u\n", options.host.c_str(), options.port);
        return 0;
    }
    if (command == "shell") {
        std::string line;
        for (size_t i = 0; i < args.size(); i++) {
            line += (i == 0 ? "" : " ") + args[i];
        }
        return CommandShell(&session, line, true);
    }
    if (command == "look") {
        size_t max_lines = 40;
        for (size_t i = 0; i + 1 < args.size(); i++) {
            if (args[i] == "--max") {
                max_lines = static_cast<size_t>(std::atoi(args[i + 1].c_str()));
            }
        }
        return CommandLook(&session, max_lines);
    }
    if (command == "tap") {
        int index = 0;
        int x = 0;
        int y = 0;
        for (size_t i = 0; i + 1 < args.size(); i++) {
            if (args[i] == "--index") {
                index = std::atoi(args[i + 1].c_str());
            } else if (args[i] == "--x") {
                x = std::atoi(args[i + 1].c_str());
            } else if (args[i] == "--y") {
                y = std::atoi(args[i + 1].c_str());
            }
        }
        return CommandTap(&session, index, x, y);
    }
    if (command == "type") {
        return CommandShell(&session, adb_shell::TextCommand(args.empty() ? "" : args[0]), true);
    }
    if (command == "key") {
        const int* code = adb_shell::KeyCode(args.empty() ? "" : args[0]);
        if (code == nullptr) {
            std::fprintf(stderr, "unknown key\n");
            return 2;
        }
        return CommandShell(&session, adb_shell::KeyCommand(*code), true);
    }
    if (command == "stress") {
        if (args.size() < 2) {
            Usage();
            return 2;
        }
        const int count = std::atoi(args[1].c_str());
        for (int i = 0; i < count; i++) {
            std::fprintf(stderr, "-- round %d\n", i + 1);
            if (CommandShell(&session, args[0], false) != 0) {
                return 1;
            }
        }
        return 0;
    }
    Usage();
    return 2;
}
