#ifndef ANDROID_PHONE_H
#define ANDROID_PHONE_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "adb_connection.h"
#include "adb_net.h"

// The paired phone over Wi-Fi ADB. One TLS connection is kept open and reused
// by every tool call; a call that fails drops it so the next one reconnects.
class AndroidPhone {
public:
    static AndroidPhone& Get();

    // Runs ADB wireless pairing with the code the phone shows. |port| is the
    // pairing port from the pairing dialog, not the debugging port. The host is
    // remembered so later calls only need the debugging port.
    bool Pair(const std::string& host, uint16_t port, const std::string& code, std::string* error);

    // Connects to |host|:|port| (the "IP address & Port" line of the wireless
    // debugging screen) and remembers both for EnsureConnected.
    bool Connect(const std::string& host, uint16_t port, std::string* error);

    // Finds the Android device on the network through mDNS and connects to it;
    // the found address is remembered like a manual Connect.
    bool Discover(std::string* error);

    // Reuses the open connection, or opens the remembered one.
    bool EnsureConnected(std::string* error);
    bool connected() const { return connection_ != nullptr; }
    void Disconnect();

    // Runs one command through the raw "exec:" service and collects its
    // standard output.
    bool RunCommand(const std::string& command, std::string* output, std::string* error);

    // Resolution the normalized tool coordinates are scaled to. Read once from
    // `wm size` and cached for the session.
    bool ScreenSize(int* width, int* height, std::string* error);

    // The tablet's adbd drops idle or backgrounded TLS sessions, so a daemon
    // heartbeat doubles as the reconnect watchdog: it notices the loss within
    // one interval and its RunCommand retries reconnect the connection on
    // their own, without waiting for the next voice command.
    void StartHeartbeat();
    void StopHeartbeat();

private:
    AndroidPhone();
    AndroidPhone(const AndroidPhone&) = delete;
    AndroidPhone& operator=(const AndroidPhone&) = delete;
    ~AndroidPhone();

    bool Open(const std::string& host, uint16_t port, std::string* error);

    std::unique_ptr<AdbTlsStream> stream_;
    std::unique_ptr<AdbConnection> connection_;
    std::string host_;
    uint16_t port_ = 0;
    int width_ = 0;
    int height_ = 0;

    // One heartbeat daemon for the life of the process; Start/Stop only flip
    // the flag, so a reconnect that goes through Disconnect never has to tear
    // down or respawn the thread it is running on.
    std::thread heartbeat_thread_;
    std::atomic<bool> heartbeat_desired_{false};
    void HeartbeatLoop();

    // Protects stream_, connection_, host_, port_, width_, height_
    mutable std::mutex mutex_;
};

// Registers the self.android.* MCP tools.
void RegisterAndroidTools();

// True when the model last marked the current task complete (self.android.done)
// within the last 2 minutes: a goodbye right after is the natural end of a
// finished task, not a server cut.
bool AndroidTaskDoneRecently();

#endif  // ANDROID_PHONE_H
