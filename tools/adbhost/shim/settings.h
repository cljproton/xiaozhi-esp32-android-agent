// NVS replacement for the host harness: one small file per key, so the key
// material the firmware would keep in flash survives between runs.
#ifndef ADBHOST_SETTINGS_H
#define ADBHOST_SETTINGS_H

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

class Settings {
public:
    explicit Settings(const std::string& ns, bool read_write = false)
        : ns_(ns), read_write_(read_write) {}

    ~Settings() = default;

    std::string GetString(const std::string& key, const std::string& default_value = "") {
        std::ifstream in(path(key), std::ios::binary);
        if (!in) {
            return default_value;
        }
        std::string value((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        return value;
    }

    bool SetString(const std::string& key, const std::string& value) {
        if (!read_write_) {
            return false;
        }
        std::error_code error;
        std::filesystem::create_directories(root() / ns_, error);
        std::ofstream out(path(key), std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }
        out.write(value.data(), static_cast<std::streamsize>(value.size()));
        return out.good();
    }

    int32_t GetInt(const std::string& key, int32_t default_value = 0) {
        const std::string text = GetString(key, "");
        if (text.empty()) {
            return default_value;
        }
        return static_cast<int32_t>(std::strtol(text.c_str(), nullptr, 10));
    }

    void SetInt(const std::string& key, int32_t value) { SetString(key, std::to_string(value)); }

    bool GetBool(const std::string& key, bool default_value = false) {
        const std::string text = GetString(key, "");
        if (text.empty()) {
            return default_value;
        }
        return text == "1" || text == "true";
    }

    void SetBool(const std::string& key, bool value) { SetString(key, value ? "1" : "0"); }

    void EraseKey(const std::string& key) {
        std::error_code error;
        std::filesystem::remove(path(key), error);
    }

    void EraseAll() {
        std::error_code error;
        std::filesystem::remove_all(root() / ns_, error);
    }

private:
    static std::filesystem::path root() {
        const char* configured = std::getenv("ADBHOST_NVS");
        return configured != nullptr ? std::filesystem::path(configured)
                                     : std::filesystem::path("build/nvs");
    }

    std::filesystem::path path(const std::string& key) const { return root() / ns_ / key; }

    std::string ns_;
    bool read_write_ = false;
};

#endif  // ADBHOST_SETTINGS_H
