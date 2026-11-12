#ifndef ADB_SHELL_H
#define ADB_SHELL_H

#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

// Debug logs of the focus parser. The host test compiles this header without
// the ESP log library, so the calls vanish there.
#ifdef ESP_PLATFORM
#include <esp_log.h>
#else
#define ESP_LOGD(...)
#define ESP_LOGI(...)
#define ESP_LOGW(...)
#endif

// Command lines the control tools run on the phone through the "exec:" service.
// Every string here is one line the phone's shell receives, so anything that
// comes from the model is quoted before it gets in.
namespace adb_shell {

// "exec:" is the raw service: no pseudo terminal, so binary output such as a
// screencap PNG arrives byte for byte instead of with its newlines rewritten.
inline std::string Service(const std::string& command) { return "exec:" + command; }

// Quotes |text| for `input text`, which splits its argument on spaces and so
// needs them as "%s". Single quotes stop the shell from expanding anything.
inline std::string QuoteText(const std::string& text) {
    std::string quoted = "'";
    for (char c : text) {
        if (c == ' ') {
            quoted += "%s";
        } else if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(c);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

// "input text" only takes what it can put on the keyboard without an IME, so
// anything above ASCII has to go through the phone's pinyin input instead.
inline bool IsTypeable(const std::string& text) {
    for (unsigned char c : text) {
        if (c == '\n' || c == '\r' || c < 0x20 || c > 0x7e) {
            return false;
        }
    }
    return !text.empty();
}

// The ADBKeyboard input method commits any Unicode text into the focused field
// through its broadcast receiver; `input text` cannot send non-ASCII. Chinese
// text is welcome here, but a control character would break the shell line.
inline bool IsBroadcastable(const std::string& text) {
    for (unsigned char c : text) {
        if (c < 0x20 || c == 0x7f) {
            return false;
        }
    }
    return !text.empty();
}

// Quotes |text| as an am broadcast --es value: single quotes stop the shell
// from expanding anything, and broadcast values keep their spaces as spaces.
inline std::string QuoteBroadcastText(const std::string& text) {
    std::string quoted = "'";
    for (char c : text) {
        if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(c);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

inline std::string BroadcastTextCommand(const std::string& text) {
    return "am broadcast -a ADB_INPUT_TEXT --es msg " + QuoteBroadcastText(text);
}

inline std::string TapCommand(int x, int y) {
    return "input tap " + std::to_string(x) + " " + std::to_string(y);
}

inline std::string SwipeCommand(int x1, int y1, int x2, int y2, int duration_ms) {
    return "input swipe " + std::to_string(x1) + " " + std::to_string(y1) + " " +
           std::to_string(x2) + " " + std::to_string(y2) + " " + std::to_string(duration_ms);
}

inline std::string TextCommand(const std::string& text) { return "input text " + QuoteText(text); }

// Key names the model may use, mapped to their Android key codes. Unknown
// names get a null pointer so the tool can list the valid ones.
inline const int* KeyCode(const std::string& name) {
    static const struct {
        const char* name;
        int code;
    } kKeys[] = {
        {"back", 4},         {"home", 3},     {"recent", 187}, {"enter", 66},
        {"delete", 67},      {"tab", 61},     {"escape", 111}, {"menu", 82},
        {"power", 26},       {"wakeup", 224}, {"sleep", 223},  {"volume_up", 24},
        {"volume_down", 25}, {"search", 84},  {"page_up", 92}, {"page_down", 93},
    };
    for (const auto& key : kKeys) {
        if (name == key.name) {
            return &key.code;
        }
    }
    return nullptr;
}

inline std::string KeyCommand(int code) { return "input keyevent " + std::to_string(code); }

// Launch an app by package: monkey resolves and starts its launcher activity,
// which a bare am start cannot do without an activity name.
inline std::string LaunchCommand(const std::string& package) {
    return "monkey -p " + package + " -c android.intent.category.LAUNCHER 1";
}

// The last line with anything on it. `cmd package resolve-activity --brief`
// prints the launcher activity as "package/activity" on it.
inline std::string LastNonEmptyLine(const std::string& text) {
    const size_t end = text.find_last_not_of(" \t\r\n");
    if (end == std::string::npos) {
        return "";
    }
    size_t start = text.find_last_of('\n', end);
    start = (start == std::string::npos) ? 0 : start + 1;
    while (start < end && (text[start] == ' ' || text[start] == '\t')) {
        start++;
    }
    return text.substr(start, end - start + 1);
}

// Reads `wm size` output: "Physical size: 1080x2400", and possibly an
// "Override size: ..." line after it. The last line wins, so when the user set
// a resolution override that is what the coordinates are scaled to.
inline bool ParseScreenSize(const std::string& output, int* width, int* height) {
    int found_width = 0;
    int found_height = 0;
    size_t position = 0;
    while ((position = output.find("size:", position)) != std::string::npos) {
        int w = 0;
        int h = 0;
        if (std::sscanf(output.c_str() + position, "size: %dx%d", &w, &h) == 2 && w > 0 && h > 0) {
            found_width = w;
            found_height = h;
        }
        position += 5;
    }
    *width = found_width;
    *height = found_height;
    return found_width > 0 && found_height > 0;
}

// The focused window names the app that is on screen, which is what decides
// whether a screenshot or a tap would show something private. grep keeps the
// transfer small: the whole window dump is megabytes.
inline std::string FocusCommand() { return "dumpsys window windows"; }

// Reads the package name out of FocusCommand output, for example
// "mCurrentFocus=Window{2f6c1a3 u0 com.android.chrome/...Main}".
// Also handles "dumpsys window windows" output like "Window #0 Window{... u0 com.pkg/...}".
// Empty when nothing usable is there: a null focus, a lock screen, or a ROM
// whose dump reads differently.
// The package is the first "package/activity" word after |marker| in |line|.
// Either " u0 pkg/act" (skip 4: space, u0, space) or the word after the first
// space following the marker. Empty when the line has no usable package there.
inline std::string PackageAfter(const std::string& line, const std::string& marker) {
    const size_t focus_pos = line.find(marker);
    if (focus_pos == std::string::npos) {
        return "";
    }
    size_t start = line.find(" u0 ", focus_pos);
    if (start != std::string::npos) {
        start += 4;
    } else {
        start = line.find(' ', focus_pos);
        if (start == std::string::npos) {
            return "";
        }
        start++;
    }
    size_t space = line.find(' ', start);
    const std::string word = line.substr(start, space - start);
    const size_t slash = word.find('/');
    if (slash == std::string::npos) {
        return "";
    }
    const std::string package = word.substr(0, slash);
    if (package.empty() || package.find('.') == std::string::npos ||
        package.find_first_of("{}()=:,") != std::string::npos) {
        return "";
    }
    return package;
}

// Scans for the first line carrying one of the markers, in marker priority:
// mCurrentFocus (what is on screen now) beats mFocusedApp (older ROMs) beats
// Window{ (MIUI omits the focus line on the desktop, so the launcher window
// is the fallback). One marker at a time keeps a hidden stale window listed
// above the focused one from being picked instead.
inline std::string ParseFocusPackage(const std::string& dump) {
    ESP_LOGD("AdbShell", "ParseFocusPackage: dump length=%u", static_cast<unsigned>(dump.size()));
    if (!dump.empty()) {
        ESP_LOGD("AdbShell", "ParseFocusPackage: dump preview='%s'", dump.substr(0, 200).c_str());
    }
    static const char* const kMarkers[] = {"mCurrentFocus=", "mFocusedApp=", "Window{"};
    for (const char* marker : kMarkers) {
        size_t position = 0;
        while (position < dump.size()) {
            size_t end = dump.find('\n', position);
            const size_t line_end = (end == std::string::npos) ? dump.size() : end;
            const std::string line = dump.substr(position, line_end - position);
            position = (end == std::string::npos) ? dump.size() : end + 1;
            const std::string package = PackageAfter(line, marker);
            if (!package.empty()) {
                ESP_LOGI("AdbShell", "ParseFocusPackage: parsed package='%s' via %s",
                         package.c_str(), marker);
                return package;
            }
        }
    }
    ESP_LOGW("AdbShell", "ParseFocusPackage: no valid package found in dump");
    return "";
}

// Apps whose screen must never be looked at or touched: the user's money,
// messages, photos and secrets, plus the system UI, where message previews show
// up on the lock screen and in the notification shade. Matched loosely on
// purpose: a bank the list does not know by name is still caught by "bank", and
// a broker or exchange usually still says what it is in its package name. Add
// the package of a finance app that slips through here.
inline bool IsSensitivePackage(const std::string& package) {
    static const char* const kSensitive[] = {
        // Banks, brokers and exchanges.
        "bank",
        "broker",
        "securities",
        "stock",
        "trade",
        "financ",
        "fund",
        "invest",
        "binance",
        "coinbase",
        "okx",
        "okex",
        "huobi",
        "kraken",
        "bybit",
        "kucoin",
        "bitget",
        "mexc",
        "coinex",
        "eastmoney",
        "hexin",
        "futu",
        "xueqiu",
        "chinastock",
        "robinhood",
        "pay",
        "wallet",
        "crypto",
        // Messages, passwords and photos.
        "sms",
        "mms",
        "messag",
        "authenticator",
        "password",
        "vault",
        "keyguard",
        "gallery",
        "photos",
        // Lock screen and notification previews.
        // "systemui" removed: desktop/launcher is com.android.systemui, would block normal use.
    };
    std::string lower;
    lower.reserve(package.size());
    for (char c : package) {
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    for (const char* keyword : kSensitive) {
        if (lower.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Package names look like "com.example.app". Used to keep typos and anything
// else that is not a package out of the user's own block list.
inline bool IsPackageName(const std::string& package) {
    if (package.size() < 3 || package.size() > 127 || package.front() == '.' ||
        package.back() == '.' || package.find("..") != std::string::npos) {
        return false;
    }
    bool has_dot = false;
    for (char c : package) {
        if (c == '.') {
            has_dot = true;
        } else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
            return false;
        }
    }
    return has_dot;
}

// The packages the user added themselves, as one comma separated string in NVS.
inline bool ListContains(const std::string& list, const std::string& package) {
    if (package.empty()) {
        return false;
    }
    size_t position = 0;
    while (position <= list.size()) {
        const size_t comma = list.find(',', position);
        if (list.substr(position, comma - position) == package) {
            return true;
        }
        if (comma == std::string::npos) {
            return false;
        }
        position = comma + 1;
    }
    return false;
}

inline std::string ListAdd(const std::string& list, const std::string& package) {
    if (!IsPackageName(package) || ListContains(list, package)) {
        return list;
    }
    return list.empty() ? package : list + "," + package;
}

inline std::string ListRemove(const std::string& list, const std::string& package) {
    std::string kept;
    size_t position = 0;
    while (position <= list.size()) {
        const size_t comma = list.find(',', position);
        const std::string item = list.substr(position, comma - position);
        if (!item.empty() && item != package) {
            kept += (kept.empty() ? "" : ",") + item;
        }
        if (comma == std::string::npos) {
            return kept;
        }
        position = comma + 1;
    }
    return kept;
}

// One control of the screen as uiautomator describes it. This is what the model
// reads instead of a screenshot: the server never shows it the picture.
struct UiNode {
    std::string label;       // text, or the accessibility description
    std::string class_name;  // short form, e.g. "Button"
    bool focused = false;
    int x1 = 0;
    int y1 = 0;
    int x2 = 0;
    int y2 = 0;
};

// Written to /data/local/tmp rather than /sdcard: the shell uid is always
// allowed there, while /sdcard depends on the ROM's SELinux policy.
inline std::string UiDumpCommand() {
    // --compressed drops empty attributes: about half the bytes over TLS and
    // in the parse buffer, same text/bounds/clickable data. Verified on MIUI.
    return "uiautomator dump --compressed /data/local/tmp/z.xml >/dev/null 2>&1; cat "
           "/data/local/tmp/z.xml";
}

inline std::string UnescapeXml(const std::string& value) {
    std::string out;
    for (size_t i = 0; i < value.size(); i++) {
        if (value[i] != '&') {
            out += value[i];
        } else if (value.compare(i, 5, "&amp;") == 0) {
            out += '&';
            i += 4;
        } else if (value.compare(i, 6, "&quot;") == 0) {
            out += '"';
            i += 5;
        } else if (value.compare(i, 4, "&lt;") == 0) {
            out += '<';
            i += 3;
        } else if (value.compare(i, 4, "&gt;") == 0) {
            out += '>';
            i += 3;
        } else if (value.compare(i, 6, "&apos;") == 0) {
            out += '\'';
            i += 5;
        } else {
            out += value[i];
        }
    }
    return out;
}

// Reads one attribute out of a single "<node ...>" tag.
inline std::string Attribute(const std::string& tag, const std::string& name) {
    const std::string needle = " " + name + "=\"";
    size_t start = tag.find(needle);
    if (start == std::string::npos) {
        return "";
    }
    start += needle.size();
    const size_t end = tag.find('"', start);
    if (end == std::string::npos) {
        return "";
    }
    return UnescapeXml(tag.substr(start, end - start));
}

// Everything the model can act on: controls with words on them, plus the focused
// input field. Containers, images without a description and the empty majority of
// the tree are dropped before the text ever leaves the device.
inline std::vector<UiNode> ParseUiNodes(const std::string& xml) {
    std::vector<UiNode> nodes;
    size_t position = 0;
    while ((position = xml.find("<node ", position)) != std::string::npos) {
        const size_t end = xml.find('>', position);
        if (end == std::string::npos) {
            break;
        }
        const std::string tag = xml.substr(position, end - position);
        position = end + 1;

        UiNode node;
        node.label = Attribute(tag, "text");
        if (node.label.empty()) {
            node.label = Attribute(tag, "content-desc");
        }
        node.class_name = Attribute(tag, "class");
        const size_t dot = node.class_name.rfind('.');
        if (dot != std::string::npos) {
            node.class_name.erase(0, dot + 1);
        }
        node.focused = Attribute(tag, "focused") == "true";
        const bool clickable = Attribute(tag, "clickable") == "true";
        int x1 = 0;
        int y1 = 0;
        int x2 = 0;
        int y2 = 0;
        if (std::sscanf(Attribute(tag, "bounds").c_str(), "[%d,%d][%d,%d]", &x1, &y1, &x2, &y2) !=
            4) {
            continue;
        }
        if (x2 <= x1 || y2 <= y1) {
            continue;
        }
        if (node.label.empty() && !clickable && !node.focused) {
            continue;
        }
        node.x1 = x1;
        node.y1 = y1;
        node.x2 = x2;
        node.y2 = y2;
        nodes.push_back(node);
    }
    return nodes;
}

// Cuts |text| to |max_bytes| without leaving half of a multi byte character
// behind, which would make the JSON sent to the server invalid UTF-8.
inline void TruncateUtf8(std::string* text, size_t max_bytes) {
    if (text->size() <= max_bytes) {
        return;
    }
    text->resize(max_bytes);
    size_t start = text->size();
    while (start > 0 && (static_cast<unsigned char>((*text)[start - 1]) & 0xc0) == 0x80) {
        start--;
    }
    if (start == 0) {
        text->clear();
        return;
    }
    const unsigned char lead = static_cast<unsigned char>((*text)[start - 1]);
    size_t needed = 1;
    if ((lead & 0xe0) == 0xc0) {
        needed = 2;
    } else if ((lead & 0xf0) == 0xe0) {
        needed = 3;
    } else if ((lead & 0xf8) == 0xf0) {
        needed = 4;
    }
    if (text->size() - (start - 1) < needed) {
        text->resize(start - 1);
    }
}

// One line per control so the model can name a control instead of guessing pixel
// coordinates. Capped: a long list costs more to read than it is worth.
inline std::string FormatUiNodes(const std::vector<UiNode>& nodes, int width, int height,
                                 const std::string& package, size_t max_lines) {
    std::string text = "Screen " + std::to_string(width) + "x" + std::to_string(height);
    if (!package.empty()) {
        text += " app " + package;
    }
    text += ", " + std::to_string(nodes.size()) + " controls\n";
    size_t shown = 0;
    for (size_t i = 0; i < nodes.size(); i++) {
        if (shown >= max_lines || text.size() > 3000) {
            text += "... and " + std::to_string(nodes.size() - i) + " more\n";
            break;
        }
        const UiNode& node = nodes[i];
        std::string line = std::to_string(i + 1) + " ";
        if (!node.class_name.empty()) {
            line += node.class_name + " ";
        }
        std::string label = node.label;
        // Keep the quoted label on one line and unquoted inside.
        for (char& c : label) {
            if (c == '"' || c == '\'' || c == '\n' || c == '\r') {
                c = ' ';
            }
        }
        if (label.size() > 60) {
            TruncateUtf8(&label, 60);
        }
        line += "\"" + label + "\" [" + std::to_string(node.x1) + "," + std::to_string(node.y1) +
                "][" + std::to_string(node.x2) + "," + std::to_string(node.y2) + "]";
        if (node.focused) {
            line += " focused";
        }
        text += line + "\n";
        shown++;
    }
    return text;
}

// One step of a self.android.batch call, parsed from one line of the steps
// text. Coordinates are 0..1000 over the screen, like the single-action tools.
struct BatchStep {
    enum class Op { kTapIndex, kTapXY, kType, kKey, kSwipe, kLaunch, kWait };
    Op op = Op::kWait;
    int index = 0;
    int x = 0;
    int y = 0;
    int x2 = 0;
    int y2 = 0;
    int duration_ms = 0;
    int key_code = 0;
    std::string text;  // the type text, the key name or the launch package
};

inline std::string BatchTrim(const std::string& text) {
    const size_t start = text.find_first_not_of(" \t\r");
    if (start == std::string::npos) {
        return "";
    }
    const size_t end = text.find_last_not_of(" \t\r");
    return text.substr(start, end - start + 1);
}

// Strict decimal: digits only, so a stray sign or word never becomes a
// coordinate.
inline bool BatchInt(const std::string& token, int* value) {
    if (token.empty() || token.size() > 9) {
        return false;
    }
    long parsed = 0;
    for (char c : token) {
        if (c < '0' || c > '9') {
            return false;
        }
        parsed = parsed * 10 + (c - '0');
    }
    *value = static_cast<int>(parsed);
    return true;
}

// One batch step per line: tap 3 | tap 500 800 | type text | key back |
// swipe x1 y1 x2 y2 ms | launch com.example.app | wait ms. Empty lines are
// skipped; the first bad line aborts with its line number in |error|.
inline bool ParseBatchSteps(const std::string& spec, std::vector<BatchStep>* steps,
                            std::string* error) {
    steps->clear();
    int line_no = 0;
    size_t position = 0;
    while (position <= spec.size()) {
        size_t end = spec.find('\n', position);
        if (end == std::string::npos) {
            end = spec.size();
        }
        const std::string line = BatchTrim(spec.substr(position, end - position));
        position = end + 1;
        line_no++;
        if (line.empty()) {
            continue;
        }
        if (steps->size() >= 40) {
            *error = "At most 40 steps per batch";
            return false;
        }
        const size_t space = line.find(' ');
        const std::string op = (space == std::string::npos) ? line : line.substr(0, space);
        const std::string rest =
            (space == std::string::npos) ? "" : BatchTrim(line.substr(space + 1));
        // Numeric fields of |rest|, whitespace separated.
        std::vector<std::string> tokens;
        size_t scan = 0;
        while (scan <= rest.size()) {
            size_t tok_end = rest.find(' ', scan);
            if (tok_end == std::string::npos) {
                tok_end = rest.size();
            }
            if (tok_end > scan) {
                tokens.push_back(rest.substr(scan, tok_end - scan));
            }
            scan = tok_end + 1;
        }
        auto fail = [line_no, error](const std::string& what) {
            *error = "Line " + std::to_string(line_no) + ": " + what;
            return false;
        };
        BatchStep step;
        if (op == "tap") {
            int x = 0;
            int y = 0;
            if (tokens.size() == 1 && BatchInt(tokens[0], &step.index) && step.index >= 1 &&
                step.index <= 1000) {
                step.op = BatchStep::Op::kTapIndex;
            } else if (tokens.size() == 2 && BatchInt(tokens[0], &x) && BatchInt(tokens[1], &y) &&
                       x <= 1000 && y <= 1000) {
                step.op = BatchStep::Op::kTapXY;
                step.x = x;
                step.y = y;
            } else {
                return fail(
                    "tap takes a control number (tap 3) or two coordinates 0..1000 (tap 500 800)");
            }
        } else if (op == "type") {
            if (!IsBroadcastable(rest)) {
                return fail(
                    "type needs non-empty text without control characters; a new line is a "
                    "separate key enter step");
            }
            step.op = BatchStep::Op::kType;
            step.text = rest;
        } else if (op == "key") {
            const int* code = KeyCode(rest);
            if (code == nullptr) {
                return fail("unknown key '" + rest +
                            "', valid: back, home, recent, enter, delete, tab, escape, menu, "
                            "power, wakeup, sleep, volume_up, volume_down, search, page_up, "
                            "page_down");
            }
            step.op = BatchStep::Op::kKey;
            step.key_code = *code;
        } else if (op == "swipe") {
            int v[5] = {0, 0, 0, 0, 0};
            bool ok = tokens.size() == 5;
            for (int i = 0; ok && i < 5; i++) {
                ok = BatchInt(tokens[i], &v[i]);
            }
            if (!ok || v[0] > 1000 || v[1] > 1000 || v[2] > 1000 || v[3] > 1000 || v[4] < 50 ||
                v[4] > 3000) {
                return fail("swipe takes x1 y1 x2 y2 ms, coordinates 0..1000, ms 50..3000");
            }
            step.op = BatchStep::Op::kSwipe;
            step.x = v[0];
            step.y = v[1];
            step.x2 = v[2];
            step.y2 = v[3];
            step.duration_ms = v[4];
        } else if (op == "launch") {
            if (!IsPackageName(rest)) {
                return fail("launch needs a package name like com.example.app");
            }
            step.op = BatchStep::Op::kLaunch;
            step.text = rest;
        } else if (op == "wait") {
            int ms = 0;
            if (tokens.size() != 1 || !BatchInt(tokens[0], &ms) || ms < 1 || ms > 5000) {
                return fail("wait takes a pause in milliseconds, 1..5000");
            }
            step.op = BatchStep::Op::kWait;
            step.duration_ms = ms;
        } else {
            return fail("unknown step '" + op + "', use tap, type, key, swipe, launch or wait");
        }
        steps->push_back(step);
    }
    if (steps->empty()) {
        *error = "steps is empty";
        return false;
    }
    return true;
}

}  // namespace adb_shell

#endif  // ADB_SHELL_H
