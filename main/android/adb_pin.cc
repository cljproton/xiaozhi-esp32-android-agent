#include "adb_pin.h"

#include <cstddef>
#include <cstdint>

namespace {

// Returns the number of bytes consumed, or 0 when |text| is not valid UTF-8.
size_t DecodeUtf8(const std::string& text, size_t offset, uint32_t* codepoint) {
    const auto byte = [&](size_t index) { return static_cast<uint8_t>(text[index]); };
    const uint8_t first = byte(offset);
    size_t length = 0;
    uint32_t value = 0;
    if (first < 0x80) {
        *codepoint = first;
        return 1;
    } else if ((first & 0xe0) == 0xc0) {
        length = 2;
        value = first & 0x1f;
    } else if ((first & 0xf0) == 0xe0) {
        length = 3;
        value = first & 0x0f;
    } else if ((first & 0xf8) == 0xf0) {
        length = 4;
        value = first & 0x07;
    } else {
        return 0;
    }
    if (offset + length > text.size()) {
        return 0;
    }
    for (size_t i = 1; i < length; i++) {
        const uint8_t next = byte(offset + i);
        if ((next & 0xc0) != 0x80) {
            return 0;
        }
        value = (value << 6) | (next & 0x3f);
    }
    *codepoint = value;
    return length;
}

int DigitFor(uint32_t codepoint) {
    if (codepoint >= '0' && codepoint <= '9') {
        return static_cast<int>(codepoint - '0');
    }
    if (codepoint >= 0xff10 && codepoint <= 0xff19) {  // full-width ０-９
        return static_cast<int>(codepoint - 0xff10);
    }
    switch (codepoint) {
        case 0x3007:  // 〇
        case 0x96f6:  // 零
            return 0;
        case 0x4e00:  // 一
        case 0x5e7a:  // 幺
        case 0x58f9:  // 壹
            return 1;
        case 0x4e8c:  // 二
        case 0x4e24:  // 两
        case 0x8d30:  // 贰
            return 2;
        case 0x4e09:  // 三
        case 0x53c1:  // 叁
            return 3;
        case 0x56db:  // 四
        case 0x8086:  // 肆
            return 4;
        case 0x4e94:  // 五
        case 0x4f0d:  // 伍
            return 5;
        case 0x516d:  // 六
        case 0x9646:  // 陆
            return 6;
        case 0x4e03:  // 七
        case 0x67d2:  // 柒
            return 7;
        case 0x516b:  // 八
        case 0x634c:  // 捌
            return 8;
        case 0x4e5d:  // 九
        case 0x7396:  // 玖
            return 9;
        default:
            return -1;
    }
}

bool IsSeparator(uint32_t codepoint) {
    switch (codepoint) {
        case ' ':
        case '\t':
        case '-':
        case ',':
        case '.':
        case 0xff0d:  // －
        case 0x2014:  // —
        case 0x2013:  // –
        case 0xff0c:  // ，
        case 0x3002:  // 。
        case 0x3001:  // 、
            return true;
        default:
            return false;
    }
}

}  // namespace

std::string AdbNormalizePairingCode(const std::string& spoken) {
    std::string digits;
    size_t offset = 0;
    while (offset < spoken.size()) {
        uint32_t codepoint = 0;
        const size_t length = DecodeUtf8(spoken, offset, &codepoint);
        if (length == 0) {
            return "";
        }
        offset += length;
        if (IsSeparator(codepoint)) {
            continue;
        }
        const int digit = DigitFor(codepoint);
        if (digit < 0) {
            return "";
        }
        digits.push_back(static_cast<char>('0' + digit));
        if (digits.size() > 6) {
            return "";
        }
    }
    return digits.size() == 6 ? digits : "";
}
