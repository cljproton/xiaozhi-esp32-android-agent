// Wraps the TLS stream and prints every byte crossing it, which the device
// cannot show: its serial log only has the frame headers AdbConnection reads.
#ifndef ADBHOST_TRACE_STREAM_H
#define ADBHOST_TRACE_STREAM_H

#include <cstdio>
#include <cstring>
#include <string>

#include "adb_frame.h"
#include "adb_io.h"

namespace adbhost {

inline const char* CommandName(uint32_t command) {
    switch (command) {
        case kAdbCommandCnxn:
            return "CNXN";
        case kAdbCommandAuth:
            return "AUTH";
        case kAdbCommandOpen:
            return "OPEN";
        case kAdbCommandOkay:
            return "OKAY";
        case kAdbCommandClose:
            return "CLSE";
        case kAdbCommandWrite:
            return "WRTE";
        case kAdbCommandStls:
            return "STLS";
        default:
            return "?";
    }
}

class TraceStream : public AdbStream {
public:
    TraceStream(AdbStream* inner, bool enabled) : inner_(inner), enabled_(enabled) {}

    bool ReadFully(uint8_t* buffer, size_t size) override {
        if (!enabled_) {
            return inner_->ReadFully(buffer, size);
        }
        const bool ok = inner_->ReadFully(buffer, size);
        Dump("<<", buffer, ok ? size : 0, ok);
        return ok;
    }

    bool WriteFully(const uint8_t* data, size_t size) override {
        if (!enabled_) {
            return inner_->WriteFully(data, size);
        }
        Dump(">>", data, size, true);
        return inner_->WriteFully(data, size);
    }

private:
    static void Dump(const char* direction, const uint8_t* data, size_t size, bool ok) {
        if (!ok) {
            std::fprintf(stderr, "%s read failed\n", direction);
            return;
        }
        if (size == kAdbFrameSize) {
            AdbFrame frame;
            if (AdbFrameDecode(data, &frame)) {
                std::fprintf(stderr, "%s %s cmd=0x%08x (%s) arg0=%u arg1=%u len=%u\n", direction,
                             "frame", frame.command, CommandName(frame.command), frame.arg0,
                             frame.arg1, frame.data_length);
                return;
            }
        }
        std::string preview;
        for (size_t i = 0; i < size && i < 64; i++) {
            const uint8_t byte = data[i];
            preview.push_back(byte >= 0x20 && byte < 0x7f ? static_cast<char>(byte) : '.');
        }
        std::fprintf(stderr, "%s %zu bytes '%s'\n", direction, size, preview.c_str());
    }

    AdbStream* inner_;
    bool enabled_;
};

}  // namespace adbhost

#endif  // ADBHOST_TRACE_STREAM_H
