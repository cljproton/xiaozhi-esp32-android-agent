#include "adb_frame.h"

#include <vector>

namespace {

void PutLe32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>(value);
    out[1] = static_cast<uint8_t>(value >> 8);
    out[2] = static_cast<uint8_t>(value >> 16);
    out[3] = static_cast<uint8_t>(value >> 24);
}

uint32_t GetLe32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
}

}  // namespace

void AdbFrameEncode(AdbFrame frame, uint8_t out[kAdbFrameSize]) {
    frame.magic = frame.command ^ 0xffffffffu;
    PutLe32(out + 0, frame.command);
    PutLe32(out + 4, frame.arg0);
    PutLe32(out + 8, frame.arg1);
    PutLe32(out + 12, frame.data_length);
    PutLe32(out + 16, frame.data_check);
    PutLe32(out + 20, frame.magic);
}

bool AdbFrameDecode(const uint8_t in[kAdbFrameSize], AdbFrame* frame) {
    frame->command = GetLe32(in + 0);
    frame->arg0 = GetLe32(in + 4);
    frame->arg1 = GetLe32(in + 8);
    frame->data_length = GetLe32(in + 12);
    frame->data_check = GetLe32(in + 16);
    frame->magic = GetLe32(in + 20);
    return frame->magic == (frame->command ^ 0xffffffffu);
}

uint32_t AdbFrameChecksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
    }
    return sum;
}

bool ReadExactly(AdbStream* stream, uint8_t* buffer, size_t size) {
    size_t done = 0;
    while (done < size) {
        if (!stream->ReadFully(buffer + done, size - done)) {
            return false;
        }
        done = size;  // ReadFully either fills or fails
    }
    return true;
}

bool WriteExactly(AdbStream* stream, const uint8_t* data, size_t size) {
    return stream->WriteFully(data, size);
}

bool AdbRequestStls(AdbStream* stream) {
    AdbFrame hello;
    hello.command = kAdbCommandCnxn;
    hello.arg0 = kAdbVersion;
    hello.arg1 = kAdbMaxPayload;
    hello.data_length = sizeof(kAdbBanner) - 1;  // banner is NUL-terminated, adbd expects NUL
    hello.data_check = AdbFrameChecksum(reinterpret_cast<const uint8_t*>(kAdbBanner), hello.data_length);
    uint8_t header[kAdbFrameSize];
    AdbFrameEncode(hello, header);
    if (!WriteExactly(stream, header, sizeof(header)) ||
        !WriteExactly(stream, reinterpret_cast<const uint8_t*>(kAdbBanner), hello.data_length)) {
        return false;
    }

    AdbFrame reply;
    if (!ReadExactly(stream, header, sizeof(header)) || !AdbFrameDecode(header, &reply)) {
        return false;
    }
    if (reply.command != kAdbCommandStls) {
        return false;
    }
    std::vector<uint8_t> ignored(reply.data_length);
    if (reply.data_length != 0 && !ReadExactly(stream, ignored.data(), ignored.size())) {
        return false;
    }

    AdbFrame ack;
    ack.command = kAdbCommandStls;
    ack.arg0 = reply.arg0;
    AdbFrameEncode(ack, header);
    return WriteExactly(stream, header, sizeof(header));
}
