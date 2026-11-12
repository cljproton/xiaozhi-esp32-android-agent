"""Drive the ADB message channel against a fake adbd over a socket pair."""

import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
ANDROID = ROOT / "main/android"

MAIN = r'''
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "adb_connection.h"
#include "adb_frame.h"

namespace {

bool ReadFd(int fd, uint8_t* buffer, size_t size) {
    size_t done = 0;
    while (done < size) {
        const ssize_t read_size = read(fd, buffer + done, size - done);
        if (read_size <= 0) {
            return false;
        }
        done += static_cast<size_t>(read_size);
    }
    return true;
}

bool WriteFd(int fd, const uint8_t* buffer, size_t size) {
    size_t done = 0;
    while (done < size) {
        const ssize_t write_size = write(fd, buffer + done, size - done);
        if (write_size <= 0) {
            return false;
        }
        done += static_cast<size_t>(write_size);
    }
    return true;
}

struct SocketStream : AdbStream {
    explicit SocketStream(int descriptor) : fd(descriptor) {}
    int fd;
    bool ReadFully(uint8_t* buffer, size_t size) override { return ReadFd(fd, buffer, size); }
    bool WriteFully(const uint8_t* data, size_t size) override { return WriteFd(fd, data, size); }
};

struct FakeFrame {
    AdbFrame frame;
    std::string payload;
};

bool FakeRead(int fd, FakeFrame* out) {
    uint8_t header[kAdbFrameSize];
    if (!ReadFd(fd, header, sizeof(header)) || !AdbFrameDecode(header, &out->frame)) {
        return false;
    }
    out->payload.resize(out->frame.data_length);
    return out->frame.data_length == 0 ||
           ReadFd(fd, reinterpret_cast<uint8_t*>(out->payload.data()), out->frame.data_length);
}

bool FakeSend(int fd, uint32_t command, uint32_t arg0, uint32_t arg1, const std::string& payload) {
    AdbFrame frame;
    frame.command = command;
    frame.arg0 = arg0;
    frame.arg1 = arg1;
    frame.data_length = static_cast<uint32_t>(payload.size());
    frame.data_check =
        AdbFrameChecksum(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
    uint8_t header[kAdbFrameSize];
    AdbFrameEncode(frame, header);
    return WriteFd(fd, header, sizeof(header)) &&
           (payload.empty() || WriteFd(fd, reinterpret_cast<const uint8_t*>(payload.data()),
                                       payload.size()));
}

// The identity stand-in: the "signature" starts with the token so the fake
// adbd can tell which challenge was signed.
bool SignToken(const uint8_t token[20], uint8_t signature[AdbConnection::kSignatureSize]) {
    std::memset(signature, 0, AdbConnection::kSignatureSize);
    std::memcpy(signature, token, 20);
    return true;
}

constexpr uint32_t kFakePeerMaxPayload = 4096;
// Below the skip-checksum version so payload checksums stay enforced and the
// corrupt-frame test can expect a rejection.
constexpr uint32_t kFakePeerVersion = 0x01000000;
constexpr uint32_t kFakeRemoteId = 42;
const char kBanner[] = "device::fake\0";

// Reads our CNXN, authenticates us and sends the device banner.
bool FakeHandshake(int fd, const uint8_t token[20]) {
    FakeFrame open;
    if (!FakeRead(fd, &open)) {
        return false;
    }
    assert(open.frame.command == kAdbCommandCnxn);
    assert(open.frame.arg1 == 1024 * 1024);
    assert(open.payload.compare(0, 6, "host::") == 0);

    assert(FakeSend(fd, kAdbCommandAuth, kAdbAuthToken, 0,
                    std::string(reinterpret_cast<const char*>(token), 20)));

    FakeFrame auth;
    if (!FakeRead(fd, &auth)) {
        return false;
    }
    assert(auth.frame.command == kAdbCommandAuth);
    assert(auth.frame.arg0 == kAdbAuthSignature);
    assert(auth.payload.size() == AdbConnection::kSignatureSize);
    assert(std::memcmp(auth.payload.data(), token, 20) == 0);

    return FakeSend(fd, kAdbCommandCnxn, kFakePeerVersion, kFakePeerMaxPayload, kBanner);
}

struct Fixture {
    int client = -1;
    int server = -1;
    Fixture() {
        int pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        client = pair[0];
        server = pair[1];
    }
    ~Fixture() {
        close(client);
        close(server);
    }
};

void RunShellOutput() {
    Fixture pair;
    SocketStream stream(pair.client);
    AdbConnection connection(&stream, SignToken, "");
    const uint8_t token[20] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};

    std::thread fake([&pair, &token]() {
        assert(FakeHandshake(pair.server, token));
        FakeFrame open;
        assert(FakeRead(pair.server, &open));
        assert(open.frame.command == kAdbCommandOpen);
        assert(open.frame.arg0 == 1);
        assert(open.payload == std::string("shell:echo hi\0", 14));

        assert(FakeSend(pair.server, kAdbCommandOkay, kFakeRemoteId, 1, ""));
        assert(FakeSend(pair.server, kAdbCommandWrite, kFakeRemoteId, 1, "hi\n"));

        FakeFrame ack;
        assert(FakeRead(pair.server, &ack));
        assert(ack.frame.command == kAdbCommandOkay);
        assert(ack.frame.arg0 == 1 && ack.frame.arg1 == kFakeRemoteId);

        assert(FakeSend(pair.server, kAdbCommandClose, kFakeRemoteId, 1, ""));
    });

    assert(connection.Connect());
    std::string output;
    assert(connection.RunService("shell:echo hi", "", &output));
    assert(output == "hi\n");
    fake.join();
}

// Data that arrives before the device acknowledged the open still has to be
// accepted, with the remote id taken from the data frame, and a caller that
// does not want the output must not be dereferenced.
void RunWriteBeforeOkay() {
    Fixture pair;
    SocketStream stream(pair.client);
    AdbConnection connection(&stream, SignToken, "");
    const uint8_t token[20] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

    std::thread fake([&pair, &token]() {
        assert(FakeHandshake(pair.server, token));
        FakeFrame open;
        assert(FakeRead(pair.server, &open));
        assert(open.frame.command == kAdbCommandOpen);

        // No OKAY first: the device sends its output straight away.
        assert(FakeSend(pair.server, kAdbCommandWrite, kFakeRemoteId, 1, "noise\n"));
        FakeFrame ack;
        assert(FakeRead(pair.server, &ack));
        assert(ack.frame.command == kAdbCommandOkay);
        assert(ack.frame.arg0 == 1 && ack.frame.arg1 == kFakeRemoteId);
        assert(FakeSend(pair.server, kAdbCommandClose, kFakeRemoteId, 1, ""));
    });

    assert(connection.Connect());
    assert(connection.RunService("shell:echo", "", nullptr));
    fake.join();
}

void RunShellInput() {
    Fixture pair;
    SocketStream stream(pair.client);
    AdbConnection connection(&stream, SignToken, "");
    const uint8_t token[20] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};

    std::thread fake([&pair, &token]() {
        assert(FakeHandshake(pair.server, token));
        FakeFrame open;
        assert(FakeRead(pair.server, &open));
        assert(open.payload == std::string("shell:cat\0", 10));
        assert(FakeSend(pair.server, kAdbCommandOkay, kFakeRemoteId, 1, ""));

        FakeFrame write;
        assert(FakeRead(pair.server, &write));
        assert(write.frame.command == kAdbCommandWrite);
        assert(write.frame.arg0 == 1 && write.frame.arg1 == kFakeRemoteId);
        assert(write.payload == "hello");
        assert(FakeSend(pair.server, kAdbCommandOkay, kFakeRemoteId, 1, ""));

        assert(FakeSend(pair.server, kAdbCommandWrite, kFakeRemoteId, 1, "hello"));
        FakeFrame ack;
        assert(FakeRead(pair.server, &ack));
        assert(ack.frame.command == kAdbCommandOkay);
        assert(FakeSend(pair.server, kAdbCommandClose, kFakeRemoteId, 1, ""));
    });

    assert(connection.Connect());
    std::string output;
    assert(connection.RunService("shell:cat", "hello", &output));
    assert(output == "hello");
    fake.join();
}

// adbd refuses the service by closing the stream before acknowledging it.
void RunRefusedService() {
    Fixture pair;
    SocketStream stream(pair.client);
    AdbConnection connection(&stream, SignToken, "");
    const uint8_t token[20] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};

    std::thread fake([&pair, &token]() {
        assert(FakeHandshake(pair.server, token));
        FakeFrame open;
        assert(FakeRead(pair.server, &open));
        assert(FakeSend(pair.server, kAdbCommandClose, 0, 1, ""));
    });

    assert(connection.Connect());
    std::string output;
    assert(!connection.RunService("shell:nope", "", &output));
    fake.join();
}

// A corrupted payload has to be rejected instead of returned as output.
void RunBadChecksum() {
    Fixture pair;
    SocketStream stream(pair.client);
    AdbConnection connection(&stream, SignToken, "");
    const uint8_t token[20] = {5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5};

    std::thread fake([&pair, &token]() {
        assert(FakeHandshake(pair.server, token));
        FakeFrame open;
        assert(FakeRead(pair.server, &open));
        assert(FakeSend(pair.server, kAdbCommandOkay, kFakeRemoteId, 1, ""));

        // Hand written frame with a deliberate checksum mismatch.
        AdbFrame frame;
        frame.command = kAdbCommandWrite;
        frame.arg0 = kFakeRemoteId;
        frame.arg1 = 1;
        frame.data_length = 2;
        frame.data_check = 0;
        frame.magic = frame.command ^ 0xffffffffu;
        uint8_t header[kAdbFrameSize];
        AdbFrameEncode(frame, header);
        uint8_t payload[2] = {'n', 'o'};
        assert(WriteFd(pair.server, header, sizeof(header)));
        assert(WriteFd(pair.server, payload, sizeof(payload)));
    });

    assert(connection.Connect());
    std::string output;
    assert(!connection.RunService("shell:echo", "", &output));
    fake.join();
}

}  // namespace

int main() {
    RunShellOutput();
    RunWriteBeforeOkay();
    RunShellInput();
    RunRefusedService();
    RunBadChecksum();
    std::printf("android connection tests passed\n");
    return 0;
}
'''


@unittest.skipUnless(shutil.which("c++"), "requires a host C++ compiler")
class AndroidConnectionTest(unittest.TestCase):
    def test_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "android-connection-test"
            build = subprocess.run(
                [
                    "c++",
                    "-std=c++23",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pthread",
                    f"-I{ANDROID}",
                    str(ANDROID / "adb_connection.cc"),
                    str(ANDROID / "adb_frame.cc"),
                    "-x",
                    "c++",
                    "-",
                    "-o",
                    str(binary),
                ],
                input=MAIN,
                text=True,
                capture_output=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("android connection tests passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
