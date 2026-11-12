"""Exercise the ADB frame codec and the spoken pairing code parser on the host."""

import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
ANDROID = ROOT / "main/android"

MAIN = r'''
#include <cassert>
#include <cstdio>

#include "adb_frame.h"
#include "adb_pin.h"

static void CheckFrameRoundTrip() {
    AdbFrame frame;
    frame.command = kAdbCommandOpen;
    frame.arg0 = 0x11223344;
    frame.arg1 = 7;
    frame.data_length = 21;
    frame.data_check = 1234;

    uint8_t bytes[kAdbFrameSize];
    AdbFrameEncode(frame, bytes);

    // Little endian on the wire, magic is the one's complement of the command.
    assert(bytes[0] == 0x4f && bytes[1] == 0x50 && bytes[2] == 0x45 && bytes[3] == 0x4e);
    assert(bytes[20] == (0x4f ^ 0xff) && bytes[23] == (0x4e ^ 0xff));

    AdbFrame decoded;
    assert(AdbFrameDecode(bytes, &decoded));
    assert(decoded.command == kAdbCommandOpen);
    assert(decoded.arg0 == 0x11223344);
    assert(decoded.arg1 == 7);
    assert(decoded.data_length == 21);
    assert(decoded.data_check == 1234);

    // A stream that lost sync has to be rejected.
    bytes[21] ^= 0x01;
    assert(!AdbFrameDecode(bytes, &decoded));
}

static void CheckChecksum() {
    const uint8_t data[] = {0x01, 0x02, 0xff, 0x00};
    assert(AdbFrameChecksum(data, sizeof(data)) == 0x102);
    assert(AdbFrameChecksum(nullptr, 0) == 0);
}

static void CheckPin(const char* spoken, const char* expected) {
    const std::string actual = AdbNormalizePairingCode(spoken);
    if (actual != expected) {
        std::printf("%s -> %s, expected %s\n", spoken, actual.c_str(), expected);
        assert(false);
    }
}

int main() {
    CheckFrameRoundTrip();
    CheckChecksum();

    CheckPin("123456", "123456");
    CheckPin("123-456", "123456");
    CheckPin("1 2 3 4 5 6", "123456");
    CheckPin("  123 456 ", "123456");
    CheckPin("123，456", "123456");
    // Full-width digits and Chinese numerals, which is what speech recognition
    // tends to produce.
    CheckPin("１２３４５６", "123456");
    CheckPin("一二三四五六", "123456");
    CheckPin("幺两三四五六", "123456");
    CheckPin("壹贰叁肆伍陆", "123456");

    // Anything that is not exactly six digits has to be refused.
    CheckPin("12345", "");
    CheckPin("1234567", "");
    CheckPin("12345a", "");
    CheckPin("", "");
    CheckPin("密码是123456", "");

    std::printf("android protocol tests passed\n");
    return 0;
}
'''


@unittest.skipUnless(shutil.which("c++"), "requires a host C++ compiler")
class AndroidProtocolTest(unittest.TestCase):
    def test_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "android-protocol-test"
            build = subprocess.run(
                [
                    "c++",
                    "-std=c++23",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    f"-I{ANDROID}",
                    str(ANDROID / "adb_frame.cc"),
                    str(ANDROID / "adb_pin.cc"),
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
            run = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("android protocol tests passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
