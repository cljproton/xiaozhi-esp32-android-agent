#!/bin/sh
# Builds the harness against the firmware sources, unchanged: same adb_*.cc,
# same adb_shell.h, only the platform layer comes from shim/.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$HERE/../../main/android
IDF=${IDF_PATH:-/home/clj/.espressif/v6.1/esp-idf}
M=$IDF/components/mbedtls/mbedtls
OUT=$HERE/build

sh "$HERE/build_mbedtls.sh"

INC="-I$HERE/shim -I$HERE -I$SRC -I$SRC/third_party/spake2 \
-I$M/include -I$M/tf-psa-crypto/include -I$M/tf-psa-crypto/core \
-I$M/tf-psa-crypto/drivers/builtin/include -I$M/tf-psa-crypto/drivers/builtin/src \
-I$M/tf-psa-crypto/utilities -I$M/tf-psa-crypto/extras -I$M/tf-psa-crypto/platform \
-I$M/tf-psa-crypto/dispatch -I$M/library"
FLAGS="-std=c++23 -include esp_log.h -O1 -g -Wall -Wextra -Wno-unused-parameter -pthread"

cd "$OUT"
cc -O1 -g -std=c99 -c -o spake2_port.o $INC "$SRC/spake2_port.c"
# The vendored spake2 header relies on stdint.h arriving from somewhere else.
cc -O1 -g -std=c99 -include stdint.h -c -o spake2.o -I"$SRC/third_party/spake2" \
    "$SRC/third_party/spake2/spake2.c"
c++ $FLAGS $INC -o adbhost \
    "$HERE/main.cc" \
    "$SRC/adb_net.cc" "$SRC/adb_connection.cc" "$SRC/adb_frame.cc" \
    "$SRC/adb_crypto.cc" "$SRC/adb_pairing.cc" "$SRC/adb_pin.cc" \
    spake2_port.o spake2.o "$OUT/mbedtls-obj/libmbed.a" -pthread
echo "built $OUT/adbhost"
