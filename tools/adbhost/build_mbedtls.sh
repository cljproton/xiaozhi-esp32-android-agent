#!/bin/sh
# Builds the Mbed TLS that ESP-IDF ships for the host, once. Its own CMake cannot
# configure this rearranged tree, so the sources are compiled directly.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
IDF=${IDF_PATH:-/home/clj/.espressif/v6.1/esp-idf}
M=$IDF/components/mbedtls/mbedtls
OUT=$HERE/build/mbedtls-obj

if [ -f "$OUT/libmbed.a" ] && [ "$1" != "--force" ]; then
    echo "mbedtls already built: $OUT/libmbed.a"
    exit 0
fi

rm -rf "$OUT"
mkdir -p "$OUT"
INC="-I$HERE/shim -I$M/include -I$M/tf-psa-crypto/include -I$M/tf-psa-crypto/core \
-I$M/tf-psa-crypto/drivers/builtin/include -I$M/tf-psa-crypto/drivers/builtin/src \
-I$M/tf-psa-crypto/utilities -I$M/tf-psa-crypto/extras -I$M/tf-psa-crypto/platform \
-I$M/tf-psa-crypto/dispatch -I$M/library"
FLAGS="-O2 -fPIC -std=c99 -D_POSIX_C_SOURCE=200809L"

ls "$M"/library/*.c "$M"/tf-psa-crypto/core/*.c "$M"/tf-psa-crypto/extras/*.c \
    "$M"/tf-psa-crypto/platform/*.c "$M"/tf-psa-crypto/utilities/*.c \
    "$M"/tf-psa-crypto/drivers/builtin/src/*.c > "$OUT/sources.txt"
echo "compiling $(wc -l < "$OUT/sources.txt") Mbed TLS sources"
cat "$OUT/sources.txt" | xargs -P 8 -I{} sh -c 'cd '"$OUT"' && cc '"$FLAGS"' '"$INC"' -c "{}" -o "$(basename {} .c).o"'
ar rcs "$OUT/libmbed.a" "$OUT"/*.o
echo "built $OUT/libmbed.a"
