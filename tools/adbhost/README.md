# adbhost

Host build of the Android control code in `main/android`, so the ADB protocol
can be driven from a laptop with gdb, a byte trace and a two second rebuild
instead of a five minute flash.

It compiles the firmware sources unchanged (`adb_net.cc`, `adb_connection.cc`,
`adb_frame.cc`, `adb_crypto.cc`, `adb_pairing.cc`, `adb_shell.h`); only the
platform layer is replaced:

| Firmware | Harness |
| --- | --- |
| `esp_log.h` | `shim/esp_log.h`, timestamped to stderr, level from `ADBHOST_LOG` |
| NVS `Settings` | `shim/settings.h`, one file per key under `build/nvs/` |
| `esp_fill_random` | `getentropy()` in `main.cc` |
| Mbed TLS component | ESP-IDF's vendored Mbed TLS 4.1, compiled for the host |

## Build

```sh
sh tools/adbhost/build.sh
```

The first run also compiles ESP-IDF's Mbed TLS (~110 files, a minute). `build/`
is git-ignored and holds the binary, the Mbed TLS objects and the stored keys.

## Use

```sh
cd tools/adbhost/build
./adbhost status                          # stored address + pairing
./adbhost --host 192.168.1.165 --port 44293 connect
./adbhost --trace shell echo hi           # hexdump every byte over TLS
./adbhost look                            # focus app + numbered controls
./adbhost tap --index 3
./adbhost type "hello"                    # ASCII only; CJK needs the IME path
```

`shell`, `look`, `tap`, `type` and `key` remember the last address in
`build/nvs/android/`, so `--host`/`--port` are only needed once per session.

## Pairing

The harness is its own ADB client with its own RSA key, so adbd has to trust it
before it accepts the TLS certificate:

```sh
./adbhost --host 192.168.1.165 --port 37123 pair --code 123456
```

The pairing port and code come from the phone's "Pair device with pairing code"
dialog and are only valid while that dialog is open. The control port from the
"Wireless debugging" screen is a different number and changes whenever wireless
debugging is turned off and on; `python3 discover.py` asks the LAN over mDNS for
the current one.

## Notes

- `psa_crypto_init()` has to run before the stored RSA key is loaded; on the
  device ESP-IDF does that at boot. Missing it makes every key look corrupt
  (`MBEDTLS_ERR_PK_KEY_INVALID_FORMAT`) and silently regenerate it.
- `--trace` prints what the device cannot: the frames on both sides of the TLS
  upgrade, plus the raw byte direction before TLS is up.
- A green result here does not prove the device works: the harness has a large
  heap and real threads, so heap exhaustion and the heartbeat/tool race only
  show up on hardware.
