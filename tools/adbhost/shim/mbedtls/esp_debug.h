// The ESP port raises the Mbed TLS debug threshold for one connection. On the
// host the normal mbedtls_ssl_conf_dbg path is enough.
#ifndef ADBHOST_MBEDTLS_ESP_DEBUG_H
#define ADBHOST_MBEDTLS_ESP_DEBUG_H

#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>

static inline void mbedtls_esp_enable_debug_log(mbedtls_ssl_config* conf, int level) {
    (void)conf;
    (void)level;
}

static inline void mbedtls_esp_disable_debug_log(mbedtls_ssl_config* conf) { (void)conf; }

#endif  // ADBHOST_MBEDTLS_ESP_DEBUG_H
