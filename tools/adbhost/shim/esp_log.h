// ESP_LOG replacement for the host harness. The format strings in the shared
// firmware sources already carry the tag as an argument, so this only has to
// print them the way the serial console would.
#ifndef ADBHOST_ESP_LOG_H
#define ADBHOST_ESP_LOG_H

#include <stdarg.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// 0 = off, 1 = error, 2 = warn, 3 = info, 4 = debug. Set from ADBHOST_LOG.
extern int adbhost_log_level;

void adbhost_log(char level, const char* tag, const char* format, ...)
    __attribute__((format(printf, 3, 4)));

#ifdef __cplusplus
}
#endif

#define ESP_LOGE(tag, fmt, ...)                                             \
    do {                                                                    \
        if (adbhost_log_level >= 1) adbhost_log('E', tag, fmt, ##__VA_ARGS__); \
    } while (0)
#define ESP_LOGW(tag, fmt, ...)                                             \
    do {                                                                    \
        if (adbhost_log_level >= 2) adbhost_log('W', tag, fmt, ##__VA_ARGS__); \
    } while (0)
#define ESP_LOGI(tag, fmt, ...)                                             \
    do {                                                                    \
        if (adbhost_log_level >= 3) adbhost_log('I', tag, fmt, ##__VA_ARGS__); \
    } while (0)
#define ESP_LOGD(tag, fmt, ...)                                             \
    do {                                                                    \
        if (adbhost_log_level >= 4) adbhost_log('D', tag, fmt, ##__VA_ARGS__); \
    } while (0)
#define ESP_LOGV(tag, fmt, ...)                                             \
    do {                                                                    \
        if (adbhost_log_level >= 5) adbhost_log('V', tag, fmt, ##__VA_ARGS__); \
    } while (0)

#endif  // ADBHOST_ESP_LOG_H
