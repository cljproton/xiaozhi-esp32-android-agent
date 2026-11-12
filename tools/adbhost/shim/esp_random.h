#ifndef ADBHOST_ESP_RANDOM_H
#define ADBHOST_ESP_RANDOM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Filled from getentropy() in main.cc.
void esp_fill_random(void* buffer, size_t length);

#ifdef __cplusplus
}
#endif

#endif  // ADBHOST_ESP_RANDOM_H
