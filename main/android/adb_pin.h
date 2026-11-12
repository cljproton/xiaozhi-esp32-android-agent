#ifndef ADB_PIN_H
#define ADB_PIN_H

#include <string>

// Turns a spoken or typed ADB pairing code into exactly six ASCII digits.
// Accepts "一二三四五六", "1 2 3 4 5 6", "123-456", full-width digits and the
// usual separators. Returns an empty string when the input is not a 6 digit
// code, so the caller can ask the user to repeat it.
std::string AdbNormalizePairingCode(const std::string& spoken);

#endif  // ADB_PIN_H
