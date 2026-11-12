#ifndef ADB_IO_H
#define ADB_IO_H

#include <cstddef>
#include <cstdint>

// Byte stream the ADB protocol runs over. Abstract so the protocol can be
// driven from a host test as well as from the real TLS connection.
class AdbStream {
public:
    virtual ~AdbStream() = default;

    // Reads exactly |size| bytes, false on end of stream or error.
    virtual bool ReadFully(uint8_t* buffer, size_t size) = 0;
    virtual bool WriteFully(const uint8_t* data, size_t size) = 0;
};

#endif  // ADB_IO_H
