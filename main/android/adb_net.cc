#include "adb_net.h"

#include <cerrno>
#include <cstring>
#include <vector>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <esp_log.h>
#include <mbedtls/debug.h>
#include <mbedtls/esp_debug.h>

#include "adb_crypto.h"
#include "adb_frame.h"
#include "adb_pairing.h"

#if defined(CONFIG_MBEDTLS_DYNAMIC_FREE_CONFIG_DATA)
// ESP-IDF frees conf->key_cert, and the private key inside it, once the server's
// CertificateVerify is done. TLS 1.3 sends the client certificate after that,
// so the handshake would go out empty and the phone would drop the connection.
#error "Android control needs CONFIG_MBEDTLS_DYNAMIC_FREE_CONFIG_DATA=n"
#endif

namespace {

constexpr char kTag[] = "AdbNet";
constexpr int kTimeoutSeconds = 10;
constexpr size_t kKeyingMaterialSize = 64;

}  // namespace

AdbTlsStream::AdbTlsStream() {
    mbedtls_ssl_init(&ssl_);
    mbedtls_ssl_config_init(&config_);
}

AdbTlsStream::~AdbTlsStream() {
    Close();
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_config_free(&config_);
}

void AdbTlsStream::Close() {
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(1);
#endif
    if (ssl_ready_) {
        mbedtls_ssl_close_notify(&ssl_);
        ssl_ready_ = false;
    }
    if (socket_ >= 0) {
        ::close(socket_);
        socket_ = -1;
    }
}

bool AdbTlsStream::OpenSocket(const std::string& host, uint16_t port) {
    struct addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* results = nullptr;
    const std::string service = std::to_string(port);
    const int ret = getaddrinfo(host.c_str(), service.c_str(), &hints, &results);
    if (ret != 0) {
        ESP_LOGE(kTag, "Cannot resolve %s: %d", host.c_str(), ret);
        return false;
    }

    for (struct addrinfo* info = results; info != nullptr; info = info->ai_next) {
        socket_ = ::socket(info->ai_family, info->ai_socktype, info->ai_protocol);
        if (socket_ < 0) {
            continue;
        }
        // mbedTLS reads and writes through these timeouts, so a phone that
        // stops answering cannot wedge the audio task.
        struct timeval timeout = {kTimeoutSeconds, 0};
        setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (::connect(socket_, info->ai_addr, info->ai_addrlen) == 0) {
            break;
        }
        ::close(socket_);
        socket_ = -1;
    }
    freeaddrinfo(results);
    if (socket_ < 0) {
        ESP_LOGE(kTag, "Cannot connect to %s:%u", host.c_str(), port);
    }
    return socket_ >= 0;
}

bool AdbTlsStream::ReadPlain(uint8_t* buffer, size_t size) {
    size_t done = 0;
    while (done < size) {
        const ssize_t ret = ::recv(socket_, buffer + done, size - done, 0);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        if (ret <= 0) {
            return false;
        }
        done += static_cast<size_t>(ret);
    }
    return true;
}

bool AdbTlsStream::WritePlain(const uint8_t* data, size_t size) {
    size_t done = 0;
    while (done < size) {
        const ssize_t ret = ::send(socket_, data + done, size - done, 0);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        if (ret <= 0) {
            return false;
        }
        done += static_cast<size_t>(ret);
    }
    return true;
}

bool AdbTlsStream::UpgradeStls() {
    struct PlainStream : AdbStream {
        AdbTlsStream* self;
        explicit PlainStream(AdbTlsStream* s) : self(s) {}
        bool ReadFully(uint8_t* buffer, size_t size) override {
            return self->ReadPlain(buffer, size);
        }
        bool WriteFully(const uint8_t* data, size_t size) override {
            return self->WritePlain(data, size);
        }
    };
    PlainStream plain(this);
    return AdbRequestStls(&plain);
}

bool AdbTlsStream::Connect(const std::string& host, uint16_t port, mbedtls_x509_crt* certificate,
                           mbedtls_pk_context* key, bool upgrade_stls) {
    if (!OpenSocket(host, port)) {
        return false;
    }
    if (upgrade_stls && !UpgradeStls()) {
        ESP_LOGE(kTag, "STLS upgrade failed");
        Close();
        return false;
    }

    int ret = mbedtls_ssl_config_defaults(&config_, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        ESP_LOGE(kTag, "TLS client config failed: -0x%04x", static_cast<unsigned>(-ret));
        Close();
        return false;
    }
    // adbd pins the protocol version on both ends.
    mbedtls_ssl_conf_min_tls_version(&config_, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&config_, MBEDTLS_SSL_VERSION_TLS1_3);
    // The certificate is self signed and regenerated on every adbd restart, so
    // the chain proves nothing; pairing authenticates with SPAKE2 and later
    // connections with the AUTH signature.
    mbedtls_ssl_conf_authmode(&config_, MBEDTLS_SSL_VERIFY_NONE);
#if defined(MBEDTLS_DEBUG_C)
    // Disable debug for adb connection to avoid handshake slowdown.
    // mbedtls_esp_enable_debug_log(&config_, 2);
#endif
    if (certificate != nullptr && key != nullptr) {
        ret = mbedtls_ssl_conf_own_cert(&config_, certificate, key);
        if (ret != 0) {
            ESP_LOGE(kTag, "TLS client certificate failed: -0x%04x", static_cast<unsigned>(-ret));
            Close();
            return false;
        }
    }

    ret = mbedtls_ssl_setup(&ssl_, &config_);
    if (ret != 0) {
        ESP_LOGE(kTag, "TLS setup failed: -0x%04x", static_cast<unsigned>(-ret));
        Close();
        return false;
    }
    mbedtls_ssl_set_bio(&ssl_, this, SendCallback, RecvCallback, nullptr);

    while ((ret = mbedtls_ssl_handshake(&ssl_)) != 0) {
        // A TLS 1.3 server hands out session tickets before the handshake
        // reports success; that is a pause, not a failure.
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
            ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            continue;
        }
        ESP_LOGE(kTag, "TLS handshake failed: -0x%04x", static_cast<unsigned>(-ret));
        Close();
        return false;
    }
    ssl_ready_ = true;
    return true;
}

bool AdbTlsStream::ExportKeyingMaterial(uint8_t out[64]) {
    if (!ssl_ready_) {
        return false;
    }
    // sizeof() on purpose: adbd passes the terminating NUL in the label.
    const int ret = mbedtls_ssl_export_keying_material(&ssl_, out, kKeyingMaterialSize, "adb-label",
                                                       sizeof("adb-label"), nullptr, 0, 0);
    if (ret != 0) {
        ESP_LOGE(kTag, "Cannot export TLS keying material: -0x%04x", static_cast<unsigned>(-ret));
        return false;
    }
    return true;
}

bool AdbTlsStream::ReadFully(uint8_t* buffer, size_t size) {
    size_t done = 0;
    while (done < size) {
        const int ret = mbedtls_ssl_read(&ssl_, buffer + done, size - done);
        if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            return false;
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
            ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            continue;
        }
        if (ret < 0) {
            ESP_LOGE(kTag, "TLS read failed: -0x%04x", static_cast<unsigned>(-ret));
            return false;
        }
        done += static_cast<size_t>(ret);
    }
    return true;
}

bool AdbTlsStream::WriteFully(const uint8_t* data, size_t size) {
    size_t done = 0;
    while (done < size) {
        const int ret = mbedtls_ssl_write(&ssl_, data + done, size - done);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret <= 0) {
            ESP_LOGE(kTag, "TLS write failed: -0x%04x", static_cast<unsigned>(-ret));
            return false;
        }
        done += static_cast<size_t>(ret);
    }
    return true;
}

int AdbTlsStream::SendCallback(void* context, const unsigned char* data, size_t size) {
    auto* self = static_cast<AdbTlsStream*>(context);
    const int ret = ::send(self->socket_, data, size, 0);
    if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return ret;
}

int AdbTlsStream::RecvCallback(void* context, unsigned char* data, size_t size) {
    auto* self = static_cast<AdbTlsStream*>(context);
    const int ret = ::recv(self->socket_, data, size, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    return ret;
}

bool AdbPairWithPhone(const std::string& host, uint16_t port, const std::string& pairing_code,
                      std::string* peer_public_key) {
    AdbIdentity& identity = AdbIdentity::Get();
    if (!identity.EnsureReady()) {
        return false;
    }
    AdbTlsStream stream;
    if (!stream.Connect(host, port, identity.certificate(), identity.private_key())) {
        return false;
    }
    uint8_t keying_material[kKeyingMaterialSize];
    if (!stream.ExportKeyingMaterial(keying_material)) {
        return false;
    }
    return AdbPairingRun(&stream, pairing_code, keying_material, identity.encoded_public_key(),
                         peer_public_key);
}
