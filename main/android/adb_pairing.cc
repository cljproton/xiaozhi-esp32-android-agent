#include "adb_pairing.h"

#include <cstring>
#include <memory>
#include <vector>

#include <esp_log.h>
#include <psa/crypto.h>

#include "third_party/spake2/spake2.h"

namespace {

constexpr char kTag[] = "AdbPairing";

// PairingPacketHeader in AOSP: version, type, big endian payload size.
constexpr uint8_t kPairingVersion = 1;
constexpr uint8_t kSpake2MsgPacket = 0;
constexpr uint8_t kPeerInfoPacket = 1;

constexpr size_t kKeyingMaterialSize = 64;
constexpr size_t kAesKeySize = 16;
constexpr size_t kGcmTagSize = 16;
// sizeof(PeerInfo) in AOSP, of which the first byte is the type.
constexpr size_t kPeerInfoSize = 8192;
constexpr uint8_t kPeerInfoRsaPublicKey = 0;
constexpr size_t kMaxPayload = 2 * kPeerInfoSize;

constexpr char kHkdfInfo[] = "adb pairing_auth aes-128-gcm key";
// sizeof() on purpose: AOSP hashes the terminating NUL as part of the name.
constexpr char kClientName[] = "adb pair client";
constexpr char kServerName[] = "adb pair server";

bool WritePacket(AdbPairingStream* stream, uint8_t type, const uint8_t* payload, size_t size) {
    const uint8_t header[6] = {kPairingVersion, type,
                               static_cast<uint8_t>(size >> 24),
                               static_cast<uint8_t>(size >> 16),
                               static_cast<uint8_t>(size >> 8),
                               static_cast<uint8_t>(size)};
    return stream->WriteFully(header, sizeof(header)) && stream->WriteFully(payload, size);
}

bool ReadPacket(AdbPairingStream* stream, uint8_t expected_type, std::vector<uint8_t>* payload) {
    uint8_t header[6];
    if (!stream->ReadFully(header, sizeof(header))) {
        return false;
    }
    if (header[0] != kPairingVersion || header[1] != expected_type) {
        ESP_LOGE(kTag, "Unexpected pairing packet version=%u type=%u", header[0], header[1]);
        return false;
    }
    const size_t size = (static_cast<size_t>(header[2]) << 24) |
                        (static_cast<size_t>(header[3]) << 16) |
                        (static_cast<size_t>(header[4]) << 8) | static_cast<size_t>(header[5]);
    if (size == 0 || size > kMaxPayload) {
        ESP_LOGE(kTag, "Pairing payload of %u bytes is out of range", static_cast<unsigned>(size));
        return false;
    }
    payload->resize(size);
    return stream->ReadFully(payload->data(), size);
}

// HKDF-SHA256 with an empty salt, exactly what AOSP's Aes128Gcm does with the
// SPAKE2 key material.
bool DeriveAesKey(const uint8_t* key_material, size_t key_material_len, uint8_t key[kAesKeySize]) {
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status = psa_crypto_init();
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_setup(&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SALT, nullptr,
                                                0);
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SECRET,
                                                key_material, key_material_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_INFO,
                                                reinterpret_cast<const uint8_t*>(kHkdfInfo),
                                                sizeof(kHkdfInfo) - 1);
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_output_bytes(&operation, key, kAesKeySize);
    }
    psa_key_derivation_abort(&operation);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(kTag, "Failed to derive the pairing cipher key: %ld", static_cast<long>(status));
        return false;
    }
    return true;
}

bool AesGcm(bool encrypt, const uint8_t key[kAesKeySize], const uint8_t* in, size_t in_len,
            std::vector<uint8_t>* out) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, kAesKeySize * 8);
    psa_set_key_usage_flags(&attributes, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

    psa_status_t status = psa_crypto_init();
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (status == PSA_SUCCESS) {
        status = psa_import_key(&attributes, key, kAesKeySize, &key_id);
    }
    // Pairing exchanges exactly one encrypted packet in each direction, so the
    // nonce is always sequence zero: twelve zero bytes.
    const uint8_t nonce[12] = {};
    out->resize(encrypt ? in_len + kGcmTagSize : in_len);
    size_t out_len = 0;
    if (status == PSA_SUCCESS) {
        if (encrypt) {
            status = psa_aead_encrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce), nullptr, 0, in,
                                      in_len, out->data(), out->size(), &out_len);
        } else {
            status = psa_aead_decrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce), nullptr, 0, in,
                                      in_len, out->data(), out->size(), &out_len);
        }
        psa_destroy_key(key_id);
    }
    if (status != PSA_SUCCESS) {
        // A wrong pairing code only shows up here, as a failed GCM tag.
        ESP_LOGE(kTag, "Pairing %s failed: %ld", encrypt ? "encrypt" : "decrypt",
                 static_cast<long>(status));
        return false;
    }
    out->resize(out_len);
    return true;
}

}  // namespace

bool AdbPairingRun(AdbPairingStream* stream, const std::string& pairing_code,
                   const uint8_t keying_material[64], const std::string& our_public_key,
                   std::string* peer_public_key) {
    if (pairing_code.size() != 6) {
        ESP_LOGE(kTag, "Pairing code must be six digits");
        return false;
    }

    // AOSP appends the TLS exporter to the spoken code, so a stolen connection
    // cannot be finished with only the code.
    uint8_t password[6 + kKeyingMaterialSize];
    memcpy(password, pairing_code.data(), 6);
    memcpy(password + 6, keying_material, kKeyingMaterialSize);

    std::unique_ptr<spake2_ctx_st, void (*)(spake2_ctx_st*)> spake2(
        SPAKE2_CTX_new(spake2_role_alice, reinterpret_cast<const uint8_t*>(kClientName),
                       sizeof(kClientName), reinterpret_cast<const uint8_t*>(kServerName),
                       sizeof(kServerName)),
        SPAKE2_CTX_free);
    if (spake2 == nullptr) {
        ESP_LOGE(kTag, "Failed to create a SPAKE2 context");
        return false;
    }

    uint8_t spake2_msg[SPAKE2_MAX_MSG_SIZE];
    size_t spake2_len = 0;
    if (SPAKE2_generate_msg(spake2.get(), spake2_msg, &spake2_len, sizeof(spake2_msg), password,
                            sizeof(password)) != 1 ||
        spake2_len == 0) {
        ESP_LOGE(kTag, "Failed to generate the SPAKE2 message");
        return false;
    }
    if (!WritePacket(stream, kSpake2MsgPacket, spake2_msg, spake2_len)) {
        return false;
    }

    std::vector<uint8_t> their_msg;
    if (!ReadPacket(stream, kSpake2MsgPacket, &their_msg)) {
        return false;
    }
    uint8_t key_material[SPAKE2_MAX_KEY_SIZE];
    size_t key_material_len = 0;
    if (SPAKE2_process_msg(spake2.get(), key_material, &key_material_len, sizeof(key_material),
                           their_msg.data(), their_msg.size()) != 1 ||
        key_material_len == 0) {
        ESP_LOGE(kTag, "Failed to process the peer's SPAKE2 message");
        return false;
    }
    // The context must not be used again once the key is derived.
    spake2.reset();

    uint8_t aes_key[kAesKeySize];
    if (!DeriveAesKey(key_material, key_material_len, aes_key)) {
        return false;
    }

    // PeerInfo: a type byte followed by a NUL terminated ADB public key, zero
    // padded to the full 8192 bytes AOSP always encrypts.
    std::vector<uint8_t> peer_info(kPeerInfoSize, 0);
    peer_info[0] = kPeerInfoRsaPublicKey;
    if (our_public_key.empty() || our_public_key.size() + 1 > kPeerInfoSize - 1) {
        return false;
    }
    memcpy(peer_info.data() + 1, our_public_key.data(), our_public_key.size());

    std::vector<uint8_t> encrypted;
    if (!AesGcm(true, aes_key, peer_info.data(), peer_info.size(), &encrypted) ||
        !WritePacket(stream, kPeerInfoPacket, encrypted.data(), encrypted.size())) {
        return false;
    }

    std::vector<uint8_t> reply;
    if (!ReadPacket(stream, kPeerInfoPacket, &reply)) {
        return false;
    }
    std::vector<uint8_t> decrypted;
    if (!AesGcm(false, aes_key, reply.data(), reply.size(), &decrypted)) {
        return false;
    }
    // GCM tag verification succeeded -> peer knows the SPAKE2 key, pairing is valid.
    // The PeerInfo layout varies across Android versions; we only log it.
    if (decrypted.size() < 2) {
        ESP_LOGW(kTag, "Peer info too short (%u bytes), but pairing succeeded",
                 static_cast<unsigned>(decrypted.size()));
    } else {
        ESP_LOGI(kTag, "Peer info: %u bytes, type %u", static_cast<unsigned>(decrypted.size()),
                 static_cast<unsigned>(decrypted[0]));
    }
    // We don't actually use the peer public key (TLS uses VERIFY_NONE, AUTH uses our key).
    // If it's empty or malformed, just log and continue -- pairing still succeeded.
    if (decrypted.size() >= 2) {
        const char* text = reinterpret_cast<const char*>(decrypted.data() + 1);
        *peer_public_key = std::string(text, strnlen(text, decrypted.size() - 1));
        if (peer_public_key->empty()) {
            ESP_LOGW(kTag, "Peer public key empty, but pairing succeeded");
        }
    }
    return true;
}
