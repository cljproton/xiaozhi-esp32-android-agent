// Before adb_crypto.h: mbedtls/pk.h pulls in the bignum header without the
// declarations the ESP-IDF wrapper adds, and the include guard then hides them.
#include <mbedtls/bignum.h>

#include "adb_crypto.h"

#include <cstring>
#include <vector>

#include <esp_log.h>
#include <esp_random.h>
#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <psa/crypto.h>

#include "settings.h"

namespace {

constexpr char kTag[] = "AdbIdentity";
constexpr char kNamespace[] = "adb";
constexpr char kPrivateKeySetting[] = "private_key";
constexpr char kPublicKeySetting[] = "public_key";
// Android shows this name in its "Allow wireless debugging?" dialog.
constexpr char kKeyName[] = " xiaozhi@esp32";
constexpr size_t kRsaBits = 2048;
constexpr size_t kModulusSize = kRsaBits / 8;
// PKCS#1 RSAPrivateKey DER for a 2048 bit key is about 1.2 KB.
constexpr size_t kMaxPrivateKeyDer = 2048;
// Android's own public key blob: modulus size in words and the Montgomery
// helper constants n0inv and rr, then modulus and exponent, all little endian.
constexpr size_t kAndroidKeySize = 3 * sizeof(uint32_t) + 2 * kModulusSize;

void PutLe32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>(value);
    out[1] = static_cast<uint8_t>(value >> 8);
    out[2] = static_cast<uint8_t>(value >> 16);
    out[3] = static_cast<uint8_t>(value >> 24);
}

uint32_t GetBe32(const uint8_t* in) {
    return (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
}

std::string Base64Encode(const uint8_t* data, size_t len) {
    size_t out_len = 0;
    mbedtls_base64_encode(nullptr, 0, &out_len, data, len);
    std::string out(out_len, '\0');
    if (mbedtls_base64_encode(reinterpret_cast<unsigned char*>(out.data()), out.size(), &out_len,
                              data, len) != 0) {
        return {};
    }
    out.resize(out_len);
    return out;
}

bool Base64Decode(const std::string& text, std::vector<uint8_t>* out) {
    out->resize(text.size() * 3 / 4 + 4);
    size_t out_len = 0;
    if (mbedtls_base64_decode(out->data(), out->size(), &out_len,
                              reinterpret_cast<const unsigned char*>(text.data()),
                              text.size()) != 0) {
        return false;
    }
    out->resize(out_len);
    return true;
}

// rr = 2^4096 mod n = (2^2048 mod n)^2 mod n, the value Android's
// RSA_MONT_CTX wants next to n0inv.
bool ComputeRr(mbedtls_mpi* n, uint8_t out[kModulusSize]) {
    mbedtls_mpi two;
    mbedtls_mpi power;
    mbedtls_mpi rr;
    mbedtls_mpi_init(&two);
    mbedtls_mpi_init(&power);
    mbedtls_mpi_init(&rr);
    bool ok = mbedtls_mpi_lset(&two, 2) == 0 &&
              mbedtls_mpi_lset(&power, 2 * kModulusSize * 8) == 0 &&
              mbedtls_mpi_exp_mod(&rr, &two, &power, n, nullptr) == 0 &&
              mbedtls_mpi_write_binary(&rr, out, kModulusSize) == 0;
    mbedtls_mpi_free(&two);
    mbedtls_mpi_free(&power);
    mbedtls_mpi_free(&rr);
    return ok;
}

// Re-encodes a PKCS#1 RSAPublicKey (what psa_export_public_key produces) into
// the 524 byte blob adbd expects, base64 encoded. adbd decodes it back with
// RSA_new/BN_bin2bn and checks nothing, so a mismatch only shows up as a failed
// pairing.
bool BuildAndroidPublicKey(const uint8_t* der, size_t der_len, std::string* out) {
    auto* p = const_cast<unsigned char*>(der);
    const unsigned char* end = der + der_len;
    size_t seq_len = 0;
    if (mbedtls_asn1_get_tag(&p, end, &seq_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) !=
        0) {
        return false;
    }

    mbedtls_mpi modulus;
    mbedtls_mpi exponent;
    mbedtls_mpi_init(&modulus);
    mbedtls_mpi_init(&exponent);
    uint8_t modulus_be[kModulusSize];
    uint8_t exponent_be[sizeof(uint32_t)];
    uint8_t rr_be[kModulusSize];
    bool ok = mbedtls_asn1_get_mpi(&p, end, &modulus) == 0 &&
              mbedtls_asn1_get_mpi(&p, end, &exponent) == 0 &&
              mbedtls_mpi_size(&modulus) == kModulusSize &&
              mbedtls_mpi_write_binary(&modulus, modulus_be, sizeof(modulus_be)) == 0 &&
              mbedtls_mpi_write_binary(&exponent, exponent_be, sizeof(exponent_be)) == 0;
    if (ok) {
        // n0inv = -1 / n mod 2^32, but the low word of the modulus is all the
        // iteration needs. Five Newton steps double the correct bits from 1 to
        // 32.
        const uint32_t n0 = GetBe32(modulus_be + kModulusSize - sizeof(uint32_t));
        uint32_t inv = n0;
        for (int i = 0; i < 5; i++) {
            inv *= 2 - n0 * inv;
        }
        ok = static_cast<uint32_t>(n0 * inv) == 1 && ComputeRr(&modulus, rr_be);
        if (ok) {
            uint8_t blob[kAndroidKeySize];
            PutLe32(blob, kModulusSize / sizeof(uint32_t));
            PutLe32(blob + 4, 0u - inv);
            for (size_t i = 0; i < kModulusSize; i++) {
                blob[8 + i] = modulus_be[kModulusSize - 1 - i];
                blob[8 + kModulusSize + i] = rr_be[kModulusSize - 1 - i];
            }
            PutLe32(blob + 8 + 2 * kModulusSize, GetBe32(exponent_be));
            std::string encoded = Base64Encode(blob, sizeof(blob));
            ok = !encoded.empty();
            if (ok) {
                *out = encoded;
            }
        }
    }
    mbedtls_mpi_free(&modulus);
    mbedtls_mpi_free(&exponent);
    return ok;
}

}  // namespace

AdbIdentity& AdbIdentity::Get() {
    static AdbIdentity instance;
    return instance;
}

AdbIdentity::AdbIdentity() {
    mbedtls_pk_init(&private_key_);
    mbedtls_x509_crt_init(&certificate_);
}

AdbIdentity::~AdbIdentity() {
    mbedtls_pk_free(&private_key_);
    mbedtls_x509_crt_free(&certificate_);
}

bool AdbIdentity::EnsureReady() {
    if (ready_) {
        return true;
    }
    if (!Load()) {
        // A failed load can leave a half parsed context behind.
        mbedtls_pk_free(&private_key_);
        if (!Generate()) {
            return false;
        }
    }
    if (!BuildCertificate()) {
        mbedtls_pk_free(&private_key_);
        return false;
    }
    ready_ = true;
    return true;
}

bool AdbIdentity::Load() {
    Settings settings(kNamespace);
    const std::string encoded = settings.GetString(kPublicKeySetting);
    const std::string private_key = settings.GetString(kPrivateKeySetting);
    if (encoded.empty() || private_key.empty()) {
        return false;
    }
    std::vector<uint8_t> der;
    if (!Base64Decode(private_key, &der) || !ParsePrivateKey(der.data(), der.size())) {
        ESP_LOGE(kTag, "Stored ADB key is unusable, generating a new one");
        return false;
    }
    encoded_public_key_ = encoded + '\0';
    return true;
}

bool AdbIdentity::Generate() {
    ESP_LOGI(kTag, "Generating ADB RSA key pair");
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, kRsaBits);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));

    psa_status_t status = psa_crypto_init();
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    if (status == PSA_SUCCESS) {
        status = psa_generate_key(&attributes, &key);
    }
    if (status != PSA_SUCCESS) {
        ESP_LOGE(kTag, "Failed to generate ADB key: %ld", static_cast<long>(status));
        return false;
    }

    uint8_t private_der[kMaxPrivateKeyDer];
    size_t private_len = 0;
    uint8_t public_der[512];
    size_t public_len = 0;
    const psa_status_t private_status =
        psa_export_key(key, private_der, sizeof(private_der), &private_len);
    const psa_status_t public_status =
        psa_export_public_key(key, public_der, sizeof(public_der), &public_len);
    psa_destroy_key(key);
    if (private_status != PSA_SUCCESS || public_status != PSA_SUCCESS) {
        ESP_LOGE(kTag, "Failed to export the new ADB key");
        return false;
    }

    std::string encoded;
    if (!BuildAndroidPublicKey(public_der, public_len, &encoded)) {
        ESP_LOGE(kTag, "Failed to encode the new ADB public key");
        return false;
    }
    if (!ParsePrivateKey(private_der, private_len)) {
        return false;
    }

    Settings settings(kNamespace, true);
    if (!settings.SetString(kPrivateKeySetting, Base64Encode(private_der, private_len)) ||
        !settings.SetString(kPublicKeySetting, encoded)) {
        ESP_LOGE(kTag, "The ADB key is generated but cannot be saved, NVS is full");
        return false;
    }
    encoded_public_key_ = encoded + '\0';
    return true;
}

bool AdbIdentity::ParsePrivateKey(const uint8_t* der, size_t der_len) {
    const int ret = mbedtls_pk_parse_key(&private_key_, der, der_len, nullptr, 0);
    if (ret != 0) {
        ESP_LOGE(kTag, "Failed to parse ADB key: -0x%04x", static_cast<unsigned>(-ret));
        return false;
    }
    return true;
}

bool AdbIdentity::BuildCertificate() {
    mbedtls_x509write_cert writer;
    mbedtls_x509write_crt_init(&writer);
    mbedtls_x509write_crt_set_version(&writer, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&writer, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&writer, &private_key_);
    mbedtls_x509write_crt_set_issuer_key(&writer, &private_key_);

    // adbd never validates the chain or the dates, it only pins the key, so a
    // long lived self signed certificate with the right key is enough.
    uint8_t serial[16] = {0x01};
    esp_fill_random(serial + 1, sizeof(serial) - 1);
    std::vector<uint8_t> der(2048);
    int ret = mbedtls_x509write_crt_set_serial_raw(&writer, serial, sizeof(serial));
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_validity(&writer, "20200101000000", "20491231235959");
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_subject_name(&writer, "CN=xiaozhi-adb");
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_issuer_name(&writer, "CN=xiaozhi-adb");
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_der(&writer, der.data(), der.size());
    }
    mbedtls_x509write_crt_free(&writer);
    if (ret <= 0) {
        ESP_LOGE(kTag, "Failed to write ADB certificate: %d", ret);
        return false;
    }
    ret = mbedtls_x509_crt_parse_der(&certificate_, der.data() + der.size() - ret, ret);
    if (ret != 0) {
        ESP_LOGE(kTag, "Failed to parse ADB certificate: %d", ret);
        return false;
    }
    ESP_LOGI(kTag, "ADB certificate ready, %u bytes", static_cast<unsigned>(certificate_.raw.len));
    return true;
}

bool AdbIdentity::SignAuthToken(const uint8_t token[20], uint8_t signature[kSignatureSize]) {
    size_t sig_len = 0;
    const int ret = mbedtls_pk_sign(&private_key_, MBEDTLS_MD_SHA1, token, 20, signature,
                                    kSignatureSize, &sig_len);
    if (ret != 0 || sig_len != kSignatureSize) {
        ESP_LOGE(kTag, "Failed to sign ADB AUTH token: %d", ret);
        return false;
    }
    return true;
}
