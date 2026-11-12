#ifndef MQTT_PROTOCOL_H
#define MQTT_PROTOCOL_H


#include "protocol.h"
#include <mqtt.h>
#include <udp.h>
#include <cJSON.h>
#include <psa/crypto.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/task.h>
#include <esp_timer.h>

#include <functional>
#include <string>
#include <map>
#include <mutex>
#include <memory>
#include <atomic>

#define MQTT_PING_INTERVAL_SECONDS 90
#define MQTT_RECONNECT_INTERVAL_MS 60000

#define UDP_KEEPALIVE_INTERVAL_MS 15000

#define MQTT_PROTOCOL_SERVER_HELLO_EVENT (1 << 0)

class MqttProtocol : public Protocol {
public:
    MqttProtocol();
    ~MqttProtocol();

    bool Start() override;
    bool SendAudio(std::unique_ptr<AudioStreamPacket> packet) override;
    bool OpenAudioChannel() override;
    void CloseAudioChannel(bool send_goodbye = true) override;
    bool IsAudioChannelOpened() const override;

private:
    // Alive flag for safe scheduled callbacks - set to false in destructor
    std::shared_ptr<std::atomic<bool>> alive_ = std::make_shared<std::atomic<bool>>(true);
    
    EventGroupHandle_t event_group_handle_;

    std::string publish_topic_;

    mutable std::mutex channel_mutex_;
    std::mutex crypto_mutex_;
    std::unique_ptr<Mqtt> mqtt_;
    // Shared so SendAudio() can hold a reference and call Send() without
    // holding channel_mutex_; the UDP receive callback (run on the modem's
    // AT event task) also needs that mutex, so holding it across a blocking
    // Send() would stall AT response parsing and cause spurious timeouts.
    std::shared_ptr<Udp> udp_;
    psa_key_id_t aes_key_id_ = PSA_KEY_ID_NULL;
    std::string aes_nonce_;
    std::string udp_server_;
    int udp_port_;
    uint32_t local_sequence_;
    uint32_t remote_sequence_;
    esp_timer_handle_t reconnect_timer_;

    // UDP keepalive：会话期间发空音频包防 NAT 丢包；ping 由同一任务顺带发送
    std::atomic<bool> udp_keepalive_enabled_{false};
    TaskHandle_t udp_keepalive_task_handle_ = nullptr;
    static void UdpKeepAliveEntry(void* arg);
    void UdpKeepAliveLoop();
    bool SendUdpKeepAlive();

    bool StartMqttClient(bool report_error=false);
    void ParseServerHello(const cJSON* root);
    bool DecodeHexString(const std::string& hex_string, std::string& decoded);
    bool CryptAesCtr(const uint8_t* input, size_t input_size, const uint8_t* nonce, uint8_t* output);

    bool SendText(const std::string& text) override;
    std::string GetHelloMessage();
};


#endif // MQTT_PROTOCOL_H
