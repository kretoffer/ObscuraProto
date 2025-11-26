#ifndef OBSCURAPROTO_WS_CLIENT_HPP
#define OBSCURAPROTO_WS_CLIENT_HPP

#include "ws_common.hpp"
#include "session.hpp"
#include <functional>
#include <thread>
#include <future>
#include <map>
#include <mutex>
#include <atomic>

namespace ObscuraProto {
namespace net {

class WsClientWrapper {
public:
    using OnReadyCallback = std::function<void()>;
    using OnPayloadCallback = std::function<void(Payload)>;
    using OnDisconnectCallback = std::function<void()>;

    WsClientWrapper(KeyPair server_sign_key);
    ~WsClientWrapper();

    void connect(const std::string& uri);
    void disconnect();
    void send(const Payload& payload);

    /**
     * @brief Sends a payload and returns a future for the response.
     * @param payload The payload to send. The op_code should indicate a request.
     * @return A future that will contain the response payload.
     */
    std::future<Payload> async_request(const Payload& payload);

    /**
     * @brief Sends a response to a specific server-initiated request.
     * @param request_id The ID of the request being responded to.
     * @param payload The response payload.
     */
    void send_response(uint32_t request_id, const Payload& payload);

    void set_on_ready_callback(OnReadyCallback callback);
    void set_on_payload_callback(OnPayloadCallback callback);
    void set_on_disconnect_callback(OnDisconnectCallback callback);

private:
    void on_open(WsConnectionHdl hdl);
    void on_close(WsConnectionHdl hdl);
    void on_fail(WsConnectionHdl hdl);
    void on_message(WsConnectionHdl hdl, WsClientMessagePtr msg);
    void run_client();

    WsClient client_;
    std::unique_ptr<Session> session_;
    WsConnectionHdl connection_hdl_;
    std::unique_ptr<std::thread> client_thread_;
    bool is_connected_ = false;

    OnReadyCallback on_ready_callback_;
    OnPayloadCallback on_payload_callback_;
    OnDisconnectCallback on_disconnect_callback_;

    // For request-response mechanism
    std::mutex pending_requests_mutex_;
    std::map<uint32_t, std::promise<Payload>> pending_requests_;
    std::atomic<uint32_t> next_request_id_{0};
};

} // namespace net
} // namespace ObscuraProto

#endif // OBSCURAPROTO_WS_CLIENT_HPP
