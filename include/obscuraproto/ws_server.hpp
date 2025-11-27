#ifndef OBSCURAPROTO_WS_SERVER_HPP
#define OBSCURAPROTO_WS_SERVER_HPP

#include "ws_common.hpp"
#include "session.hpp"
#include <map>
#include <functional>
#include <thread>
#include <future>
#include <mutex>
#include <atomic>

namespace ObscuraProto {
namespace net {

class WsServerWrapper {
public:
    using OnPayloadCallback = std::function<void(WsConnectionHdl, Payload)>;

    WsServerWrapper(KeyPair server_sign_key);
    ~WsServerWrapper();

    void run(uint16_t port);
    void stop();
    void send(WsConnectionHdl hdl, const Payload& payload);

    /**
     * @brief Sends a response to a specific request.
     * @param hdl The connection handle of the client.
     * @param request_id The ID of the request being responded to.
     * @param payload The response payload.
     */
    void send_response(WsConnectionHdl hdl, uint32_t request_id, const Payload& payload);

    /**
     * @brief Sends a request to a client and returns a future for the response.
     * @param hdl The connection handle of the client.
     * @param payload The payload to send as a request.
     * @return A future that will contain the response payload.
     */
    std::future<Payload> async_request(WsConnectionHdl hdl, const Payload& payload);

    /**
     * @brief Registers a handler for a specific operation code.
     * @param op_code The operation code to handle.
     * @param callback The function to call when a payload with this op_code is received.
     */
    void register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback);

    /**
     * @brief Sets a default handler for any operation code that doesn't have a specific handler registered.
     * @param callback The function to call.
     */
    void set_default_payload_handler(OnPayloadCallback callback);

    /**
     * @brief DEPRECATED: Sets the default payload handler. Use set_default_payload_handler for clarity.
     */
    void set_on_payload_callback(OnPayloadCallback callback);

private:
    void on_open(WsConnectionHdl hdl);
    void on_close(WsConnectionHdl hdl);
    void on_message(WsConnectionHdl hdl, WsMessagePtr msg);

    WsServer server_;
    KeyPair server_sign_key_;
    std::map<WsConnectionHdl, Session, std::owner_less<WsConnectionHdl>> sessions_;
    
    std::mutex op_handlers_mutex_;
    std::map<Payload::OpCode, OnPayloadCallback> op_code_handlers_;
    OnPayloadCallback default_payload_handler_;
    
    std::unique_ptr<std::thread> server_thread_;

    // For request-response mechanism (server-to-client)
    std::mutex pending_requests_mutex_;
    std::map<uint32_t, std::promise<Payload>> pending_requests_;
    std::atomic<uint32_t> next_request_id_{0};
};

} // namespace net
} // namespace ObscuraProto

#endif // OBSCURAPROTO_WS_SERVER_HPP
