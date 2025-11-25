#ifndef OBSCURAPROTO_WS_SERVER_HPP
#define OBSCURAPROTO_WS_SERVER_HPP

#include "ws_common.hpp"
#include "session.hpp"
#include <map>
#include <functional>
#include <thread>

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

    void set_on_payload_callback(OnPayloadCallback callback);

private:
    void on_open(WsConnectionHdl hdl);
    void on_close(WsConnectionHdl hdl);
    void on_message(WsConnectionHdl hdl, WsMessagePtr msg);

    WsServer server_;
    KeyPair server_sign_key_;
    std::map<WsConnectionHdl, Session, std::owner_less<WsConnectionHdl>> sessions_;
    OnPayloadCallback on_payload_callback_;
    std::unique_ptr<std::thread> server_thread_;
};

} // namespace net
} // namespace ObscuraProto

#endif // OBSCURAPROTO_WS_SERVER_HPP
