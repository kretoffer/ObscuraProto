#ifndef OBSCURAPROTO_WS_COMMON_HPP
#define OBSCURAPROTO_WS_COMMON_HPP

#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <websocketpp/client.hpp>

namespace ObscuraProto {
namespace net {

    // Define types for convenience
    using WsServer = websocketpp::server<websocketpp::config::asio>;
    using WsClient = websocketpp::client<websocketpp::config::asio>;
    using WsConnectionHdl = websocketpp::connection_hdl;
    using WsMessagePtr = WsServer::message_ptr;
    using WsClientMessagePtr = WsClient::message_ptr;

    // Define a common binary message type for websocketpp
    const websocketpp::frame::opcode::value BINDATA_OPCODE = websocketpp::frame::opcode::binary;

} // namespace net
} // namespace ObscuraProto

#endif // OBSCURAPROTO_WS_COMMON_HPP
