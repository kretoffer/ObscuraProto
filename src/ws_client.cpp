#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/handshake_messages.hpp"
#include "obscuraproto/errors.hpp"

#include <iostream>

namespace ObscuraProto {
namespace net {

WsClientWrapper::WsClientWrapper(KeyPair server_sign_key) {
    session_ = std::make_unique<Session>(Role::CLIENT, std::move(server_sign_key));
    client_.init_asio();
    client_.set_open_handler(std::bind(&WsClientWrapper::on_open, this, std::placeholders::_1));
    client_.set_close_handler(std::bind(&WsClientWrapper::on_close, this, std::placeholders::_1));
    client_.set_fail_handler(std::bind(&WsClientWrapper::on_fail, this, std::placeholders::_1));
    client_.set_message_handler(std::bind(&WsClientWrapper::on_message, this, std::placeholders::_1, std::placeholders::_2));
    client_.clear_access_channels(websocketpp::log::alevel::all);
}

WsClientWrapper::~WsClientWrapper() {
    disconnect();
}

void WsClientWrapper::connect(const std::string& uri) {
    try {
        websocketpp::lib::error_code ec;
        WsClient::connection_ptr con = client_.get_connection(uri, ec);
        if (ec) {
            throw RuntimeError("Could not create connection: " + ec.message());
        }

        client_.connect(con);

        client_thread_ = std::make_unique<std::thread>(&WsClientWrapper::run_client, this);

    } catch (const std::exception& e) {
        std::cerr << "Connection failed: " << e.what() << std::endl;
    }
}

void WsClientWrapper::disconnect() {
    if (!is_connected_) return;
    
    try {
        client_.close(connection_hdl_, websocketpp::close::status::going_away, "Client disconnecting");
    } catch (const websocketpp::exception& e) {
        // Ignore exceptions on close
    }

    if (client_thread_ && client_thread_->joinable()) {
        client_thread_->join();
    }
    is_connected_ = false;
}

void WsClientWrapper::send(const Payload& payload) {
    if (!is_connected_ || !session_->is_handshake_complete()) {
        throw LogicError("Session not ready for sending data.");
    }

    try {
        EncryptedPacket packet = session_->encrypt_payload(payload);
        client_.send(connection_hdl_, packet.data(), packet.size(), BINDATA_OPCODE);
    } catch (const std::exception& e) {
        std::cerr << "Error sending packet: " << e.what() << std::endl;
    }
}

void WsClientWrapper::set_on_ready_callback(OnReadyCallback callback) {
    on_ready_callback_ = std::move(callback);
}

void WsClientWrapper::set_on_payload_callback(OnPayloadCallback callback) {
    on_payload_callback_ = std::move(callback);
}

void WsClientWrapper::set_on_disconnect_callback(OnDisconnectCallback callback) {
    on_disconnect_callback_ = std::move(callback);
}

void WsClientWrapper::on_open(WsConnectionHdl hdl) {
    connection_hdl_ = hdl;
    is_connected_ = true;

    // Start the ObscuraProto handshake
    try {
        ClientHello client_hello = session_->client_initiate_handshake();
        byte_vector request = client_hello.serialize();
        client_.send(hdl, request.data(), request.size(), BINDATA_OPCODE);
    } catch (const std::exception& e) {
        std::cerr << "Handshake initiation failed: " << e.what() << std::endl;
        disconnect();
    }
}

void WsClientWrapper::on_close(WsConnectionHdl hdl) {
    is_connected_ = false;
    if (on_disconnect_callback_) {
        on_disconnect_callback_();
    }
}

void WsClientWrapper::on_fail(WsConnectionHdl hdl) {
    is_connected_ = false;
    if (on_disconnect_callback_) {
        on_disconnect_callback_();
    }
}

void WsClientWrapper::on_message(WsConnectionHdl hdl, WsClientMessagePtr msg) {
    if (msg->get_opcode() != BINDATA_OPCODE) {
        return; // Ignore non-binary messages
    }

    try {
        if (!session_->is_handshake_complete()) {
            // Expecting ServerHello
            byte_vector data(msg->get_payload().begin(), msg->get_payload().end());
            ServerHello server_hello = ServerHello::deserialize(data);
            session_->client_finalize_handshake(server_hello);

            if (session_->is_handshake_complete() && on_ready_callback_) {
                on_ready_callback_();
            }
        } else {
            // Expecting encrypted data
            byte_vector packet(msg->get_payload().begin(), msg->get_payload().end());
            Payload payload = session_->decrypt_packet(packet);

            if (on_payload_callback_) {
                on_payload_callback_(std::move(payload));
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Message processing failed: " << e.what() << std::endl;
        disconnect();
    }
}

void WsClientWrapper::run_client() {
    try {
        client_.run();
    } catch (const std::exception& e) {
        std::cerr << "Client thread exception: " << e.what() << std::endl;
    }
}

} // namespace net
} // namespace ObscuraProto
