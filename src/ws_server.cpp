#include "obscuraproto/ws_server.hpp"
#include "obscuraproto/handshake_messages.hpp"
#include "obscuraproto/errors.hpp"

#include <iostream>

namespace ObscuraProto {
namespace net {

constexpr uint16_t RESPONSE_OP_CODE = 0xFFFF;

WsServerWrapper::WsServerWrapper(KeyPair server_sign_key) : server_sign_key_(std::move(server_sign_key)) {
    server_.init_asio();
    server_.set_open_handler(std::bind(&WsServerWrapper::on_open, this, std::placeholders::_1));
    server_.set_close_handler(std::bind(&WsServerWrapper::on_close, this, std::placeholders::_1));
    server_.set_message_handler(std::bind(&WsServerWrapper::on_message, this, std::placeholders::_1, std::placeholders::_2));
    server_.clear_access_channels(websocketpp::log::alevel::all);
}

WsServerWrapper::~WsServerWrapper() {
    stop();
}

void WsServerWrapper::run(uint16_t port) {
    server_thread_ = std::make_unique<std::thread>([this, port]() {
        try {
            server_.listen(port);
            server_.start_accept();
            server_.run();
        } catch (const std::exception& e) {
            std::cerr << "Server thread exception: " << e.what() << std::endl;
        }
    });
}

void WsServerWrapper::stop() {
    if (server_.is_listening()) {
        server_.stop_listening();
    }

    // Fulfill any pending request promises with an exception
    {
        std::lock_guard<std::mutex> lock(pending_requests_mutex_);
        for (auto& pair : pending_requests_) {
            pair.second.set_exception(std::make_exception_ptr(RuntimeError("Server is stopping")));
        }
        pending_requests_.clear();
    }

    // Iterate over all connections and close them
    for (auto const& [hdl, session] : sessions_) {
        try {
            server_.close(hdl, websocketpp::close::status::going_away, "Server shutdown");
        } catch (const websocketpp::exception& e) {
            // Ignore exceptions on close
        }
    }
    sessions_.clear();

    if (server_thread_ && server_thread_->joinable()) {
        server_thread_->join();
    }
}

void WsServerWrapper::send(WsConnectionHdl hdl, const Payload& payload) {
    auto it = sessions_.find(hdl);
    if (it == sessions_.end() || !it->second.is_handshake_complete()) {
        throw LogicError("Session not ready for sending data.");
    }

    try {
        EncryptedPacket packet = it->second.encrypt_payload(payload);
        server_.send(hdl, packet.data(), packet.size(), BINDATA_OPCODE);
    } catch (const std::exception& e) {
        std::cerr << "Error sending packet: " << e.what() << std::endl;
    }
}

void WsServerWrapper::send_response(WsConnectionHdl hdl, uint32_t request_id, const Payload& payload) {
    PayloadBuilder response_builder(RESPONSE_OP_CODE);
    response_builder.add_param(request_id);
    response_builder.add_param(payload.serialize());
    
    send(hdl, response_builder.build());
}

std::future<Payload> WsServerWrapper::async_request(WsConnectionHdl hdl, const Payload& payload) {
    auto it = sessions_.find(hdl);
    if (it == sessions_.end() || !it->second.is_handshake_complete()) {
        throw LogicError("Session not ready for sending requests.");
    }

    uint32_t request_id = next_request_id_++;
    
    Payload request_payload;
    request_payload.op_code = payload.op_code;

    PayloadBuilder id_builder(0);
    id_builder.add_param(request_id);
    byte_vector id_param = id_builder.build().parameters;

    request_payload.parameters.reserve(id_param.size() + payload.parameters.size());
    request_payload.parameters.insert(request_payload.parameters.end(), id_param.begin(), id_param.end());
    request_payload.parameters.insert(request_payload.parameters.end(), payload.parameters.begin(), payload.parameters.end());

    auto promise = std::promise<Payload>();
    auto future = promise.get_future();

    {
        std::lock_guard<std::mutex> lock(pending_requests_mutex_);
        pending_requests_[request_id] = std::move(promise);
    }

    send(hdl, request_payload);

    return future;
}

void WsServerWrapper::set_on_payload_callback(OnPayloadCallback callback) {
    on_payload_callback_ = std::move(callback);
}

void WsServerWrapper::on_open(WsConnectionHdl hdl) {
    // A new connection is open, but we wait for the ClientHello to create a session.
}

void WsServerWrapper::on_close(WsConnectionHdl hdl) {
    sessions_.erase(hdl);
    // Note: We don't clean up pending requests for this specific connection here,
    // as it would require iterating the map. They will be fulfilled with an
    // exception when the server stops, or will eventually time out (if timeouts are implemented).
}

void WsServerWrapper::on_message(WsConnectionHdl hdl, WsMessagePtr msg) {
    if (msg->get_opcode() != BINDATA_OPCODE) {
        return; // Ignore non-binary messages
    }

    auto it = sessions_.find(hdl);

    if (it == sessions_.end()) { // New connection, expect ClientHello
        try {
            byte_vector data(msg->get_payload().begin(), msg->get_payload().end());
            ClientHello client_hello = ClientHello::deserialize(data);

            // Create a new session for this connection
            auto emplace_result = sessions_.emplace(hdl, Session(Role::SERVER, server_sign_key_));
            Session& new_session = emplace_result.first->second;

            ServerHello server_hello = new_session.server_respond_to_handshake(client_hello);
            byte_vector response = server_hello.serialize();
            server_.send(hdl, response.data(), response.size(), BINDATA_OPCODE);

        } catch (const std::exception& e) {
            std::cerr << "Handshake failed: " << e.what() << std::endl;
            server_.close(hdl, websocketpp::close::status::policy_violation, "Handshake error");
            sessions_.erase(hdl);
        }
    } else {
        Session& session = it->second;
        if (!session.is_handshake_complete()) {
            return;
        }
        try {
            byte_vector packet(msg->get_payload().begin(), msg->get_payload().end());
            Payload payload = session.decrypt_packet(packet);

            if (payload.op_code == RESPONSE_OP_CODE) {
                // This is a response from a client to a server-initiated request
                PayloadReader reader(payload);
                uint32_t request_id = reader.read_param_u32();
                byte_vector response_bytes = reader.read_param_bytes();
                Payload response_payload = Payload::deserialize(response_bytes);

                {
                    std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                    auto it = pending_requests_.find(request_id);
                    if (it != pending_requests_.end()) {
                        it->second.set_value(std::move(response_payload));
                        pending_requests_.erase(it);
                    } else {
                        std::cerr << "[SERVER] Received response for unknown request ID: " << request_id << std::endl;
                    }
                }
            } else {
                // This is a regular message or a request from the client
                if (on_payload_callback_) {
                    on_payload_callback_(hdl, std::move(payload));
                }
            }

        } catch (const std::exception& e) {
            std::cerr << "Decryption failed: " << e.what() << std::endl;
        }
    }
}

} // namespace net
} // namespace ObscuraProto
