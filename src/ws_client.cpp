#include "obscuraproto/ws_client.hpp"

#include <iostream>

#include "obscuraproto/errors.hpp"
#include "obscuraproto/handshake_messages.hpp"

namespace ObscuraProto {
    namespace net {

        constexpr uint16_t RESPONSE_OP_CODE = 0xFFFF;

        WsClientWrapper::WsClientWrapper(KeyPair server_sign_key) {
            session_ = std::make_unique<Session>(Role::CLIENT, std::move(server_sign_key));
            client_.init_asio();
            client_.set_open_handler(std::bind(&WsClientWrapper::on_open, this, std::placeholders::_1));
            client_.set_close_handler(std::bind(&WsClientWrapper::on_close, this, std::placeholders::_1));
            client_.set_fail_handler(std::bind(&WsClientWrapper::on_fail, this, std::placeholders::_1));
            client_.set_message_handler(
                std::bind(&WsClientWrapper::on_message, this, std::placeholders::_1, std::placeholders::_2));
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
            // If the client thread doesn't exist, we have nothing to do.
            if (!client_thread_) {
                return;
            }

            // Stop the ASIO io_service processing loop.
            // This will cause client_.run() to return.
            client_.stop();

            // Fulfill any pending request promises with an exception
            {
                std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                for (auto& pair : pending_requests_) {
                    pair.second.set_exception(std::make_exception_ptr(RuntimeError("Client disconnected")));
                }
                pending_requests_.clear();
            }

            // If the connection is open, request a clean close.
            if (is_connected_) {
                try {
                    websocketpp::lib::error_code ec;
                    client_.close(connection_hdl_, websocketpp::close::status::going_away, "", ec);
                    if (ec) {
                        // This can happen if the connection is already closing, which is fine.
                    }
                } catch (const websocketpp::exception& e) {
                    // Ignore exceptions on close
                }
            }

            // Wait for the thread to finish.
            if (client_thread_->joinable()) {
                client_thread_->join();
            }

            client_thread_.reset();
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

        std::future<Payload> WsClientWrapper::async_request(const Payload& payload) {
            if (!is_connected_ || !session_->is_handshake_complete()) {
                throw LogicError("Session not ready for sending requests.");
            }

            uint32_t request_id = next_request_id_++;

            // Manually prepend the request ID to the payload parameters
            Payload request_payload;
            request_payload.op_code = payload.op_code;

            PayloadBuilder id_builder(0);  // op_code doesn't matter here
            id_builder.add_param(request_id);
            byte_vector id_param = id_builder.build().parameters;

            request_payload.parameters.reserve(id_param.size() + payload.parameters.size());
            request_payload.parameters.insert(request_payload.parameters.end(), id_param.begin(), id_param.end());
            request_payload.parameters.insert(
                request_payload.parameters.end(), payload.parameters.begin(), payload.parameters.end());

            auto promise = std::promise<Payload>();
            auto future = promise.get_future();

            {
                std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                pending_requests_[request_id] = std::move(promise);
            }

            send(request_payload);

            return future;
        }

        void WsClientWrapper::send_response(uint32_t request_id, const Payload& payload) {
            PayloadBuilder response_builder(RESPONSE_OP_CODE);
            response_builder.add_param(request_id);
            response_builder.add_param(payload.serialize());

            send(response_builder.build());
        }

        void WsClientWrapper::set_on_ready_callback(OnReadyCallback callback) {
            on_ready_callback_ = std::move(callback);
        }

        void WsClientWrapper::register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            op_code_handlers_[op_code] = std::move(callback);
        }

        void WsClientWrapper::register_request_handler(Payload::OpCode op_code, OnRequestCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            request_handlers_[op_code] = std::move(callback);
        }

        void WsClientWrapper::set_default_payload_handler(OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            default_payload_handler_ = std::move(callback);
        }

        // legacy
        void WsClientWrapper::set_on_payload_callback(OnPayloadCallback callback) {
            set_default_payload_handler(std::move(callback));
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
                return;  // Ignore non-binary messages
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

                    if (payload.op_code == RESPONSE_OP_CODE) {
                        // This is a response to a request
                        PayloadReader reader(payload);
                        uint32_t request_id = reader.read_param<uint32_t>();
                        byte_vector response_bytes = reader.read_param<byte_vector>();
                        Payload response_payload = Payload::deserialize(response_bytes);

                        {
                            std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                            auto it = pending_requests_.find(request_id);
                            if (it != pending_requests_.end()) {
                                it->second.set_value(std::move(response_payload));
                                pending_requests_.erase(it);
                            } else {
                                std::cerr
                                    << "Received response for unknown or already handled request ID: " << request_id
                                    << std::endl;
                            }
                        }

                    } else {
                        // This is a regular push message or a request from the server
                        bool handled = false;
                        OnRequestCallback request_handler;
                        OnPayloadCallback op_handler;
                        OnPayloadCallback default_handler;

                        {
                            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
                            auto req_it = request_handlers_.find(payload.op_code);
                            if (req_it != request_handlers_.end()) {
                                request_handler = req_it->second;
                                handled = true;
                            } else {
                                auto op_it = op_code_handlers_.find(payload.op_code);
                                if (op_it != op_code_handlers_.end()) {
                                    op_handler = op_it->second;
                                    handled = true;
                                } else {
                                    default_handler = default_payload_handler_;
                                }
                            }
                        }

                        if (request_handler) {
                            PayloadReader reader(payload);
                            uint32_t request_id = reader.read_param<uint32_t>();
                            Payload response_payload = request_handler(reader);
                            send_response(request_id, response_payload);
                        } else if (op_handler) {
                            op_handler(std::move(payload));
                        } else if (default_handler) {
                            default_handler(std::move(payload));
                        }
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

    }  // namespace net
}  // namespace ObscuraProto
