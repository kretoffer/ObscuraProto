#include "obscuraproto/ws_server.hpp"

#include <iostream>

#include "obscuraproto/errors.hpp"
#include "obscuraproto/handshake_messages.hpp"

namespace ObscuraProto {
    namespace net {

        WsServerWrapper::WsServerWrapper(KeyPair server_sign_key) : server_sign_key_(std::move(server_sign_key)) {
            server_.init_asio();
            server_.set_open_handler(std::bind(&WsServerWrapper::on_open, this, std::placeholders::_1));
            server_.set_close_handler(std::bind(&WsServerWrapper::on_close, this, std::placeholders::_1));
            server_.set_message_handler(
                std::bind(&WsServerWrapper::on_message, this, std::placeholders::_1, std::placeholders::_2));
            server_.clear_access_channels(websocketpp::log::alevel::all);
            server_.set_close_handshake_timeout(100);
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
                for (auto& [conn_hdl, requests] : pending_requests_) {
                    for (auto& [id, promise] : requests) {
                        promise.set_exception(std::make_exception_ptr(RuntimeError("Server is stopping")));
                    }
                }
                pending_requests_.clear();
            }

            // Iterate over all authenticated connections and close them
            for (auto const& [hdl, session] : sessions_) {
                try {
                    server_.close(hdl, websocketpp::close::status::going_away, "Server shutdown");
                } catch (const websocketpp::exception& e) {
                    // Ignore exceptions on close
                }
            }
            sessions_.clear();

            // Iterate over all anonymous connections and close them
            for (auto const& [hdl, session] : anon_sessions_) {
                try {
                    server_.close(hdl, websocketpp::close::status::going_away, "Server shutdown");
                } catch (const websocketpp::exception& e) {
                    // Ignore exceptions on close
                }
            }
            anon_sessions_.clear();

            {
                std::lock_guard<std::mutex> lock(identity_map_mutex_);
                identity_to_hdl_.clear();
                hdl_to_identity_.clear();
            }

            if (server_thread_ && server_thread_->joinable()) {
                server_thread_->join();
            }
        }

        void WsServerWrapper::send(WsConnectionHdl hdl, const Payload& payload) {
            Session* session = nullptr;
            auto it = sessions_.find(hdl);
            if (it != sessions_.end() && it->second.is_handshake_complete()) {
                session = &it->second;
            } else {
                auto anon_it = anon_sessions_.find(hdl);
                if (anon_it != anon_sessions_.end() && anon_it->second.is_handshake_complete()) {
                    session = &anon_it->second;
                }
            }
            if (!session) {
                throw LogicError("Session not ready for sending data.");
            }

            try {
                EncryptedPacket packet = session->encrypt_payload(payload);
                server_.send(hdl, packet.data(), packet.size(), BINDATA_OPCODE);
            } catch (const std::exception& e) {
                std::cerr << "Error sending packet: " << e.what() << std::endl;
            }
        }

        void WsServerWrapper::send_response(WsConnectionHdl hdl, uint32_t request_id, const Payload& payload) {
            PayloadBuilder response_builder(OpCode::RESPONSE);
            response_builder.add_param(request_id);
            response_builder.add_param(payload.serialize());

            send(hdl, response_builder.build());
        }

        std::future<Payload> WsServerWrapper::async_request(WsConnectionHdl hdl, const Payload& payload) {
            Session* session = nullptr;
            auto it = sessions_.find(hdl);
            if (it != sessions_.end() && it->second.is_handshake_complete()) {
                session = &it->second;
            } else {
                auto anon_it = anon_sessions_.find(hdl);
                if (anon_it != anon_sessions_.end() && anon_it->second.is_handshake_complete()) {
                    session = &anon_it->second;
                }
            }
            if (!session) {
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
            request_payload.parameters.insert(
                request_payload.parameters.end(), payload.parameters.begin(), payload.parameters.end());

            auto promise = std::promise<Payload>();
            auto future = promise.get_future();

            {
                std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                pending_requests_[hdl][request_id] = std::move(promise);
            }

            send(hdl, request_payload);

            return future;
        }

        std::shared_ptr<Stream> WsServerWrapper::start_stream(WsConnectionHdl hdl) {
            uint32_t stream_id = next_outgoing_stream_id_ * 2 + 1;
            next_outgoing_stream_id_++;

            auto stream = std::make_shared<Stream>(stream_id, [this, hdl](const Payload& p) { send(hdl, p); });

            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                per_connection_streams_[hdl][stream_id] = stream;
            }

            PayloadBuilder builder(OpCode::STREAM_START);
            builder.add_param(stream_id);
            send(hdl, builder.build());

            return stream;
        }

        void WsServerWrapper::register_incoming_stream_handler(std::function<void(std::shared_ptr<Stream>)> callback) {
            incoming_stream_handler_ = std::move(callback);
        }

        void WsServerWrapper::register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            op_code_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::register_request_handler(Payload::OpCode op_code, OnRequestCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            request_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::set_default_payload_handler(OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            default_payload_handler_ = std::move(callback);
        }

        // legacy
        void WsServerWrapper::set_on_payload_callback(OnPayloadCallback callback) {
            set_default_payload_handler(std::move(callback));
        }

        void WsServerWrapper::on_open(WsConnectionHdl hdl) {
            // A new connection is open, but we wait for the ClientHello to create a session.
        }

        void WsServerWrapper::on_close(WsConnectionHdl hdl) {
            sessions_.erase(hdl);
            anon_sessions_.erase(hdl);

            {
                std::lock_guard<std::mutex> lock(identity_map_mutex_);
                auto it = hdl_to_identity_.find(hdl);
                if (it != hdl_to_identity_.end()) {
                    identity_to_hdl_.erase(it->second);
                    hdl_to_identity_.erase(it);
                }
            }

            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                per_connection_streams_.erase(hdl);
            }

            {
                std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                auto conn_it = pending_requests_.find(hdl);
                if (conn_it != pending_requests_.end()) {
                    for (auto& [id, promise] : conn_it->second) {
                        promise.set_exception(std::make_exception_ptr(RuntimeError("Client disconnected")));
                    }
                    pending_requests_.erase(conn_it);
                }
            }
        }

        // --- Anonymous Session Methods ---

        void WsServerWrapper::send_anonymous(WsConnectionHdl hdl, const Payload& payload) {
            auto it = anon_sessions_.find(hdl);
            if (it == anon_sessions_.end() || !it->second.is_handshake_complete()) {
                throw LogicError("Anonymous session not ready for sending data.");
            }

            try {
                EncryptedPacket packet = it->second.encrypt_payload(payload);
                server_.send(hdl, packet.data(), packet.size(), BINDATA_OPCODE);
            } catch (const std::exception& e) {
                std::cerr << "Error sending packet to anonymous session: " << e.what() << std::endl;
            }
        }

        void WsServerWrapper::register_anon_op_handler(Payload::OpCode op_code, OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(anon_op_handlers_mutex_);
            anon_op_code_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::register_anon_request_handler(Payload::OpCode op_code, OnRequestCallback callback) {
            std::lock_guard<std::mutex> lock(anon_op_handlers_mutex_);
            anon_request_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::set_anon_default_payload_handler(OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(anon_op_handlers_mutex_);
            anon_default_payload_handler_ = std::move(callback);
        }

        // --- Client Identity Methods ---

        void WsServerWrapper::set_client_identity_handler(IdentityHandler callback) {
            client_identity_handler_ = std::move(callback);
        }

        PublicKey WsServerWrapper::get_client_identity(WsConnectionHdl hdl) {
            auto it = sessions_.find(hdl);
            if (it == sessions_.end()) {
                throw LogicError("Session not found for this connection.");
            }
            auto identity = it->second.get_peer_identity();
            if (!identity.has_value()) {
                throw LogicError("Session has no peer identity.");
            }
            return *identity;
        }

        void WsServerWrapper::send_to_identity(const PublicKey& identity_pk, const Payload& payload) {
            std::lock_guard<std::mutex> lock(identity_map_mutex_);
            auto it = identity_to_hdl_.find(identity_pk);
            if (it == identity_to_hdl_.end()) {
                throw LogicError("Identity is not connected.");
            }
            send(it->second, payload);
        }

        std::future<Payload> WsServerWrapper::async_request_to_identity(const PublicKey& identity_pk,
                                                                        const Payload& payload) {
            std::lock_guard<std::mutex> lock(identity_map_mutex_);
            auto it = identity_to_hdl_.find(identity_pk);
            if (it == identity_to_hdl_.end()) {
                throw LogicError("Identity is not connected.");
            }
            return async_request(it->second, payload);
        }

        Payload WsServerWrapper::sync_request_to_identity(const PublicKey& identity_pk, const Payload& payload) {
            auto future_result = this->async_request_to_identity(identity_pk, payload);
            Payload result = future_result.get();
            return result;
        }

        // --- Message Dispatch ---

        static void dispatch_payload(
            WsConnectionHdl hdl,
            Payload& payload,
            WsServerWrapper& server,
            const std::map<Payload::OpCode, WsServerWrapper::OnRequestCallback>& request_handlers,
            const std::map<Payload::OpCode, WsServerWrapper::OnPayloadCallback>& op_code_handlers,
            const WsServerWrapper::OnPayloadCallback& default_handler,
            std::mutex& handlers_mutex,
            std::function<void(WsConnectionHdl, uint32_t, const Payload&)> send_response_fn) {
            bool handled = false;
            WsServerWrapper::OnRequestCallback request_handler;
            WsServerWrapper::OnPayloadCallback op_handler;
            WsServerWrapper::OnPayloadCallback default_h;

            {
                std::lock_guard<std::mutex> lock(handlers_mutex);
                auto req_it = request_handlers.find(payload.op_code);
                if (req_it != request_handlers.end()) {
                    request_handler = req_it->second;
                    handled = true;
                } else {
                    auto op_it = op_code_handlers.find(payload.op_code);
                    if (op_it != op_code_handlers.end()) {
                        op_handler = op_it->second;
                        handled = true;
                    } else {
                        default_h = default_handler;
                    }
                }
            }

            if (request_handler) {
                PayloadReader reader(payload);
                uint32_t request_id = reader.read_param<uint32_t>();
                Payload response_payload = request_handler(hdl, reader);
                send_response_fn(hdl, request_id, response_payload);
            } else if (op_handler) {
                op_handler(hdl, std::move(payload));
            } else if (default_h) {
                default_h(hdl, std::move(payload));
            }
        }

        void WsServerWrapper::on_message(WsConnectionHdl hdl, WsMessagePtr msg) {
            if (msg->get_opcode() != BINDATA_OPCODE) {
                return;  // Ignore non-binary messages
            }

            // Check if this is an existing authenticated session
            auto auth_it = sessions_.find(hdl);
            if (auth_it != sessions_.end()) {
                Session& session = auth_it->second;
                if (!session.is_handshake_complete()) {
                    return;
                }
                try {
                    byte_vector packet(msg->get_payload().begin(), msg->get_payload().end());
                    Payload payload = session.decrypt_packet(packet);

                    if (payload.op_code == OpCode::RESPONSE) {
                        // This is a response from a client to a server-initiated request
                        PayloadReader reader(payload);
                        uint32_t request_id = reader.read_param<uint32_t>();
                        byte_vector response_bytes = reader.read_param<byte_vector>();
                        Payload response_payload = Payload::deserialize(response_bytes);

                        {
                            std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                            auto conn_it = pending_requests_.find(hdl);
                            if (conn_it != pending_requests_.end()) {
                                auto req_it = conn_it->second.find(request_id);
                                if (req_it != conn_it->second.end()) {
                                    req_it->second.set_value(std::move(response_payload));
                                    conn_it->second.erase(req_it);
                                } else {
                                    std::cerr << "[SERVER] Received response for unknown request ID: " << request_id
                                              << std::endl;
                                }
                            } else {
                                std::cerr << "[SERVER] Received response for unknown connection" << std::endl;
                            }
                        }
                    } else if (payload.op_code == OpCode::STREAM_START || payload.op_code == OpCode::STREAM_DATA ||
                               payload.op_code == OpCode::STREAM_END || payload.op_code == OpCode::STREAM_CANCEL) {
                        PayloadReader reader(payload);
                        uint32_t stream_id = reader.read_param<uint32_t>();

                        switch (payload.op_code) {
                            case OpCode::STREAM_START: {
                                auto stream = std::make_shared<Stream>(stream_id,
                                                                       [this, hdl](const Payload& p) { send(hdl, p); });
                                {
                                    std::lock_guard<std::mutex> lock(streams_mutex_);
                                    per_connection_streams_[hdl][stream_id] = stream;
                                }
                                if (incoming_stream_handler_) {
                                    incoming_stream_handler_(std::move(stream));
                                }
                                break;
                            }
                            case OpCode::STREAM_DATA: {
                                byte_vector data = reader.read_param<byte_vector>();
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                auto conn_it = per_connection_streams_.find(hdl);
                                if (conn_it != per_connection_streams_.end()) {
                                    auto str_it = conn_it->second.find(stream_id);
                                    if (str_it != conn_it->second.end()) {
                                        str_it->second->dispatch_data(std::move(data));
                                    }
                                }
                                break;
                            }
                            case OpCode::STREAM_END: {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                auto conn_it = per_connection_streams_.find(hdl);
                                if (conn_it != per_connection_streams_.end()) {
                                    auto str_it = conn_it->second.find(stream_id);
                                    if (str_it != conn_it->second.end()) {
                                        str_it->second->dispatch_end();
                                    }
                                }
                                break;
                            }
                            case OpCode::STREAM_CANCEL: {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                auto conn_it = per_connection_streams_.find(hdl);
                                if (conn_it != per_connection_streams_.end()) {
                                    auto str_it = conn_it->second.find(stream_id);
                                    if (str_it != conn_it->second.end()) {
                                        str_it->second->dispatch_cancel();
                                        conn_it->second.erase(str_it);
                                    }
                                }
                                break;
                            }
                        }

                    } else {
                        // Regular message or request from authenticated client
                        dispatch_payload(
                            hdl,
                            payload,
                            *this,
                            request_handlers_,
                            op_code_handlers_,
                            default_payload_handler_,
                            op_handlers_mutex_,
                            [this](WsConnectionHdl h, uint32_t rid, const Payload& p) { send_response(h, rid, p); });
                    }

                } catch (const std::exception& e) {
                    std::cerr << "Decryption failed for authenticated session: " << e.what() << std::endl;
                }
                return;
            }

            // Check if this is an existing anonymous session
            auto anon_it = anon_sessions_.find(hdl);
            if (anon_it != anon_sessions_.end()) {
                Session& session = anon_it->second;
                if (!session.is_handshake_complete()) {
                    return;
                }
                try {
                    byte_vector packet(msg->get_payload().begin(), msg->get_payload().end());
                    Payload payload = session.decrypt_packet(packet);

                    if (payload.op_code == OpCode::RESPONSE) {
                        // This is a response from an anonymous client to a server-initiated request
                        PayloadReader reader(payload);
                        uint32_t request_id = reader.read_param<uint32_t>();
                        byte_vector response_bytes = reader.read_param<byte_vector>();
                        Payload response_payload = Payload::deserialize(response_bytes);

                        {
                            std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                            auto conn_it = pending_requests_.find(hdl);
                            if (conn_it != pending_requests_.end()) {
                                auto req_it = conn_it->second.find(request_id);
                                if (req_it != conn_it->second.end()) {
                                    req_it->second.set_value(std::move(response_payload));
                                    conn_it->second.erase(req_it);
                                } else {
                                    std::cerr
                                        << "[SERVER] Received anonymous response for unknown request ID: " << request_id
                                        << std::endl;
                                }
                            } else {
                                std::cerr << "[SERVER] Received anonymous response for unknown connection" << std::endl;
                            }
                        }
                    } else if (payload.op_code == OpCode::STREAM_START || payload.op_code == OpCode::STREAM_DATA ||
                               payload.op_code == OpCode::STREAM_END || payload.op_code == OpCode::STREAM_CANCEL) {
                        PayloadReader reader(payload);
                        uint32_t stream_id = reader.read_param<uint32_t>();

                        switch (payload.op_code) {
                            case OpCode::STREAM_START: {
                                auto stream = std::make_shared<Stream>(
                                    stream_id, [this, hdl](const Payload& p) { send_anonymous(hdl, p); });
                                {
                                    std::lock_guard<std::mutex> lock(streams_mutex_);
                                    per_connection_streams_[hdl][stream_id] = stream;
                                }
                                if (incoming_stream_handler_) {
                                    incoming_stream_handler_(std::move(stream));
                                }
                                break;
                            }
                            case OpCode::STREAM_DATA: {
                                byte_vector data = reader.read_param<byte_vector>();
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                auto conn_it = per_connection_streams_.find(hdl);
                                if (conn_it != per_connection_streams_.end()) {
                                    auto str_it = conn_it->second.find(stream_id);
                                    if (str_it != conn_it->second.end()) {
                                        str_it->second->dispatch_data(std::move(data));
                                    }
                                }
                                break;
                            }
                            case OpCode::STREAM_END: {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                auto conn_it = per_connection_streams_.find(hdl);
                                if (conn_it != per_connection_streams_.end()) {
                                    auto str_it = conn_it->second.find(stream_id);
                                    if (str_it != conn_it->second.end()) {
                                        str_it->second->dispatch_end();
                                    }
                                }
                                break;
                            }
                            case OpCode::STREAM_CANCEL: {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                auto conn_it = per_connection_streams_.find(hdl);
                                if (conn_it != per_connection_streams_.end()) {
                                    auto str_it = conn_it->second.find(stream_id);
                                    if (str_it != conn_it->second.end()) {
                                        str_it->second->dispatch_cancel();
                                        conn_it->second.erase(str_it);
                                    }
                                }
                                break;
                            }
                        }

                    } else {
                        dispatch_payload(hdl,
                                         payload,
                                         *this,
                                         anon_request_handlers_,
                                         anon_op_code_handlers_,
                                         anon_default_payload_handler_,
                                         anon_op_handlers_mutex_,
                                         [this](WsConnectionHdl h, uint32_t rid, const Payload& p) {
                                             PayloadBuilder response_builder(OpCode::RESPONSE);
                                             response_builder.add_param(rid);
                                             response_builder.add_param(p.serialize());
                                             send_anonymous(h, response_builder.build());
                                         });
                    }

                } catch (const std::exception& e) {
                    std::cerr << "Decryption failed for anonymous session: " << e.what() << std::endl;
                }
                return;
            }

            // --- New connection, expect ClientHello ---
            try {
                byte_vector data(msg->get_payload().begin(), msg->get_payload().end());
                ClientHello client_hello = ClientHello::deserialize(data);

                // Determine whether to create an authenticated or anonymous session
                bool is_identified = client_hello.has_client_identity;

                // Create a temporary session to process the handshake
                Session temp_session(Role::SERVER, server_sign_key_);
                ServerHello server_hello = temp_session.server_respond_to_handshake(client_hello);
                byte_vector response = server_hello.serialize();
                server_.send(hdl, response.data(), response.size(), BINDATA_OPCODE);

                if (is_identified && temp_session.has_peer_identity()) {
                    // Client provided valid identity - check with application handler
                    PublicKey client_pk = *temp_session.get_peer_identity();

                    bool accepted = true;
                    if (client_identity_handler_) {
                        accepted = client_identity_handler_(hdl, client_pk);
                    }

                    if (accepted) {
                        // Move the session to the authenticated map
                        auto emplace_result = sessions_.emplace(hdl, std::move(temp_session));
                        {
                            std::lock_guard<std::mutex> lock(identity_map_mutex_);
                            identity_to_hdl_[client_pk] = hdl;
                            hdl_to_identity_[hdl] = client_pk;
                        }
                    } else {
                        // Rejected by application handler
                        server_.close(hdl, websocketpp::close::status::policy_violation, "Identity rejected");
                    }
                } else {
                    // Anonymous session
                    anon_sessions_.emplace(hdl, std::move(temp_session));
                }

            } catch (const std::exception& e) {
                std::cerr << "Handshake failed: " << e.what() << std::endl;
                server_.close(hdl, websocketpp::close::status::policy_violation, "Handshake error");
            }
        }

        Payload WsServerWrapper::sync_request(WsConnectionHdl hdl, const Payload& payload) {
            auto future_result = this->async_request(hdl, payload);
            Payload result = future_result.get();
            return result;
        }

    }  // namespace net
}  // namespace ObscuraProto
