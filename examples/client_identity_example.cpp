#include <chrono>
#include <iostream>
#include <thread>

#include "obscuraproto/crypto.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/ws_server.hpp"

constexpr uint16_t OP_REGISTER_KEY = 0x7001;
constexpr uint16_t OP_GREETING = 0x7003;

int main() {
    if (ObscuraProto::Crypto::init() != 0) {
        std::cerr << "Failed to initialize crypto library!" << std::endl;
        return 1;
    }
    std::cout << "Crypto library initialized." << std::endl;

    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    auto client_device_key = ObscuraProto::Crypto::generate_sign_keypair();

    uint16_t port = 9005;

    // ---- Server ----
    ObscuraProto::net::WsServerWrapper server(server_long_term_key);

    ObscuraProto::PublicKey registered_key;

    server.register_anon_request_handler(
        OP_REGISTER_KEY, [&](auto hdl, ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
            std::cout << "[SERVER] Anonymous client wants to register a key." << std::endl;
            auto pk_bytes = reader.read_param<ObscuraProto::byte_vector>();
            ObscuraProto::PublicKey new_key{pk_bytes};

            if (new_key.data.size() < 6) {
                return ObscuraProto::PayloadBuilder(OP_REGISTER_KEY).add_param(false).build();
            }

            registered_key = new_key;
            std::cout << "[SERVER] Key registered successfully." << std::endl;
            return ObscuraProto::PayloadBuilder(OP_REGISTER_KEY).add_param(true).build();
        });

    server.set_client_identity_handler([&](auto hdl, ObscuraProto::PublicKey pk) -> bool {
        bool accepted = registered_key.data.size() > 0 && pk.data == registered_key.data;
        std::cout << "[SERVER] Client identity check: " << (accepted ? "ACCEPTED" : "REJECTED") << std::endl;
        return accepted;
    });

    server.register_op_handler(OP_GREETING, [&](auto hdl, ObscuraProto::Payload payload) {
        auto client_pk = server.get_client_identity(hdl);
        std::cout << "[SERVER] Authenticated client sent a greeting." << std::endl;
        server.send_to_identity(
            client_pk,
            ObscuraProto::PayloadBuilder(OP_GREETING).add_param(std::string("Hello, authenticated client!")).build());
    });

    server.run(port);
    std::cout << "[SERVER] Started on port " << port << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // ---- Phase 1: Anonymous Registration ----
    std::cout << "\n--- Phase 1: Anonymous Registration ---" << std::endl;

    ObscuraProto::net::WsClientWrapper anon_client(client_view_of_server_key);

    std::promise<void> anon_ready;
    anon_client.set_on_ready_callback([&]() { anon_ready.set_value(); });

    anon_client.connect("ws://localhost:" + std::to_string(port));

    if (anon_ready.get_future().wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
        std::cerr << "[ANON] Handshake timed out." << std::endl;
        server.stop();
        return 1;
    }
    std::cout << "[ANON] Handshake complete. Sending registration request..." << std::endl;

    auto reg_response = anon_client.sync_request(
        ObscuraProto::PayloadBuilder(OP_REGISTER_KEY).add_param(client_device_key.publicKey.data).build());

    ObscuraProto::PayloadReader r(reg_response);
    bool success = r.read_param<bool>();
    std::cout << "[ANON] Registration " << (success ? "succeeded" : "failed") << std::endl;

    anon_client.disconnect();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // ---- Phase 2: Authenticated Connection ----
    std::cout << "\n--- Phase 2: Authenticated Connection ---" << std::endl;

    ObscuraProto::net::WsClientWrapper auth_client(client_view_of_server_key);
    auth_client.set_client_identity(client_device_key);

    std::promise<void> auth_ready;
    std::promise<void> auth_greeted;

    auth_client.set_on_ready_callback([&]() {
        std::cout << "[AUTH] Handshake complete. Sending greeting..." << std::endl;
        auth_client.send(ObscuraProto::PayloadBuilder(OP_GREETING).build());
    });

    auth_client.register_op_handler(OP_GREETING, [&](ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader reader(payload);
        std::cout << "[AUTH] Received: " << reader.read_param<std::string>() << std::endl;
        auth_greeted.set_value();
    });

    auth_client.connect("ws://localhost:" + std::to_string(port));

    if (auth_greeted.get_future().wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
        std::cerr << "[AUTH] Timed out." << std::endl;
    } else {
        std::cout << "[AUTH] Successfully authenticated and received greeting." << std::endl;
    }

    auth_client.disconnect();
    server.stop();

    std::cout << "\n[SYSTEM] Client identity example completed." << std::endl;
    return 0;
}
