#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

#include "obscuraproto/crypto.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/ws_server.hpp"

// Shared state for synchronization
std::mutex mtx;
std::condition_variable cv;
bool client_ready = false;
bool server_received_message = false;
bool client_received_response = false;

void print_payload(const std::string& prefix, const ObscuraProto::Payload& payload) {
    std::cout << prefix << " OpCode: 0x" << std::hex << payload.op_code << std::dec << std::endl;

    try {
        ObscuraProto::PayloadReader reader(payload);
        if (payload.op_code == 0x1001) {
            std::cout << prefix << "  Username: " << reader.read_param<std::string>() << std::endl;
            std::cout << prefix << "  Password: " << reader.read_param<std::string>() << std::endl;
            std::cout << prefix << "  Login Attempts: " << reader.read_param<uint32_t>() << std::endl;
        } else if (payload.op_code == 0x2002) {
            std::cout << prefix << "  Message: " << reader.read_param<std::string>() << std::endl;
        } else {
            int i = 0;
            while (reader.has_more()) {
                // Fallback for unknown payloads
                auto bytes = reader.read_param<ObscuraProto::byte_vector>();
                std::cout << prefix << "  Param " << i++ << " (bytes): " << bytes.size() << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cout << prefix << "  Error reading params: " << e.what() << std::endl;
    }
}

int main() {
    // 1. Initialize the crypto library
    if (ObscuraProto::Crypto::init() != 0) {
        std::cerr << "Failed to initialize crypto library!" << std::endl;
        return 1;
    }

    std::cout << "Crypto library initialized." << std::endl;

    // 2. Setup server keys
    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    // 3. Start Server
    uint16_t port = 9002;
    ObscuraProto::net::WsServerWrapper server(server_long_term_key);
    // Use the default handler for incoming messages
    server.set_default_payload_handler([&server](auto hdl, ObscuraProto::Payload payload) {
        std::cout << "[SERVER] Received payload from client." << std::endl;
        print_payload("[SERVER]", payload);

        // Send a response
        ObscuraProto::Payload response_payload =
            ObscuraProto::PayloadBuilder(0x2002).add_param("Hello from server!").build();
        server.send(hdl, response_payload);

        std::lock_guard<std::mutex> lock(mtx);
        server_received_message = true;
        cv.notify_all();
    });

    server.run(port);
    std::cout << "[SERVER] Started on port " << port << std::endl;

    // Give the server a moment to start up
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 4. Start Client
    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_on_ready_callback([]() {
        std::cout << "[CLIENT] Handshake complete. Ready to send data." << std::endl;
        std::lock_guard<std::mutex> lock(mtx);
        client_ready = true;
        cv.notify_all();
    });

    // Use a specific handler for the server's response message
    client.register_op_handler(0x2002, [](ObscuraProto::Payload payload) {
        std::cout << "[CLIENT] Received payload from server." << std::endl;
        print_payload("[CLIENT]", payload);
        std::lock_guard<std::mutex> lock(mtx);
        client_received_response = true;
        cv.notify_all();
    });

    client.set_on_disconnect_callback([]() { std::cout << "[CLIENT] Disconnected from server." << std::endl; });

    client.connect("ws://localhost:" + std::to_string(port));
    std::cout << "[CLIENT] Connecting to server..." << std::endl;

    // 5. Wait for handshake to complete
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [] { return client_ready; });
    }

    // 6. Client sends a message
    std::cout << "\n[CLIENT] Sending a message..." << std::endl;
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001)
                                               .add_param("my_username")
                                               .add_param("my_password")
                                               .add_param((uint32_t) 3)
                                               .build();
    client.send(client_payload);

    // 7. Wait for server to receive and client to get response

    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [] { return server_received_message && client_received_response; });
    }

    std::cout << "\n[SYSTEM] Communication successful." << std::endl;

    // 8. Shutdown
    client.disconnect();
    server.stop();
    std::cout << "[SYSTEM] Shutdown complete." << std::endl;

    return 0;
}
