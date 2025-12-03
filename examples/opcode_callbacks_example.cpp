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
int server_messages_received = 0;
const int TOTAL_MESSAGES_TO_RECEIVE = 3;

// Opcodes for our example
constexpr uint16_t OP_GET_STATUS = 0x5001;
constexpr uint16_t OP_ECHO = 0x5002;
constexpr uint16_t OP_UNHANDLED = 0x5003;

int main() {
    if (ObscuraProto::Crypto::init() != 0) {
        std::cerr << "Failed to initialize crypto library!" << std::endl;
        return 1;
    }
    std::cout << "Crypto library initialized." << std::endl;

    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    // 3. Start Server and register handlers
    uint16_t port = 9004;
    ObscuraProto::net::WsServerWrapper server(server_long_term_key);

    // Register a handler for OP_GET_STATUS
    server.register_op_handler(OP_GET_STATUS, [&](auto hdl, ObscuraProto::Payload payload) {
        std::cout << "[SERVER] Handler for OP_GET_STATUS called." << std::endl;
        ObscuraProto::Payload response = ObscuraProto::PayloadBuilder(0x6001).add_param("Server is OK").build();
        server.send(hdl, response);
        {
            std::lock_guard<std::mutex> lock(mtx);
            server_messages_received++;
            cv.notify_all();
        }
    });

    // Register a handler for OP_ECHO
    server.register_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        std::cout << "[SERVER] Handler for OP_ECHO called." << std::endl;
        // Just echo the same payload back
        server.send(hdl, payload);
        {
            std::lock_guard<std::mutex> lock(mtx);
            server_messages_received++;
            cv.notify_all();
        }
    });

    // Set a default handler for anything else
    server.set_default_payload_handler([&](auto hdl, ObscuraProto::Payload payload) {
        std::cout << "[SERVER] Default handler called for OpCode 0x" << std::hex << payload.op_code << std::dec
                  << std::endl;
        {
            std::lock_guard<std::mutex> lock(mtx);
            server_messages_received++;
            cv.notify_all();
        }
    });

    server.run(port);
    std::cout << "[SERVER] Started on port " << port << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 4. Start Client
    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_on_ready_callback([]() {
        std::cout << "[CLIENT] Handshake complete." << std::endl;
        std::lock_guard<std::mutex> lock(mtx);
        client_ready = true;
        cv.notify_all();
    });

    client.set_default_payload_handler([](ObscuraProto::Payload payload) {
        std::cout << "[CLIENT] Received message from server (OpCode 0x" << std::hex << payload.op_code << std::dec
                  << ")" << std::endl;
    });

    client.connect("ws://localhost:" + std::to_string(port));
    std::cout << "[CLIENT] Connecting to server..." << std::endl;

    // 5. Wait for handshake
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [] { return client_ready; });
    }

    // 6. Client sends messages
    std::cout << "\n[CLIENT] Sending OP_GET_STATUS..." << std::endl;
    client.send(ObscuraProto::PayloadBuilder(OP_GET_STATUS).build());
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::cout << "[CLIENT] Sending OP_ECHO..." << std::endl;
    client.send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param("echo this!").build());
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::cout << "[CLIENT] Sending OP_UNHANDLED..." << std::endl;
    client.send(ObscuraProto::PayloadBuilder(OP_UNHANDLED).build());

    // 7. Wait for server to process all messages
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [] { return server_messages_received >= TOTAL_MESSAGES_TO_RECEIVE; });
    }

    std::cout << "\n[SYSTEM] All messages processed by server." << std::endl;

    // 8. Shutdown
    client.disconnect();
    server.stop();
    std::cout << "[SYSTEM] Shutdown complete." << std::endl;

    return 0;
}
