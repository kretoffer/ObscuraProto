#include "obscuraproto/ws_server.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/crypto.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <future>

// This example demonstrates the BI-DIRECTIONAL request-response pattern using the simplified API.
// 1. The client connects and sends a request to the server.
// 2. The server receives the request, sends a response, and then immediately sends its own request to the client.
// 3. The client receives the server's response and fulfills the first future.
// 4. The client also receives the server's request and sends a response back.
// 5. The server receives the client's response and fulfills the second future.

constexpr uint16_t OP_C2S_ECHO_REQUEST = 0x3001;
constexpr uint16_t OP_C2S_ECHO_RESPONSE = 0x3002;
constexpr uint16_t OP_S2C_TIME_REQUEST = 0x4001;
constexpr uint16_t OP_S2C_TIME_RESPONSE = 0x4002;

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

    std::promise<void> server_request_done_promise;
    std::future<void> server_request_done_future = server_request_done_promise.get_future();

    // 3. Start Server
    uint16_t port = 9003;
    ObscuraProto::net::WsServerWrapper server(server_long_term_key);

    // Register a handler for the client's echo request using the new simplified API
    server.register_request_handler(OP_C2S_ECHO_REQUEST, 
        [&](auto hdl, ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
            
            std::cout << "[SERVER] Received client's echo request." << std::endl;
            std::string message = reader.read_param_string();

            // To avoid blocking the network thread, run the server-initiated request in a new thread.
            std::thread([&, hdl, done_promise = &server_request_done_promise]() {
                // Now, server initiates its own request to the client
                std::cout << "\n[SERVER] Sending time request to client..." << std::endl;
                ObscuraProto::Payload time_request = ObscuraProto::PayloadBuilder(OP_S2C_TIME_REQUEST).build();
                auto server_future = server.async_request(hdl, time_request);

                if(server_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready) {
                    try {
                        auto client_response = server_future.get();
                        if (client_response.op_code == OP_S2C_TIME_RESPONSE) {
                            ObscuraProto::PayloadReader reader(client_response);
                            std::cout << "[SERVER] Received response from client: " << reader.read_param_string() << std::endl;
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "[SERVER] Exception getting client response: " << e.what() << std::endl;
                    }
                } else {
                    std::cerr << "[SERVER] Timed out waiting for client response." << std::endl;
                }
                done_promise->set_value();
            }).detach(); // Detach the thread to let it run independently.

            // Simply return the response payload. The library handles sending it.
            std::cout << "[SERVER] Sent response to client." << std::endl;
            return ObscuraProto::PayloadBuilder(OP_C2S_ECHO_RESPONSE)
                .add_param("Echoing back: " + message)
                .build();
        }
    );

    server.run(port);
    std::cout << "[SERVER] Started on port " << port << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 4. Start Client
    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    
    std::promise<void> ready_promise;
    std::future<void> ready_future = ready_promise.get_future();

    client.set_on_ready_callback([&]() {
        std::cout << "[CLIENT] Handshake complete. Ready to send requests." << std::endl;
        ready_promise.set_value();
    });

    // Register a handler for the server's time request using the new simplified API
    client.register_request_handler(OP_S2C_TIME_REQUEST, 
        [&](ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
            std::cout << "[CLIENT] Received time request from server." << std::endl;
            
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::string time_str = std::ctime(&time_t);
            time_str.pop_back(); // remove newline

            std::cout << "[CLIENT] Sending time response to server..." << std::endl;
            return ObscuraProto::PayloadBuilder(OP_S2C_TIME_RESPONSE)
                .add_param("The time is: " + time_str)
                .build();
        }
    );

    client.connect("ws://localhost:" + std::to_string(port));
    std::cout << "[CLIENT] Connecting to server..." << std::endl;

    // 5. Wait for handshake to complete
    if (ready_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
        std::cerr << "[CLIENT] Handshake timed out." << std::endl;
        server.stop();
        return 1;
    }

    // 6. Client sends a request and waits for the response
    std::cout << "\n[CLIENT] Sending an echo request..." << std::endl;
    ObscuraProto::Payload request_payload = ObscuraProto::PayloadBuilder(OP_C2S_ECHO_REQUEST)
        .add_param("Hello, world!")
        .build();
    
    auto response_future = client.async_request(request_payload);

    std::cout << "[CLIENT] Waiting for response from server..." << std::endl;
    if (response_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready) {
        try {
            ObscuraProto::Payload response = response_future.get();
            std::cout << "[CLIENT] Received response from server!" << std::endl;
            if (response.op_code == OP_C2S_ECHO_RESPONSE) {
                ObscuraProto::PayloadReader reader(response);
                std::cout << "[CLIENT]   Server response: \"" << reader.read_param_string() << "\"" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[CLIENT] Exception while getting response: " << e.what() << std::endl;
        }
    } else {
        std::cerr << "[CLIENT] Timed out waiting for server response." << std::endl;
    }

    // 7. Wait for server to finish its flow
    std::cout << "\n[SYSTEM] Waiting for server to finish its request to the client..." << std::endl;
    if(server_request_done_future.wait_for(std::chrono::seconds(10)) != std::future_status::ready) {
        std::cerr << "[SYSTEM] Timed out waiting for server flow to complete." << std::endl;
    }

    // 8. Shutdown
    std::cout << "\n[SYSTEM] Shutdown." << std::endl;
    client.disconnect();
    server.stop();

    return 0;
}
