#include <chrono>
#include <iostream>
#include <thread>

#include "obscuraproto/crypto.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/ws_server.hpp"

// This example demonstrates the bidirectional streaming API.
// 1. Server registers a handler for incoming streams.
// 2. Client connects and starts a stream.
// 3. Client sends data chunks, server receives them and writes back.
// 4. Client ends the stream, server ends as well.

int main() {
    if (ObscuraProto::Crypto::init() != 0) {
        std::cerr << "Failed to initialize crypto library!" << std::endl;
        return 1;
    }
    std::cout << "Crypto library initialized." << std::endl;

    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    uint16_t port = 9004;

    // ---- Server ----
    ObscuraProto::net::WsServerWrapper server(server_long_term_key);

    server.register_incoming_stream_handler([](std::shared_ptr<ObscuraProto::Stream> stream) {
        std::cout << "[SERVER] New incoming stream #" << stream->get_stream_id() << std::endl;

        stream->set_data_handler([stream](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            std::cout << "[SERVER] Received: \"" << msg << "\"" << std::endl;

            // Echo back via the same bidirectional stream
            ObscuraProto::byte_vector response = {'E', 'c', 'h', 'o', ':', ' '};
            response.insert(response.end(), data.begin(), data.end());
            stream->write(response);
        });

        stream->set_end_handler([stream]() {
            std::cout << "[SERVER] Client finished writing to stream #" << stream->get_stream_id() << std::endl;
            stream->end();
        });

        stream->set_cancel_handler([stream]() {
            std::cout << "[SERVER] Stream #" << stream->get_stream_id() << " was canceled." << std::endl;
        });
    });

    server.run(port);
    std::cout << "[SERVER] Started on port " << port << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // ---- Client ----
    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);

    std::promise<void> ready_promise;
    std::future<void> ready_future = ready_promise.get_future();

    client.set_on_ready_callback([&]() {
        std::cout << "[CLIENT] Handshake complete. Starting stream..." << std::endl;

        // Start an outgoing stream
        auto stream = client.start_stream();
        std::cout << "[CLIENT] Started outgoing stream #" << stream->get_stream_id() << std::endl;

        // Set handler for incoming data from the server (bidirectional)
        stream->set_data_handler([](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            std::cout << "[CLIENT] Received from server: \"" << msg << "\"" << std::endl;
        });

        stream->set_end_handler([stream]() {
            std::cout << "[CLIENT] Server finished writing to stream #" << stream->get_stream_id() << std::endl;
        });

        // Send some data
        ObscuraProto::byte_vector chunk1 = {'H', 'e', 'l', 'l', 'o'};
        stream->write(chunk1);
        std::cout << "[CLIENT] Sent chunk 1" << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        ObscuraProto::byte_vector chunk2 = {'W', 'o', 'r', 'l', 'd'};
        stream->write(chunk2);
        std::cout << "[CLIENT] Sent chunk 2" << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Signal that we're done writing
        std::cout << "[CLIENT] Ending stream #" << stream->get_stream_id() << std::endl;
        stream->end();

        ready_promise.set_value();
    });

    client.connect("ws://localhost:" + std::to_string(port));
    std::cout << "[CLIENT] Connecting to server..." << std::endl;

    if (ready_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
        std::cerr << "[CLIENT] Timed out." << std::endl;
        server.stop();
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::cout << "\n[SYSTEM] Shutdown." << std::endl;
    client.disconnect();
    server.stop();

    return 0;
}
