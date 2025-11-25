#include <iostream>
#include <string>
#include <vector>
#include <cassert>

#include "obscuraproto/session.hpp"
#include "obscuraproto/crypto.hpp"
#include "obscuraproto/packet.hpp"

void print_bytes(const std::string& title, const ObscuraProto::byte_vector& bytes) {
    std::cout << title << " (" << bytes.size() << " bytes): ";
    for (size_t i = 0; i < bytes.size() && i < 24; ++i) {
        printf("%02x", bytes[i]);
    }
    if (bytes.size() > 24) {
        std::cout << "...";
    }
    std::cout << std::endl;
}

int main() {
    // 1. Initialize the crypto library
    if (ObscuraProto::Crypto::init() != 0) {
        std::cerr << "Failed to initialize crypto library!" << std::endl;
        return 1;
    }
    std::cout << "Crypto library initialized." << std::endl;

    // 2. Setup server and client
    // In a real scenario, the client would know the server's public SIGNING key beforehand.
    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    print_bytes("Server Public Sign Key", server_long_term_key.publicKey.data);

    // The client is configured with the server's public signing key
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);
    std::cout << "Client and Server sessions created." << std::endl;
    std::cout << "\n--- Starting Handshake ---" << std::endl;

    // 3. Handshake Step 1: Client initiates and sends ClientHello
    auto client_hello = client_session.client_initiate_handshake();
    std::cout << "[C->S] Sending ClientHello" << std::endl;
    print_bytes("  Client Ephemeral PK", client_hello.ephemeral_pk.data);

    // 4. Handshake Step 2: Server processes ClientHello and sends ServerHello
    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    std::cout << "[S->C] Sending ServerHello" << std::endl;
    print_bytes("  Server Ephemeral PK", server_hello.ephemeral_pk.data);
    print_bytes("  Signature", server_hello.signature.data);
    assert(server_session.is_handshake_complete());
    std::cout << "[SERVER] Server handshake is complete." << std::endl;

    // 5. Handshake Step 3: Client processes ServerHello and finalizes
    client_session.client_finalize_handshake(server_hello);
    assert(client_session.is_handshake_complete());
    std::cout << "[CLIENT] Client handshake is complete." << std::endl;

    std::cout << "\n--- Handshake Successful ---" << std::endl;

    // 6. Data Transfer: Client -> Server
    std::cout << "\n--- Testing Data Transfer (Client to Server) ---" << std::endl;
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001)
        .add_param("my_username")
        .add_param("my_very_secret_password")
        .build();

    std::cout << "[CLIENT] Serialized payload to send:" << std::endl;
    print_bytes("  Payload Data", client_payload.serialize());

    // The client encrypts the payload. The resulting packet contains the nonce, counter, and ciphertext+tag.
    ObscuraProto::EncryptedPacket packet_to_send = client_session.encrypt_payload(client_payload);
    std::cout << "[C->S] Sending encrypted packet..." << std::endl;
    print_bytes("  Full Packet", packet_to_send);

    // 7. Server receives and decrypts
    // The server receives the exact packet sent by the client.
    std::cout << "\n[SERVER] Received packet, attempting decryption..." << std::endl;
    try {
        ObscuraProto::Payload decrypted_payload = server_session.decrypt_packet(packet_to_send);
        std::cout << "[SERVER] Message decrypted successfully!" << std::endl;
        assert(decrypted_payload.op_code == client_payload.op_code);
        
        ObscuraProto::PayloadReader reader(decrypted_payload);
        std::string username = reader.read_param_string();
        std::string password = reader.read_param_string();

        std::cout << "  OpCode: 0x" << std::hex << decrypted_payload.op_code << std::dec << std::endl;
        std::cout << "  Username: " << username << std::endl;
        std::cout << "  Password: " << password << std::endl;
        assert(username == "my_username");
        assert(password == "my_very_secret_password");

    } catch (const std::exception& e) {
        std::cerr << "[SERVER] Decryption failed: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\n--- Protocol simulation successful!---" << std::endl;

    return 0;
}