#include "obscuraproto/session.hpp"
#include <algorithm>
#include <stdexcept>

namespace ObscuraProto {

Session::Session(Role role, KeyPair server_static_key)
    : role_(role), server_static_key_(std::move(server_static_key)) {
    // For a client, the private key part of server_static_key_ should be empty.
    // For a server, both parts should be present.
}

// --- Handshake ---

Session::ClientHello Session::client_initiate_handshake() {
    if (role_ != Role::CLIENT) {
        throw std::logic_error("Only clients can initiate a handshake.");
    }

    // 1. Generate session keys and the handshake packet
    ClientHello hello;
    session_keys_ = std::make_unique<Crypto::SessionKeys>(
        Crypto::client_compute_session_keys(server_static_key_.publicKey, hello.kx_packet)
    );

    // 2. Set other hello data
    hello.supported_versions = SUPPORTED_VERSIONS;
    
    handshake_complete_ = true; // Client is ready after this step

    return hello;
}

void Session::server_respond_to_handshake(const ClientHello& client_hello) {
    if (role_ != Role::SERVER) {
        throw std::logic_error("Only servers can respond to a handshake.");
    }

    // 1. Select protocol version (optional, as we only have one)
    bool version_supported = false;
    for (const auto& v : client_hello.supported_versions) {
        if (v == Versions::V1_0) {
            version_supported = true;
            break;
        }
    }
    if (!version_supported) {
        throw std::runtime_error("Client does not support a compatible version.");
    }

    // 2. Derive session keys from the client's packet
    session_keys_ = std::make_unique<Crypto::SessionKeys>(
        Crypto::server_compute_session_keys(client_hello.kx_packet, server_static_key_)
    );
    
    handshake_complete_ = true; // Server is ready after this step
}

bool Session::is_handshake_complete() const {
    return handshake_complete_;
}


// --- Data Transfer ---

EncryptedPacket Session::encrypt_payload(const Payload& payload) {
    if (!handshake_complete_) {
        throw std::logic_error("Handshake must be complete before sending data.");
    }
    
    // Always use the 'tx' key for encryption.
    const auto& key = session_keys_->tx;
    
    send_counter_++;
    return Crypto::encrypt(payload, send_counter_, key);
}

Payload Session::decrypt_packet(const EncryptedPacket& packet) {
    if (!handshake_complete_) {
        throw std::logic_error("Handshake must be complete before receiving data.");
    }

    // Always use the 'rx' key for decryption.
    const auto& key = session_keys_->rx;

    // The counter must be incremented *before* decryption to prevent replay attacks
    // where an attacker sends message N+1, then N. We must check against the
    // *expected* next counter.
    uint64_t expected_recv_counter = recv_counter_ + 1;

    Payload payload = Crypto::decrypt(packet, expected_recv_counter, key);

    // If decryption was successful, we can now update our counter.
    recv_counter_ = expected_recv_counter;

    return payload;
}


} // namespace ObscuraProto
