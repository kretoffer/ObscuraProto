#include "obscuraproto/session.hpp"
#include "obscuraproto/errors.hpp"
#include <algorithm>

namespace ObscuraProto {

Session::Session(Role role, KeyPair server_sign_key)
    : role_(role), server_sign_key_(std::move(server_sign_key)) {
    // For a client, the private key part of server_sign_key_ should be empty.
    // For a server, both parts should be present.
}

// --- Handshake ---

ClientHello Session::client_initiate_handshake() {
    if (role_ != Role::CLIENT) {
        throw LogicError("Only clients can initiate a handshake.");
    }

    // 1. Generate an ephemeral key pair for this session
    ephemeral_kx_kp_ = std::make_unique<KeyPair>(Crypto::generate_kx_keypair());

    // 2. Create the ClientHello message
    ClientHello hello;
    hello.supported_versions = SUPPORTED_VERSIONS;
    hello.ephemeral_pk = ephemeral_kx_kp_->publicKey;

    return hello;
}

ServerHello Session::server_respond_to_handshake(const ClientHello& client_hello) {
    if (role_ != Role::SERVER) {
        throw LogicError("Only servers can respond to a handshake.");
    }

    // 1. Select a compatible protocol version
    bool version_supported = false;
    for (const auto& v : client_hello.supported_versions) {
        if (v == Versions::V1_0) {
            version_supported = true;
            break;
        }
    }
    if (!version_supported) {
        throw RuntimeError("Client does not support a compatible version.");
    }

    // 2. Generate an ephemeral key pair for this session
    ephemeral_kx_kp_ = std::make_unique<KeyPair>(Crypto::generate_kx_keypair());

    // 3. Sign our ephemeral public key with our long-term signing key
    Signature signature = Crypto::sign(ephemeral_kx_kp_->publicKey.data, server_sign_key_.privateKey);

    // 4. Compute the session keys
    session_keys_ = std::make_unique<Crypto::SessionKeys>(
        Crypto::server_compute_session_keys(*ephemeral_kx_kp_, client_hello.ephemeral_pk)
    );

    // 5. Create the ServerHello message
    ServerHello hello;
    hello.selected_version = Versions::V1_0;
    hello.ephemeral_pk = ephemeral_kx_kp_->publicKey;
    hello.signature = signature;

    handshake_complete_ = true; // Server is ready after this step
    return hello;
}

void Session::client_finalize_handshake(const ServerHello& server_hello) {
    if (role_ != Role::CLIENT) {
        throw LogicError("Only clients can finalize a handshake.");
    }
    if (!ephemeral_kx_kp_) {
        throw LogicError("client_initiate_handshake must be called first.");
    }

    // 1. Verify that the server selected a version we support
    if (server_hello.selected_version != Versions::V1_0) {
        throw RuntimeError("Server selected an unsupported version.");
    }

    // 2. Verify the signature of the server's ephemeral key
    bool signature_valid = Crypto::verify(server_hello.signature, server_hello.ephemeral_pk.data, server_sign_key_.publicKey);
    if (!signature_valid) {
        throw RuntimeError("Server's signature for its ephemeral key is invalid.");
    }

    // 3. Compute the session keys
    session_keys_ = std::make_unique<Crypto::SessionKeys>(
        Crypto::client_compute_session_keys(*ephemeral_kx_kp_, server_hello.ephemeral_pk)
    );

    handshake_complete_ = true; // Client is ready after this step
}

bool Session::is_handshake_complete() const {
    return handshake_complete_;
}


// --- Data Transfer ---

EncryptedPacket Session::encrypt_payload(const Payload& payload) {
    if (!handshake_complete_) {
        throw LogicError("Handshake must be complete before sending data.");
    }
    
    // Always use the 'tx' key for encryption.
    const auto& key = session_keys_->tx;
    
    send_counter_++;
    return Crypto::encrypt(payload, send_counter_, key);
}

Payload Session::decrypt_packet(const EncryptedPacket& packet) {
    if (!handshake_complete_) {
        throw LogicError("Handshake must be complete before receiving data.");
    }

    // Always use the 'rx' key for decryption.
    const auto& key = session_keys_->rx;

    // Decrypt the packet to get the payload and the counter.
    Crypto::DecryptedResult result = Crypto::decrypt(packet, key);

    // Now, perform the anti-replay check.
    // The received counter must be greater than the last one we processed.
    if (result.counter <= recv_counter_) {
        throw RuntimeError("Counter mismatch. Possible replay attack.");
    }

    // If decryption and counter check were successful, we can now update our counter.
    recv_counter_ = result.counter;

    return result.payload;
}

} // namespace ObscuraProto
