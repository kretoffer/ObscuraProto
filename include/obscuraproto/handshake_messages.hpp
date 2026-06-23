#ifndef OBSCURAPROTO_HANDSHAKE_MESSAGES_HPP
#define OBSCURAPROTO_HANDSHAKE_MESSAGES_HPP

#include "keys.hpp"
#include "packet.hpp"
#include "version.hpp"

namespace ObscuraProto {

    // --- Handshake Data Structures ---
    struct ClientHello {
        std::vector<Version> supported_versions;
        PublicKey ephemeral_pk;  // Client's ephemeral public key

        // Client identity (Ed25519)
        bool has_client_identity = false;
        PublicKey identity_pk;   // Client's Ed25519 public key
        Signature identity_sig;  // Ed25519 sign(ephemeral_pk) using identity_pk's private key

        byte_vector serialize() const;
        static ClientHello deserialize(const byte_vector& data);
    };

    struct ServerHello {
        Version selected_version;
        PublicKey ephemeral_pk;  // Server's ephemeral public key
        Signature signature;     // Signature of the server's ephemeral_pk

        byte_vector serialize() const;
        static ServerHello deserialize(const byte_vector& data);
    };

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_HANDSHAKE_MESSAGES_HPP
