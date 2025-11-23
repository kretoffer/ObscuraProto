#ifndef OBSCURAPROTO_SESSION_HPP
#define OBSCURAPROTO_SESSION_HPP

#include "crypto.hpp"
#include "packet.hpp"
#include "version.hpp"

#include <memory>

namespace ObscuraProto {

    enum class Role {
        CLIENT,
        SERVER
    };

    /**
     * @brief Manages the state and logic for a single ObscuraProto session.
     */
    class Session {
    public:
        /**
         * @brief Construct a new Session object.
         * @param role Whether this session belongs to a client or a server.
         * @param server_sign_key For a server, its long-term signing key pair.
         *                        For a client, a key pair with only the public key part filled.
         */
        Session(Role role, KeyPair server_sign_key);

        // --- Handshake Data Structures ---
        struct ClientHello {
            std::vector<Version> supported_versions;
            PublicKey ephemeral_pk; // Client's ephemeral public key
        };

        struct ServerHello {
            Version selected_version;
            PublicKey ephemeral_pk; // Server's ephemeral public key
            Signature signature;    // Signature of the server's ephemeral_pk
        };

        // --- Handshake Methods ---

        /**
         * @brief [CLIENT] Initiates the handshake.
         * @return A ClientHello message to be sent to the server.
         */
        ClientHello client_initiate_handshake();

        /**
         * @brief [SERVER] Responds to a client's initiation request.
         * @param client_hello The message received from the client.
         * @return A ServerHello message to be sent back to the client.
         * @throws std::runtime_error if no compatible version is found or keys are invalid.
         */
        ServerHello server_respond_to_handshake(const ClientHello& client_hello);

        /**
         * @brief [CLIENT] Finalizes the handshake after receiving the server's response.
         * @param server_hello The message received from the server.
         * @throws std::runtime_error if the server's signature is invalid or keys can't be computed.
         */
        void client_finalize_handshake(const ServerHello& server_hello);


        // --- Data Transfer Methods ---

        /**
         * @brief Encrypts a payload to be sent over the secure channel.
         * @param payload The application data to send.
         * @return An encrypted packet ready for transport.
         */
        EncryptedPacket encrypt_payload(const Payload& payload);

        /**
         * @brief Decrypts a received packet.
         * @param packet The packet received from the transport.
         * @return The decrypted application payload.
         * @throws std::runtime_error on decryption or counter failure.
         */
        Payload decrypt_packet(const EncryptedPacket& packet);

        /**
         * @brief Checks if the handshake has been successfully completed.
         */
        bool is_handshake_complete() const;

    private:
        Role role_;
        bool handshake_complete_ = false;

        // Long-term signing key. For the server, this contains the private key.
        // For the client, this contains the server's public key.
        KeyPair server_sign_key_;

        // Ephemeral key pair for the current session's key exchange.
        std::unique_ptr<KeyPair> ephemeral_kx_kp_;

        // Session keys (derived from ECDH)
        std::unique_ptr<Crypto::SessionKeys> session_keys_;

        // Message counters
        uint64_t send_counter_ = 0;
        uint64_t recv_counter_ = 0;
    };

} // namespace ObscuraProto

#endif // OBSCURAPROTO_SESSION_HPP
