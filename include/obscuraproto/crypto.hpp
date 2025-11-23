#ifndef OBSCURAPROTO_CRYPTO_HPP
#define OBSCURAPROTO_CRYPTO_HPP

#include "keys.hpp"
#include "packet.hpp"
#include <string>

namespace ObscuraProto {

    // Context for signing messages, as required by libhydrogen.
    constexpr char SIGN_CONTEXT[] = "ObscuraP";

    class Crypto {
    public:
        /**
         * @brief Initializes the cryptographic library. Must be called once.
         * @return 0 on success, -1 on error.
         */
        static int init();

        /**
         * @brief Generates a key pair for the key exchange (ECDH).
         * @return A KeyPair object.
         */
        static KeyPair generate_kx_keypair();

        /**
         * @brief Generates a key pair for digital signatures (ECDSA).
         * @return A KeyPair object.
         */
        static KeyPair generate_sign_keypair();

        /**
         * @brief Creates a digital signature for a given message.
         * @param message The data to sign.
         * @param private_key The signer's private key.
         * @return A Signature object.
         */
        static Signature sign(const byte_vector& message, const PrivateKey& private_key);

        /**
         * @brief Verifies a digital signature.
         * @param signature The signature to verify.
         * @param message The message that was signed.
         * @param public_key The signer's public key.
         * @return True if the signature is valid, false otherwise.
         */
        static bool verify(const Signature& signature, const byte_vector& message, const PublicKey& public_key);

        /**
         * @brief A structure to hold the two derived symmetric keys from ECDH.
         */
        struct SessionKeys {
            byte_vector rx; // Key for receiving data
            byte_vector tx; // Key for sending data
        };

        /**
         * @brief [CLIENT] Computes session keys and the first handshake packet.
         * @param server_pk The server's long-term public signing key.
         * @param out_packet The generated packet to be sent to the server.
         * @return The derived session keys.
         */
        static SessionKeys client_compute_session_keys(const PublicKey& server_pk, byte_vector& out_packet);

        /**
         * @brief [SERVER] Computes session keys from the client's packet.
         * @param client_packet The packet received from the client.
         * @param server_kp The server's long-term signing key pair.
         * @return The derived session keys.
         */
        static SessionKeys server_compute_session_keys(const byte_vector& client_packet, const KeyPair& server_kp);

        /**
         * @brief Encrypts a payload using ChaCha20-Poly1305 (via hydro_secretbox).
         * @param payload The data to encrypt.
         * @param counter The message counter (used as msg_id).
         * @param key The symmetric encryption key.
         * @return An EncryptedPacket containing the ciphertext and header.
         */
        static EncryptedPacket encrypt(const Payload& payload, uint64_t counter, const byte_vector& key);

        /**
         * @brief Decrypts an envelope using ChaCha20-Poly1305 (via hydro_secretbox).
         * @param packet The encrypted packet to decrypt.
         * @param counter The expected message counter (used as msg_id).
         * @param key The symmetric decryption key.
         * @return A Payload object if decryption is successful.
         * @throws std::runtime_error if decryption fails.
         */
        static Payload decrypt(const EncryptedPacket& packet, uint64_t counter, const byte_vector& key);
    };

} // namespace ObscuraProto

#endif // OBSCURAPROTO_CRYPTO_HPP
