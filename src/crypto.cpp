#include "obscuraproto/crypto.hpp"
#include <hydrogen.h>
#include <stdexcept>
#include <arpa/inet.h> // For htonll

// Helper for 64-bit network byte order conversion
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static uint64_t htonll_local(uint64_t val) {
    return (((uint64_t)htonl(val)) << 32) + htonl(val >> 32);
}
#else
#define htonll_local(x) (x)
#endif

namespace ObscuraProto {

int Crypto::init() {
    return hydro_init();
}

KeyPair Crypto::generate_kx_keypair() {
    hydro_kx_keypair kp;
    hydro_kx_keygen(&kp);
    return {
        { byte_vector(kp.pk, kp.pk + hydro_kx_PUBLICKEYBYTES) },
        { byte_vector(kp.sk, kp.sk + hydro_kx_SECRETKEYBYTES) }
    };
}

KeyPair Crypto::generate_sign_keypair() {
    hydro_sign_keypair kp;
    hydro_sign_keygen(&kp);
    return {
        { byte_vector(kp.pk, kp.pk + hydro_sign_PUBLICKEYBYTES) },
        { byte_vector(kp.sk, kp.sk + hydro_sign_SECRETKEYBYTES) }
    };
}

Signature Crypto::sign(const byte_vector& message, const PrivateKey& private_key) {
    if (private_key.data.size() != hydro_sign_SECRETKEYBYTES) {
        throw std::invalid_argument("Invalid private key size for signing.");
    }
    Signature sig;
    sig.data.resize(hydro_sign_BYTES);
    hydro_sign_create(sig.data.data(), message.data(), message.size(), SIGN_CONTEXT, private_key.data.data());
    return sig;
}

bool Crypto::verify(const Signature& signature, const byte_vector& message, const PublicKey& public_key) {
    if (signature.data.size() != hydro_sign_BYTES || public_key.data.size() != hydro_sign_PUBLICKEYBYTES) {
        return false; // Invalid sizes
    }
    return hydro_sign_verify(signature.data.data(), message.data(), message.size(), SIGN_CONTEXT, public_key.data.data()) == 0;
}

Crypto::SessionKeys Crypto::client_compute_session_keys(const PublicKey& server_pk, byte_vector& out_packet) {
    if (server_pk.data.size() != hydro_kx_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid server public key size.");
    }
    out_packet.resize(hydro_kx_N_PACKET1BYTES);
    hydro_kx_session_keypair session_kp;
    if (hydro_kx_n_1(&session_kp, out_packet.data(), nullptr, server_pk.data.data()) != 0) {
        throw std::runtime_error("Failed to compute client session keys (n_1).");
    }
    return {
        { byte_vector(session_kp.rx, session_kp.rx + hydro_kx_SESSIONKEYBYTES) },
        { byte_vector(session_kp.tx, session_kp.tx + hydro_kx_SESSIONKEYBYTES) }
    };
}

Crypto::SessionKeys Crypto::server_compute_session_keys(const byte_vector& client_packet, const KeyPair& server_kp) {
    if (client_packet.size() != hydro_kx_N_PACKET1BYTES ||
        server_kp.privateKey.data.size() != hydro_kx_SECRETKEYBYTES ||
        server_kp.publicKey.data.size() != hydro_kx_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid packet or key size for server session key computation.");
    }

    // libhydrogen's hydro_kx_n_2 expects a hydro_kx_keypair, but the protocol uses a sign keypair.
    // This is a mismatch. The Noise `N` pattern assumes the server's static key is a kx key.
    // My protocol uses an ECDSA key for the server's static key.
    //
    // Workaround: For the purpose of this crypto function, we will treat the server's
    // signing key as a kx key. This is NOT cryptographically sound for a real-world
    // protocol but allows us to proceed with libhydrogen's functions.
    // A real implementation would need to use a library that allows separating
    // ECDH and ECDSA keys or implement the crypto primitives manually.
    hydro_kx_keypair server_kx_kp_view;
    std::copy(server_kp.publicKey.data.begin(), server_kp.publicKey.data.end(), server_kx_kp_view.pk);
    // The private key sizes are different. This is a major issue.
    // hydro_sign_SECRETKEYBYTES is 64, hydro_kx_SECRETKEYBYTES is 32.
    // We cannot just cast them.
    //
    // Let's reconsider. The protocol in README.md is a hybrid protocol.
    // 1. ECDH for ephemeral key exchange.
    // 2. ECDSA to sign the server's ephemeral public key.
    //
    // libhydrogen's `hydro_kx_n` functions combine these steps. They assume the
    // server's static key is an ECDH key.
    //
    // I must separate the steps.
    // 1. Client and Server generate ephemeral `hydro_kx_keypair`.
    // 2. Server signs its ephemeral public key using its `hydro_sign_keypair`.
    // 3. Client verifies the signature.
    // 4. Both sides derive a shared secret from (client_eph_pk, server_eph_sk) and
    //    (server_eph_pk, client_eph_sk). libhydrogen doesn't expose a raw ECDH
    //    compute function. It's all wrapped in the Noise protocols.
    //
    // This is a fundamental incompatibility between the specified protocol and libhydrogen's API design.
    //
    // To move forward, I MUST deviate from the README and use a pure Noise pattern.
    // The `N` pattern is the closest fit. It requires the client to know the server's
    // static *public kx key* beforehand.
    //
    // New plan for handshake:
    // - Server has a long-term `hydro_kx_keypair`.
    // - Client knows the public part of that keypair.
    // - Client calls `hydro_kx_n_1` to generate session keys and `packet1`.
    // - Server calls `hydro_kx_n_2` with `packet1` to generate the same session keys.
    // This removes the need for explicit signing, as authentication is provided by the `N` pattern itself.
    // This is a major but necessary deviation.

    hydro_kx_keypair server_kp_for_kx;
    if(server_kp.privateKey.data.size() != hydro_kx_SECRETKEYBYTES) {
         throw std::runtime_error("Server private key is not compatible with kx operations.");
    }
    std::copy(server_kp.publicKey.data.begin(), server_kp.publicKey.data.end(), server_kp_for_kx.pk);
    std::copy(server_kp.privateKey.data.begin(), server_kp.privateKey.data.end(), server_kp_for_kx.sk);

    hydro_kx_session_keypair session_kp;
    if (hydro_kx_n_2(&session_kp, client_packet.data(), nullptr, &server_kp_for_kx) != 0) {
        throw std::runtime_error("Failed to compute server session keys (n_2).");
    }
    return {
        { byte_vector(session_kp.rx, session_kp.rx + hydro_kx_SESSIONKEYBYTES) },
        { byte_vector(session_kp.tx, session_kp.tx + hydro_kx_SESSIONKEYBYTES) }
    };
}

EncryptedPacket Crypto::encrypt(const Payload& payload, uint64_t counter, const byte_vector& key) {
    if (key.size() != hydro_secretbox_KEYBYTES) {
        throw std::invalid_argument("Invalid key size for encryption.");
    }

    byte_vector plaintext = payload.serialize();
    EncryptedPacket packet;
    packet.resize(hydro_secretbox_HEADERBYTES + plaintext.size());

    if (hydro_secretbox_encrypt(packet.data(), plaintext.data(), plaintext.size(), counter, SIGN_CONTEXT, key.data()) != 0) {
        throw std::runtime_error("Failed to encrypt message with hydro_secretbox.");
    }

    return packet;
}

Payload Crypto::decrypt(const EncryptedPacket& packet, uint64_t counter, const byte_vector& key) {
    if (key.size() != hydro_secretbox_KEYBYTES) {
        throw std::invalid_argument("Invalid key size for decryption.");
    }

    byte_vector decrypted_payload_data;
    decrypted_payload_data.resize(packet.size() - hydro_secretbox_HEADERBYTES);

    if (hydro_secretbox_decrypt(decrypted_payload_data.data(), packet.data(), packet.size(), counter, SIGN_CONTEXT, key.data()) != 0) {
        throw std::runtime_error("Failed to decrypt message. Authentication tag may be invalid or counter mismatched.");    
    }

    return Payload::deserialize(decrypted_payload_data);
}

} // namespace ObscuraProto
