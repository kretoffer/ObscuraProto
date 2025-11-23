#ifndef OBSCURAPROTO_KEYS_HPP
#define OBSCURAPROTO_KEYS_HPP

#include <vector>
#include <cstdint>

namespace ObscuraProto {

    // A generic structure for a public key.
    struct PublicKey {
        std::vector<uint8_t> data;
    };

    // A generic structure for a private key.
    struct PrivateKey {
        std::vector<uint8_t> data;
    };

    // A key pair consisting of a public and a private key.
    struct KeyPair {
        PublicKey publicKey;
        PrivateKey privateKey;
    };

    // A digital signature.
    struct Signature {
        std::vector<uint8_t> data;
    };

} // namespace ObscuraProto

#endif // OBSCURAPROTO_KEYS_HPP
