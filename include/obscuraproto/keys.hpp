#ifndef OBSCURAPROTO_KEYS_HPP
#define OBSCURAPROTO_KEYS_HPP

#include <cstdint>
#include <vector>

#include "secure_buffer.hpp"

namespace ObscuraProto {

    struct PublicKey {
        std::vector<uint8_t> data;

        bool operator==(const PublicKey& other) const {
            return data == other.data;
        }
        bool operator!=(const PublicKey& other) const {
            return data != other.data;
        }
        bool operator<(const PublicKey& other) const {
            return data < other.data;
        }
    };

    struct PrivateKey {
        SecureBuffer data;
    };

    struct KeyPair {
        PublicKey publicKey;
        PrivateKey privateKey;
    };

    struct Signature {
        std::vector<uint8_t> data;
    };

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_KEYS_HPP
