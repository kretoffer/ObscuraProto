#include "obscuraproto/handshake_messages.hpp"
#include "obscuraproto/errors.hpp"
#include <arpa/inet.h>
#include <sodium.h>

namespace ObscuraProto {

// ClientHello

byte_vector ClientHello::serialize() const {
    byte_vector buffer;
    // Add number of versions
    uint16_t num_versions = htons(static_cast<uint16_t>(supported_versions.size()));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&num_versions), reinterpret_cast<uint8_t*>(&num_versions) + sizeof(num_versions));

    // Add versions
    for (const auto& version : supported_versions) {
        uint16_t be_version = htons(version);
        buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&be_version), reinterpret_cast<uint8_t*>(&be_version) + sizeof(be_version));
    }

    // Add ephemeral public key
    buffer.insert(buffer.end(), ephemeral_pk.data.begin(), ephemeral_pk.data.end());

    return buffer;
}

ClientHello ClientHello::deserialize(const byte_vector& data) {
    ClientHello hello;
    size_t offset = 0;

    // Get number of versions
    if (data.size() < sizeof(uint16_t)) throw RuntimeError("Invalid ClientHello data: too short for version count.");
    uint16_t num_versions;
    std::copy(data.begin() + offset, data.begin() + offset + sizeof(uint16_t), reinterpret_cast<uint8_t*>(&num_versions));
    num_versions = ntohs(num_versions);
    offset += sizeof(uint16_t);

    // Get versions
    if (data.size() < offset + num_versions * sizeof(Version)) throw RuntimeError("Invalid ClientHello data: too short for versions.");
    for (int i = 0; i < num_versions; ++i) {
        uint16_t be_version;
        std::copy(data.begin() + offset, data.begin() + offset + sizeof(uint16_t), reinterpret_cast<uint8_t*>(&be_version));
        hello.supported_versions.push_back(ntohs(be_version));
        offset += sizeof(uint16_t);
    }

    // Get ephemeral public key
    if (data.size() < offset + crypto_kx_PUBLICKEYBYTES) throw RuntimeError("Invalid ClientHello data: too short for public key.");
    hello.ephemeral_pk.data.assign(data.begin() + offset, data.begin() + offset + crypto_kx_PUBLICKEYBYTES);

    return hello;
}


// ServerHello

byte_vector ServerHello::serialize() const {
    byte_vector buffer;

    // Add selected version
    uint16_t be_version = htons(selected_version);
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&be_version), reinterpret_cast<uint8_t*>(&be_version) + sizeof(be_version));

    // Add ephemeral public key
    buffer.insert(buffer.end(), ephemeral_pk.data.begin(), ephemeral_pk.data.end());

    // Add signature
    buffer.insert(buffer.end(), signature.data.begin(), signature.data.end());

    return buffer;
}

ServerHello ServerHello::deserialize(const byte_vector& data) {
    ServerHello hello;
    size_t offset = 0;

    // Get selected version
    if (data.size() < sizeof(uint16_t)) throw RuntimeError("Invalid ServerHello data: too short for version.");
    uint16_t be_version;
    std::copy(data.begin() + offset, data.begin() + offset + sizeof(uint16_t), reinterpret_cast<uint8_t*>(&be_version));
    hello.selected_version = ntohs(be_version);
    offset += sizeof(uint16_t);

    // Get ephemeral public key
    if (data.size() < offset + crypto_kx_PUBLICKEYBYTES) throw RuntimeError("Invalid ServerHello data: too short for public key.");
    hello.ephemeral_pk.data.assign(data.begin() + offset, data.begin() + offset + crypto_kx_PUBLICKEYBYTES);
    offset += crypto_kx_PUBLICKEYBYTES;

    // Get signature
    if (data.size() < offset + crypto_sign_BYTES) throw RuntimeError("Invalid ServerHello data: too short for signature.");
    hello.signature.data.assign(data.begin() + offset, data.begin() + offset + crypto_sign_BYTES);

    return hello;
}

} // namespace ObscuraProto
