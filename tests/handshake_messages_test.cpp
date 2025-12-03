#include "obscuraproto/handshake_messages.hpp"

#include <gtest/gtest.h>

#include "obscuraproto/crypto.hpp"  // For key generation
#include "obscuraproto/version.hpp"

TEST(HandshakeMessagesTest, ClientHelloSerialization) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    ObscuraProto::ClientHello original_msg;
    original_msg.supported_versions.push_back(ObscuraProto::Versions::V1_0);
    auto keypair = ObscuraProto::Crypto::generate_kx_keypair();
    original_msg.ephemeral_pk = keypair.publicKey;

    auto serialized = original_msg.serialize();
    auto deserialized = ObscuraProto::ClientHello::deserialize(serialized);

    ASSERT_EQ(deserialized.supported_versions.size(), 1);
    ASSERT_EQ(deserialized.supported_versions[0], ObscuraProto::Versions::V1_0);
    ASSERT_EQ(deserialized.ephemeral_pk.data, original_msg.ephemeral_pk.data);
}

TEST(HandshakeMessagesTest, ServerHelloSerialization) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    ObscuraProto::ServerHello original_msg;
    original_msg.selected_version = ObscuraProto::Versions::V1_0;
    auto keypair = ObscuraProto::Crypto::generate_kx_keypair();
    original_msg.ephemeral_pk = keypair.publicKey;
    original_msg.signature.data.resize(64, 0xCC);  // Fill with dummy data

    auto serialized = original_msg.serialize();
    auto deserialized = ObscuraProto::ServerHello::deserialize(serialized);

    ASSERT_EQ(deserialized.selected_version, ObscuraProto::Versions::V1_0);
    ASSERT_EQ(deserialized.ephemeral_pk.data, original_msg.ephemeral_pk.data);
    ASSERT_EQ(deserialized.signature.data, original_msg.signature.data);
}
