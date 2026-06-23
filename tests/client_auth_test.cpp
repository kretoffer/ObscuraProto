#include <gtest/gtest.h>

#include "obscuraproto/crypto.hpp"
#include "obscuraproto/handshake_messages.hpp"
#include "obscuraproto/session.hpp"

TEST(ClientAuthTest, HandshakeWithClientIdentity) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    // 1. Generate keys
    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    auto client_identity_key = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    // 2. Create sessions
    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);

    // 3. Set client identity
    client_session.set_client_identity_key(client_identity_key);

    // 4. Handshake
    auto client_hello = client_session.client_initiate_handshake();
    ASSERT_TRUE(client_hello.has_client_identity);
    ASSERT_EQ(client_hello.identity_pk.data, client_identity_key.publicKey.data);
    ASSERT_FALSE(client_hello.identity_sig.data.empty());

    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    client_session.client_finalize_handshake(server_hello);

    ASSERT_TRUE(server_session.is_handshake_complete());
    ASSERT_TRUE(client_session.is_handshake_complete());

    // 5. Verify server sees the client's identity
    ASSERT_TRUE(server_session.has_peer_identity());
    auto peer_id = server_session.get_peer_identity();
    ASSERT_TRUE(peer_id.has_value());
    ASSERT_EQ(peer_id->data, client_identity_key.publicKey.data);

    // 6. Client should not have peer identity (server doesn't authenticate to client via identity)
    ASSERT_FALSE(client_session.has_peer_identity());
}

TEST(ClientAuthTest, HandshakeWithoutClientIdentity) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);

    auto client_hello = client_session.client_initiate_handshake();
    ASSERT_FALSE(client_hello.has_client_identity);

    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    client_session.client_finalize_handshake(server_hello);

    ASSERT_TRUE(server_session.is_handshake_complete());
    ASSERT_TRUE(client_session.is_handshake_complete());

    ASSERT_FALSE(server_session.has_peer_identity());
}

TEST(ClientAuthTest, InvalidClientIdentitySignature) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    auto client_identity_key = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);

    client_session.set_client_identity_key(client_identity_key);

    auto client_hello = client_session.client_initiate_handshake();
    ASSERT_TRUE(client_hello.has_client_identity);

    // Tamper with the signature
    if (!client_hello.identity_sig.data.empty()) {
        client_hello.identity_sig.data[0] ^= 0xFF;
    }

    // Server should reject the tampered signature
    ASSERT_THROW(server_session.server_respond_to_handshake(client_hello), ObscuraProto::RuntimeError);
}

TEST(ClientAuthTest, ClientIdentityThenEncryptDecrypt) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    auto client_identity_key = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);

    client_session.set_client_identity_key(client_identity_key);

    auto client_hello = client_session.client_initiate_handshake();
    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    client_session.client_finalize_handshake(server_hello);

    ASSERT_TRUE(server_session.has_peer_identity());

    // Encrypt and decrypt should still work
    ObscuraProto::Payload payload = ObscuraProto::PayloadBuilder(0x1001).add_param("secret_data").build();

    auto encrypted = client_session.encrypt_payload(payload);
    ObscuraProto::Payload decrypted = server_session.decrypt_packet(encrypted);

    ASSERT_EQ(decrypted.op_code, 0x1001);
    ObscuraProto::PayloadReader reader(decrypted);
    ASSERT_EQ(reader.read_param<std::string>(), "secret_data");
}

TEST(ClientAuthTest, ClientHelloSerializationWithIdentity) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    auto client_identity_key = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::KeyPair dummy_server_key;
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, dummy_server_key);
    client_session.set_client_identity_key(client_identity_key);

    auto original = client_session.client_initiate_handshake();
    ASSERT_TRUE(original.has_client_identity);

    auto serialized = original.serialize();
    auto deserialized = ObscuraProto::ClientHello::deserialize(serialized);

    ASSERT_TRUE(deserialized.has_client_identity);
    ASSERT_EQ(deserialized.identity_pk.data, original.identity_pk.data);
    ASSERT_EQ(deserialized.identity_sig.data, original.identity_sig.data);
    ASSERT_EQ(deserialized.ephemeral_pk.data, original.ephemeral_pk.data);
    ASSERT_EQ(deserialized.supported_versions.size(), original.supported_versions.size());
}

TEST(ClientAuthTest, ClientHelloSerializationWithoutIdentity) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    ObscuraProto::KeyPair dummy_server_key;
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, dummy_server_key);

    auto original = client_session.client_initiate_handshake();
    ASSERT_FALSE(original.has_client_identity);

    auto serialized = original.serialize();
    auto deserialized = ObscuraProto::ClientHello::deserialize(serialized);

    ASSERT_FALSE(deserialized.has_client_identity);
    ASSERT_EQ(deserialized.ephemeral_pk.data, original.ephemeral_pk.data);
    ASSERT_EQ(deserialized.supported_versions.size(), original.supported_versions.size());
}

TEST(ClientAuthTest, SetClientIdentityOnServerThrows) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    auto server_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_key);

    auto identity_key = ObscuraProto::Crypto::generate_sign_keypair();
    ASSERT_THROW(server_session.set_client_identity_key(identity_key), ObscuraProto::LogicError);
}
