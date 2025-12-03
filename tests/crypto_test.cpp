#include "obscuraproto/crypto.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "obscuraproto/packet.hpp"
#include "obscuraproto/session.hpp"

TEST(SessionTest, HandshakeAndEncryptDecrypt) {
    // 1. Initialize the crypto library
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    // 2. Setup server and client
    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);

    // 3. Handshake
    auto client_hello = client_session.client_initiate_handshake();
    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    client_session.client_finalize_handshake(server_hello);

    ASSERT_TRUE(server_session.is_handshake_complete());
    ASSERT_TRUE(client_session.is_handshake_complete());

    // 4. Data Transfer: Client -> Server
    uint64_t timestamp = 1678886400000;
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001)
                                               .add_param("my_username")
                                               .add_param("my_very_secret_password")
                                               .add_param(timestamp)
                                               .build();

    // 5. Encrypt on client
    ObscuraProto::EncryptedPacket packet_to_send = client_session.encrypt_payload(client_payload);

    // 6. Decrypt on server
    ObscuraProto::Payload decrypted_payload;
    ASSERT_NO_THROW({ decrypted_payload = server_session.decrypt_packet(packet_to_send); });

    // 7. Verify decrypted data
    ASSERT_EQ(decrypted_payload.op_code, client_payload.op_code);

    ObscuraProto::PayloadReader reader(decrypted_payload);
    auto username = reader.read_param<std::string>();
    auto password = reader.read_param<std::string>();
    auto received_timestamp = reader.read_param<uint64_t>();

    ASSERT_EQ(username, "my_username");
    ASSERT_EQ(password, "my_very_secret_password");
    ASSERT_EQ(received_timestamp, timestamp);
}

TEST(SessionTest, DecryptionFailure) {
    // 1. Initialize and handshake
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);
    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;
    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);
    auto client_hello = client_session.client_initiate_handshake();
    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    client_session.client_finalize_handshake(server_hello);
    ASSERT_TRUE(client_session.is_handshake_complete());

    // 2. Create a payload and encrypt it
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001).add_param("some data").build();
    ObscuraProto::EncryptedPacket packet_to_send = client_session.encrypt_payload(client_payload);

    // 3. Create a second server session with a different key
    auto server_long_term_key_2 = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::Session server_session_2(ObscuraProto::Role::SERVER, server_long_term_key_2);
    // This session did not perform the handshake with the client, so it has different session keys.

    // 4. Try to decrypt with the wrong session
    ASSERT_THROW(server_session_2.decrypt_packet(packet_to_send), ObscuraProto::LogicError);

    // 5. Corrupt the packet and try to decrypt
    packet_to_send[packet_to_send.size() - 1] ^= 0xFF;  // Flip some bits in the tag
    ASSERT_THROW(server_session.decrypt_packet(packet_to_send), ObscuraProto::RuntimeError);
}

TEST(SessionTest, HandshakeFailure) {
    // 1. Initialize
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    // 2. Setup server and client with mismatched keys
    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    auto wrong_server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = wrong_server_long_term_key.publicKey;  // Client has the wrong key

    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);

    // 3. Handshake
    auto client_hello = client_session.client_initiate_handshake();
    auto server_hello = server_session.server_respond_to_handshake(client_hello);

    // 4. Client should fail to finalize the handshake
    ASSERT_THROW(client_session.client_finalize_handshake(server_hello), ObscuraProto::RuntimeError);
    ASSERT_FALSE(client_session.is_handshake_complete());
}
