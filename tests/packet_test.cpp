#include <gtest/gtest.h>
#include "obscuraproto/packet.hpp"
#include <string>
#include <vector>
#include <cstdint>

TEST(PacketTest, PayloadBuilderAndReader) {
    // 1. Build a payload
    uint64_t timestamp = 1678886400000;
    std::string username = "test_user";
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    bool is_admin = true;
    double score = 99.9;

    ObscuraProto::Payload payload = ObscuraProto::PayloadBuilder(0x2001)
        .add_param(username)
        .add_param(timestamp)
        .add_param(data)
        .add_param(is_admin)
        .add_param(score)
        .build();

    // 2. Serialize and Deserialize
    auto serialized_payload = payload.serialize();
    ObscuraProto::Payload deserialized_payload = ObscuraProto::Payload::deserialize(serialized_payload);

    // 3. Verify opcode
    ASSERT_EQ(payload.op_code, deserialized_payload.op_code);
    ASSERT_EQ(deserialized_payload.op_code, 0x2001);

    // 4. Read and verify params
    ObscuraProto::PayloadReader reader(deserialized_payload);

    auto read_username = reader.read_param<std::string>();
    auto read_timestamp = reader.read_param<uint64_t>();
    auto read_data = reader.read_param<std::vector<uint8_t>>();
    auto read_is_admin = reader.read_param<bool>();
    auto read_score = reader.read_param<double>();

    ASSERT_EQ(read_username, username);
    ASSERT_EQ(read_timestamp, timestamp);
    ASSERT_EQ(read_data, data);
    ASSERT_EQ(read_is_admin, is_admin);
    ASSERT_DOUBLE_EQ(read_score, score);

    // 5. Check for end of params
    ASSERT_FALSE(reader.has_more());
}
