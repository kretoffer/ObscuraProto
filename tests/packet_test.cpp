#include "obscuraproto/packet.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

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

TEST(PacketTest, PeekNextParamSize) {
    // 1. Build a payload
    uint32_t an_integer = 0xDEADBEEF;
    std::string a_string = "hello world";
    bool a_bool = true;

    ObscuraProto::Payload payload =
        ObscuraProto::PayloadBuilder(0x2002).add_param(an_integer).add_param(a_string).add_param(a_bool).build();

    ObscuraProto::PayloadReader reader(payload);

    // 2. Peek and read first param
    ASSERT_TRUE(reader.has_more());
    ASSERT_EQ(reader.peek_next_param_size(), sizeof(uint32_t));
    auto read_integer = reader.read_param<uint32_t>();
    ASSERT_EQ(read_integer, an_integer);

    // 3. Peek and read second param
    ASSERT_TRUE(reader.has_more());
    ASSERT_EQ(reader.peek_next_param_size(), a_string.length());
    auto read_string = reader.read_param<std::string>();
    ASSERT_EQ(read_string, a_string);

    // 4. Peek and read third param
    ASSERT_TRUE(reader.has_more());
    ASSERT_EQ(reader.peek_next_param_size(), sizeof(uint8_t));  // bool is stored as uint8_t
    auto read_bool = reader.read_param<bool>();
    ASSERT_EQ(read_bool, a_bool);

    // 5. Check for end of params
    ASSERT_FALSE(reader.has_more());
    ASSERT_THROW(reader.peek_next_param_size(), ObscuraProto::RuntimeError);
}
