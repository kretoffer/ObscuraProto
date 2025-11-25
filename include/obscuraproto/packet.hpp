#ifndef OBSCURAPROTO_PACKET_HPP
#define OBSCURAPROTO_PACKET_HPP

#include <vector>
#include <cstdint>
#include <string>

namespace ObscuraProto {

    // Using a simple vector of bytes for data representation.
    using byte_vector = std::vector<uint8_t>;

    // An encrypted packet is just a vector of bytes.
    using EncryptedPacket = byte_vector;

    /**
     * @brief Represents the internal payload before encryption.
     * Format: [OpCode (2)] + [Parameters (N)]
     */
    class Payload {
    public:
        using OpCode = uint16_t;

        OpCode op_code;
        byte_vector parameters;

        /**
         * @brief Serializes the payload into a single byte vector.
         * @return A byte vector ready for encryption.
         */
        byte_vector serialize() const;

        /**
         * @brief Deserializes a byte vector into a Payload object.
         * @param data The decrypted data.
         * @return A Payload object.
         * @throws ObscuraProto::RuntimeError if the data is too small.
         */
        static Payload deserialize(const byte_vector& data);
    };

    /**
     * @brief A helper class to build a Payload with parameters.
     */
    class PayloadBuilder {
    public:
        explicit PayloadBuilder(Payload::OpCode op_code);

        PayloadBuilder& add_param(const byte_vector& param);
        PayloadBuilder& add_param(const std::string& param);
        PayloadBuilder& add_param(uint32_t param);

        Payload build();

    private:
        Payload payload_;
    };

    /**
     * @brief A helper class to parse parameters from a payload.
     */
    class PayloadReader {
    public:
        explicit PayloadReader(const Payload& payload);

        byte_vector read_param_bytes();
        std::string read_param_string();
        uint32_t read_param_u32();

        bool has_more() const;

    private:
        const byte_vector& params_data_;
        size_t offset_ = 0;
    };

} // namespace ObscuraProto

#endif // OBSCURAPROTO_PACKET_HPP