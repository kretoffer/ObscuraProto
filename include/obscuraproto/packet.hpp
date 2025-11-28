#ifndef OBSCURAPROTO_PACKET_HPP
#define OBSCURAPROTO_PACKET_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <arpa/inet.h>
#include "errors.hpp"

namespace ObscuraProto {

    namespace detail {
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        static uint64_t htonll_local(uint64_t val) {
            return (((uint64_t)htonl(val)) << 32) + htonl(val >> 32);
        }
        static uint64_t ntohll_local(uint64_t val) {
            return (((uint64_t)ntohl(val)) << 32) + ntohl(val >> 32);
        }
        #else
        #define htonll_local(x) (x)
        #define ntohll_local(x) (x)
        #endif
    }

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
        PayloadBuilder& add_param(const char* param);
        
        PayloadBuilder& add_param(bool param);
        PayloadBuilder& add_param(int8_t param);
        PayloadBuilder& add_param(uint8_t param);
        PayloadBuilder& add_param(int16_t param);
        PayloadBuilder& add_param(uint16_t param);
        PayloadBuilder& add_param(int32_t param);
        PayloadBuilder& add_param(uint32_t param);
        PayloadBuilder& add_param(int64_t param);
        PayloadBuilder& add_param(uint64_t param);
        PayloadBuilder& add_param(float param);
        PayloadBuilder& add_param(double param);

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

        template<typename T>
        T read_param() {
            byte_vector vec = read_param_bytes();
            if (vec.size() != sizeof(T)) {
                throw RuntimeError("Invalid payload data: parameter size mismatch for the requested type.");
            }
            T val;
            std::copy(vec.begin(), vec.end(), reinterpret_cast<uint8_t*>(&val));

            if constexpr (std::is_integral_v<T> && sizeof(T) == 2) {
                return ntohs(val);
            } else if constexpr (std::is_integral_v<T> && sizeof(T) == 4) {
                return ntohl(val);
            } else if constexpr (std::is_integral_v<T> && sizeof(T) == 8) {
                return detail::ntohll_local(val);
            } else {
                return val;
            }
        }

        bool has_more() const;

    private:
        byte_vector read_param_bytes();
        const byte_vector& params_data_;
        size_t offset_ = 0;
    };

    template<>
    inline std::string PayloadReader::read_param<std::string>() {
        byte_vector vec = read_param_bytes();
        return std::string(vec.begin(), vec.end());
    }

    template<>
    inline byte_vector PayloadReader::read_param<byte_vector>() {
        return read_param_bytes();
    }

} // namespace ObscuraProto

#endif // OBSCURAPROTO_PACKET_HPP