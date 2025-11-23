#ifndef OBSCURAPROTO_PACKET_HPP
#define OBSCURAPROTO_PACKET_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>

namespace ObscuraProto {

    // Using a simple vector of bytes for data representation.
    using byte_vector = std::vector<uint8_t>;

    // An encrypted packet is just a vector of bytes.
    // The format is managed internally by hydro_secretbox.
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
         * @brief Adds a parameter using the length-prefix method.
         * @param param The parameter to add (as a byte vector).
         */
        void add_param(const byte_vector& param);

        /**
         * @brief Adds a string parameter using the length-prefix method.
         * @param param The string to add.
         */
        void add_param(const std::string& param);

        /**
         * @brief Serializes the payload into a single byte vector.
         * @return A byte vector ready for encryption.
         */
        byte_vector serialize() const;

        /**
         * @brief Deserializes a byte vector into a Payload object.
         * @param data The decrypted data.
         * @return A Payload object.
         * @throws std::runtime_error if the data is too small.
         */
        static Payload deserialize(const byte_vector& data);

        /**
         * @brief A helper class to parse parameters from a payload.
         */
        class ParamParser {
        public:
            explicit ParamParser(const byte_vector& params);

            /**
             * @brief Gets the next parameter.
             * @param out_param The byte vector to store the next parameter.
             * @return True if a parameter was extracted, false otherwise.
             */
            bool next_param(byte_vector& out_param);

            /**
             * @brief Gets the next parameter as a string.
             * @param out_param The string to store the next parameter.
             * @return True if a parameter was extracted, false otherwise.
             */
            bool next_param(std::string& out_param);

        private:
            const byte_vector& params_data;
            size_t offset = 0;
        };
    };

} // namespace ObscuraProto

#endif // OBSCURAPROTO_PACKET_HPP
