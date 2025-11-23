#include "obscuraproto/packet.hpp"
#include "obscuraproto/errors.hpp"
#include <arpa/inet.h> // For htons, ntohs, htonll, ntohll if available

// Helper for 64-bit network byte order conversion
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static uint64_t htonll(uint64_t val) {
    return (((uint64_t)htonl(val)) << 32) + htonl(val >> 32);
}
static uint64_t ntohll(uint64_t val) {
    return (((uint64_t)ntohl(val)) << 32) + ntohl(val >> 32);
}
#else
#define htonll(x) (x)
#define ntohll(x) (x)
#endif


namespace ObscuraProto {

// --- Payload ---

void Payload::add_param(const byte_vector& param) {
    if (param.size() > UINT16_MAX) {
        throw RuntimeError("Parameter size exceeds maximum of 65535 bytes.");
    }
    uint16_t len = static_cast<uint16_t>(param.size());
    uint16_t be_len = htons(len);

    parameters.insert(parameters.end(), reinterpret_cast<uint8_t*>(&be_len), reinterpret_cast<uint8_t*>(&be_len) + sizeof(be_len));
    parameters.insert(parameters.end(), param.begin(), param.end());
}

void Payload::add_param(const std::string& param) {
    add_param(byte_vector(param.begin(), param.end()));
}

byte_vector Payload::serialize() const {
    byte_vector buffer;
    buffer.reserve(sizeof(op_code) + parameters.size());

    uint16_t be_op_code = htons(op_code);
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&be_op_code), reinterpret_cast<uint8_t*>(&be_op_code) + sizeof(be_op_code));
    buffer.insert(buffer.end(), parameters.begin(), parameters.end());

    return buffer;
}

Payload Payload::deserialize(const byte_vector& data) {
    if (data.size() < sizeof(OpCode)) {
        throw RuntimeError("Data too small to be a valid payload.");
    }

    Payload payload;
    uint16_t be_op_code;
    std::copy(data.begin(), data.begin() + sizeof(OpCode), reinterpret_cast<uint8_t*>(&be_op_code));
    payload.op_code = ntohs(be_op_code);

    payload.parameters.assign(data.begin() + sizeof(OpCode), data.end());

    return payload;
}


// --- Payload::ParamParser ---

Payload::ParamParser::ParamParser(const byte_vector& params) : params_data(params) {}

bool Payload::ParamParser::next_param(byte_vector& out_param) {
    if (offset + sizeof(uint16_t) > params_data.size()) {
        return false; // Not enough data for length prefix
    }

    uint16_t be_len;
    std::copy(params_data.begin() + offset, params_data.begin() + offset + sizeof(uint16_t), reinterpret_cast<uint8_t*>(&be_len));
    uint16_t len = ntohs(be_len);
    offset += sizeof(uint16_t);

    if (offset + len > params_data.size()) {
        // Reset offset to prevent further reads on corrupted data
        offset = params_data.size();
        return false; // Not enough data for the parameter itself
    }

    out_param.assign(params_data.begin() + offset, params_data.begin() + offset + len);
    offset += len;
    return true;
}

bool Payload::ParamParser::next_param(std::string& out_param) {
    byte_vector vec;
    if (next_param(vec)) {
        out_param.assign(vec.begin(), vec.end());
        return true;
    }
    return false;
}

} // namespace ObscuraProto
