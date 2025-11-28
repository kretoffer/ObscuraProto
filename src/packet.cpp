#include "obscuraproto/packet.hpp"
#include "obscuraproto/errors.hpp"
#include <arpa/inet.h> // For htons, ntohs, htonl, ntohl

namespace ObscuraProto {

// --- Payload ---

byte_vector Payload::serialize() const {
    byte_vector buffer;
    buffer.reserve(sizeof(op_code) + parameters.size());

    uint16_t be_op_code = htons(op_code);
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&be_op_code), reinterpret_cast<const uint8_t*>(&be_op_code) + sizeof(be_op_code));
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

// --- PayloadBuilder ---

PayloadBuilder::PayloadBuilder(Payload::OpCode op_code) {
    payload_.op_code = op_code;
}

PayloadBuilder& PayloadBuilder::add_param(const byte_vector& param) {
    if (param.size() > UINT16_MAX) {
        throw RuntimeError("Parameter size exceeds maximum of 65535 bytes.");
    }
    uint16_t len = static_cast<uint16_t>(param.size());
    uint16_t be_len = htons(len);

    payload_.parameters.insert(payload_.parameters.end(), reinterpret_cast<uint8_t*>(&be_len), reinterpret_cast<uint8_t*>(&be_len) + sizeof(be_len));
    payload_.parameters.insert(payload_.parameters.end(), param.begin(), param.end());
    return *this;
}

PayloadBuilder& PayloadBuilder::add_param(const std::string& param) {
    return add_param(byte_vector(param.begin(), param.end()));
}

PayloadBuilder& PayloadBuilder::add_param(const char* param) {
    return add_param(std::string(param));
}

PayloadBuilder& PayloadBuilder::add_param(bool param) {
    return add_param(static_cast<uint8_t>(param ? 1 : 0));
}

PayloadBuilder& PayloadBuilder::add_param(int8_t param) {
    byte_vector vec(sizeof(param));
    vec[0] = param;
    return add_param(vec);
}

PayloadBuilder& PayloadBuilder::add_param(uint8_t param) {
    byte_vector vec(sizeof(param));
    vec[0] = param;
    return add_param(vec);
}

PayloadBuilder& PayloadBuilder::add_param(int16_t param) {
    int16_t be_param = htons(param);
    byte_vector vec(sizeof(be_param));
    std::copy(reinterpret_cast<uint8_t*>(&be_param), reinterpret_cast<uint8_t*>(&be_param) + sizeof(be_param), vec.begin());
    return add_param(vec);
}

PayloadBuilder& PayloadBuilder::add_param(uint16_t param) {
    uint16_t be_param = htons(param);
    byte_vector vec(sizeof(be_param));
    std::copy(reinterpret_cast<uint8_t*>(&be_param), reinterpret_cast<uint8_t*>(&be_param) + sizeof(be_param), vec.begin());
    return add_param(vec);
}

PayloadBuilder& PayloadBuilder::add_param(int32_t param) {
    int32_t be_param = htonl(param);
    byte_vector vec(sizeof(be_param));
    std::copy(reinterpret_cast<uint8_t*>(&be_param), reinterpret_cast<uint8_t*>(&be_param) + sizeof(be_param), vec.begin());
    return add_param(vec);
}

PayloadBuilder& PayloadBuilder::add_param(uint32_t param) {
    uint32_t be_param = htonl(param);
    byte_vector vec(sizeof(be_param));
    std::copy(reinterpret_cast<uint8_t*>(&be_param), reinterpret_cast<uint8_t*>(&be_param) + sizeof(be_param), vec.begin());
    return add_param(vec);
}

PayloadBuilder& PayloadBuilder::add_param(int64_t param) {
    int64_t be_param = detail::htonll_local(param);
    byte_vector vec(sizeof(be_param));
    std::copy(reinterpret_cast<uint8_t*>(&be_param), reinterpret_cast<uint8_t*>(&be_param) + sizeof(be_param), vec.begin());
    return add_param(vec);
}

PayloadBuilder& PayloadBuilder::add_param(uint64_t param) {
    uint64_t be_param = detail::htonll_local(param);
    byte_vector vec(sizeof(be_param));
    std::copy(reinterpret_cast<uint8_t*>(&be_param), reinterpret_cast<uint8_t*>(&be_param) + sizeof(be_param), vec.begin());
    return add_param(vec);
}

PayloadBuilder& PayloadBuilder::add_param(float param) {
    byte_vector vec(sizeof(param));
    std::copy(reinterpret_cast<uint8_t*>(&param), reinterpret_cast<uint8_t*>(&param) + sizeof(param), vec.begin());
    return add_param(vec);
}

PayloadBuilder& PayloadBuilder::add_param(double param) {
    byte_vector vec(sizeof(param));
    std::copy(reinterpret_cast<uint8_t*>(&param), reinterpret_cast<uint8_t*>(&param) + sizeof(param), vec.begin());
    return add_param(vec);
}


Payload PayloadBuilder::build() {
    return std::move(payload_);
}


// --- PayloadReader ---

PayloadReader::PayloadReader(const Payload& payload) : params_data_(payload.parameters) {}

bool PayloadReader::has_more() const {
    return offset_ < params_data_.size();
}

byte_vector PayloadReader::read_param_bytes() {
    if (offset_ + sizeof(uint16_t) > params_data_.size()) {
        throw RuntimeError("Invalid payload data: not enough data for parameter length.");
    }

    uint16_t be_len;
    std::copy(params_data_.begin() + offset_, params_data_.begin() + offset_ + sizeof(uint16_t), reinterpret_cast<uint8_t*>(&be_len));
    uint16_t len = ntohs(be_len);
    offset_ += sizeof(uint16_t);

    if (offset_ + len > params_data_.size()) {
        offset_ = params_data_.size(); // Prevent further reads
        throw RuntimeError("Invalid payload data: not enough data for parameter content.");
    }

    byte_vector out_param(params_data_.begin() + offset_, params_data_.begin() + offset_ + len);
    offset_ += len;
    return out_param;
}

} // namespace ObscuraProto