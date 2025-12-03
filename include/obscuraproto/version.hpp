#ifndef OBSCURAPROTO_VERSION_HPP
#define OBSCURAPROTO_VERSION_HPP

#include <cstdint>
#include <vector>

namespace ObscuraProto {

    // Protocol version is represented as a 16-bit integer.
    // For example, version 1.0 is 0x0100, 1.1 is 0x0101.
    using Version = uint16_t;

    namespace Versions {
        constexpr Version V1_0 = 0x0100;
    }

    // A list of supported versions.
    const std::vector<Version> SUPPORTED_VERSIONS = {Versions::V1_0};

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_VERSION_HPP
