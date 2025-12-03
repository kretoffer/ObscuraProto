#include "obscuraproto/version.hpp"

namespace ObscuraProto {

    std::optional<Version> VersionNegotiator::negotiate(const std::vector<Version>& client_versions,
                                                        const std::vector<Version>& server_versions) {
        for (const auto& client_version : client_versions) {
            for (const auto& server_version : server_versions) {
                if (client_version == server_version) {
                    return client_version;
                }
            }
        }
        return std::nullopt;
    }

}  // namespace ObscuraProto
