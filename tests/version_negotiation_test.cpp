#include <gtest/gtest.h>

#include "obscuraproto/version.hpp"

using namespace ObscuraProto;

TEST(VersionNegotiationTest, SuccessfulNegotiation) {
    const std::vector<Version> client_versions = {Versions::V1_0};
    const std::vector<Version> server_versions = {Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Versions::V1_0);
}

// TEST(VersionNegotiationTest, FallbackNegotiation) {
//     // This test is not relevant when only one version exists.
//     // Re-enable when more versions are added.
//     const std::vector<Version> client_versions = {0x0101, Versions::V1_0};
//     const std::vector<Version> server_versions = {Versions::V1_0};

//     auto result = VersionNegotiator::negotiate(client_versions, server_versions);

//     ASSERT_TRUE(result.has_value());
//     EXPECT_EQ(*result, Versions::V1_0);
// }

TEST(VersionNegotiationTest, NoCommonVersion) {
    constexpr Version V_UNKNOWN = 0xFFFF;
    const std::vector<Version> client_versions = {V_UNKNOWN};
    const std::vector<Version> server_versions = {Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    EXPECT_FALSE(result.has_value());
}

// TEST(VersionNegotiationTest, ClientHasOlderVersion) {
//     // This test is not relevant when only one version exists.
//     // It's effectively the same as SuccessfulNegotiation.
//     const std::vector<Version> client_versions = {Versions::V1_0};
//     const std::vector<Version> server_versions = {0x0101, Versions::V1_0};

//     auto result = VersionNegotiator::negotiate(client_versions, server_versions);

//     ASSERT_TRUE(result.has_value());
//     EXPECT_EQ(*result, Versions::V1_0);
// }

TEST(VersionNegotiationTest, EmptyClientList) {
    const std::vector<Version> client_versions = {};
    const std::vector<Version> server_versions = {Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    EXPECT_FALSE(result.has_value());
}

TEST(VersionNegotiationTest, EmptyServerList) {
    const std::vector<Version> client_versions = {Versions::V1_0};
    const std::vector<Version> server_versions = {};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    EXPECT_FALSE(result.has_value());
}
