#include "obscuraproto/rate_limiter.hpp"

#include <gtest/gtest.h>

namespace ObscuraProto {
    namespace {

        TEST(RateLimiterTest, AllowsMessagesWithinLimit) {
            RateLimitConfig cfg = RateLimitConfig::defaults();
            cfg.messages_per_second = 10;
            cfg.burst_size = 10;
            RateLimiter limiter(cfg);

            uint64_t conn = 1;
            for (int i = 0; i < 10; ++i) {
                EXPECT_TRUE(limiter.check_message_rate(conn));
                limiter.record_message(conn);
            }
        }

        TEST(RateLimiterTest, BlocksMessagesOverLimit) {
            RateLimitConfig cfg = RateLimitConfig::defaults();
            cfg.messages_per_second = 5;
            cfg.burst_size = 5;
            RateLimiter limiter(cfg);

            uint64_t conn = 1;
            for (int i = 0; i < 5; ++i) {
                limiter.record_message(conn);
            }
            // Next message should be rate limited
            EXPECT_FALSE(limiter.check_message_rate(conn));
        }

        TEST(RateLimiterTest, BlocksExcessiveHandshakes) {
            RateLimitConfig cfg = RateLimitConfig::defaults();
            cfg.handshake_attempts_per_minute = 3;
            RateLimiter limiter(cfg);

            std::string ip = "10.0.0.1";
            EXPECT_TRUE(limiter.check_handshake_rate(ip));
            limiter.record_handshake(ip);
            EXPECT_TRUE(limiter.check_handshake_rate(ip));
            limiter.record_handshake(ip);
            EXPECT_TRUE(limiter.check_handshake_rate(ip));
            limiter.record_handshake(ip);
            EXPECT_FALSE(limiter.check_handshake_rate(ip));
        }

        TEST(RateLimiterTest, UnlimitedWhenZero) {
            RateLimitConfig cfg = RateLimitConfig::defaults();
            cfg.messages_per_second = 0;
            cfg.handshake_attempts_per_minute = 0;
            cfg.connections_per_minute = 0;
            RateLimiter limiter(cfg);

            uint64_t conn = 1;
            for (int i = 0; i < 1000; ++i) {
                EXPECT_TRUE(limiter.check_message_rate(conn));
                limiter.record_message(conn);
            }

            std::string ip = "10.0.0.1";
            for (int i = 0; i < 1000; ++i) {
                EXPECT_TRUE(limiter.check_handshake_rate(ip));
                limiter.record_handshake(ip);
            }
        }

        TEST(RateLimiterTest, RespectsBurstSize) {
            RateLimitConfig cfg = RateLimitConfig::defaults();
            cfg.messages_per_second = 100;
            cfg.burst_size = 3;
            RateLimiter limiter(cfg);

            uint64_t conn = 1;
            // Should allow burst_size messages
            for (int i = 0; i < 3; ++i) {
                EXPECT_TRUE(limiter.check_message_rate(conn));
                limiter.record_message(conn);
            }
            // Fourth should be blocked
            EXPECT_FALSE(limiter.check_message_rate(conn));
        }

        TEST(RateLimiterTest, UnlimitedWhenDisabled) {
            RateLimitConfig cfg;
            cfg.enabled = false;
            cfg.messages_per_second = 1;
            cfg.handshake_attempts_per_minute = 1;
            cfg.connections_per_minute = 1;
            RateLimiter limiter(cfg);

            uint64_t conn = 1;
            for (int i = 0; i < 100; ++i) {
                EXPECT_TRUE(limiter.check_message_rate(conn));
                limiter.record_message(conn);
            }

            std::string ip = "10.0.0.1";
            for (int i = 0; i < 100; ++i) {
                EXPECT_TRUE(limiter.check_handshake_rate(ip));
                limiter.record_handshake(ip);
            }
        }

        TEST(RateLimiterTest, ActiveConnectionsTracking) {
            RateLimitConfig cfg = RateLimitConfig::defaults();
            RateLimiter limiter(cfg);

            std::string ip1 = "10.0.0.1";
            std::string ip2 = "10.0.0.2";

            uint64_t c1 = limiter.register_connection(ip1);
            EXPECT_EQ(limiter.active_total(), 1u);
            uint64_t c2 = limiter.register_connection(ip1);
            EXPECT_EQ(limiter.active_total(), 2u);
            uint64_t c3 = limiter.register_connection(ip2);
            EXPECT_EQ(limiter.active_total(), 3u);

            limiter.unregister_connection(c1, ip1);
            EXPECT_EQ(limiter.active_total(), 2u);
            limiter.unregister_connection(c2, ip1);
            EXPECT_EQ(limiter.active_total(), 1u);
            limiter.unregister_connection(c3, ip2);
            EXPECT_EQ(limiter.active_total(), 0u);
        }

    }  // namespace
}  // namespace ObscuraProto
