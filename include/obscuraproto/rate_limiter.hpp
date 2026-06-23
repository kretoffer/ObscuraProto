#ifndef OBSCURAPROTO_RATE_LIMITER_HPP
#define OBSCURAPROTO_RATE_LIMITER_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "config.hpp"

namespace ObscuraProto {

    class RateLimiter {
    public:
        explicit RateLimiter(const RateLimitConfig& config);

        // --- Connection rate (sliding window per IP) ---
        bool check_connection_rate(const std::string& ip);
        void record_connection(const std::string& ip);

        // --- Handshake rate (sliding window per IP) ---
        bool check_handshake_rate(const std::string& ip);
        void record_handshake(const std::string& ip);

        // --- Message rate (token bucket per connection) ---
        bool check_message_rate(uint64_t conn_id);
        void record_message(uint64_t conn_id);

        // --- Active connection limits ---
        bool check_active_connections(const std::string& ip) const;
        uint64_t register_connection(const std::string& ip);
        void unregister_connection(uint64_t conn_id, const std::string& ip);
        uint32_t active_total() const {
            return total_connections_.load();
        }

        // --- Cleanup ---
        void cleanup();

    private:
        using clock = std::chrono::steady_clock;

        struct SlidingWindow {
            std::vector<int64_t> timestamps_ms;
            void add(int64_t now_ms);
            size_t count_last(int64_t now_ms, int64_t window_ms) const;
            void clean(int64_t now_ms, int64_t window_ms);
        };

        struct TokenBucket {
            double tokens;
            int64_t last_refill_us;
        };

        struct PerIPState {
            SlidingWindow connections;
            SlidingWindow handshakes;
            uint32_t active_connections = 0;
        };

        RateLimitConfig config_;
        mutable std::mutex mutex_;

        std::unordered_map<std::string, PerIPState> per_ip_;
        std::unordered_map<uint64_t, TokenBucket> message_buckets_;
        std::unordered_map<uint64_t, std::string> conn_to_ip_;

        std::atomic<uint32_t> total_connections_{0};
        uint64_t next_conn_id_ = 0;

        int64_t now_ms() const;
        int64_t now_us() const;
    };

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_RATE_LIMITER_HPP
