#include "obscuraproto/rate_limiter.hpp"

namespace ObscuraProto {

    RateLimiter::RateLimiter(const RateLimitConfig& config) : config_(config) {
    }

    // --- SlidingWindow helpers ---

    void RateLimiter::SlidingWindow::add(int64_t now_ms) {
        timestamps_ms.push_back(now_ms);
    }

    size_t RateLimiter::SlidingWindow::count_last(int64_t now_ms, int64_t window_ms) const {
        if (window_ms == 0) {
            return 0;  // unlimited
        }
        int64_t cutoff = now_ms - window_ms;
        size_t count = 0;
        for (auto it = timestamps_ms.rbegin(); it != timestamps_ms.rend(); ++it) {
            if (*it >= cutoff) {
                ++count;
            } else {
                break;
            }
        }
        return count;
    }

    void RateLimiter::SlidingWindow::clean(int64_t now_ms, int64_t window_ms) {
        if (window_ms == 0) {
            timestamps_ms.clear();
            return;
        }
        int64_t cutoff = now_ms - window_ms;
        while (!timestamps_ms.empty() && timestamps_ms.front() < cutoff) {
            timestamps_ms.erase(timestamps_ms.begin());
        }
    }

    // --- Clock helpers ---

    int64_t RateLimiter::now_ms() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(clock::now().time_since_epoch()).count();
    }

    int64_t RateLimiter::now_us() const {
        return std::chrono::duration_cast<std::chrono::microseconds>(clock::now().time_since_epoch()).count();
    }

    // --- Connection rate ---

    bool RateLimiter::check_connection_rate(const std::string& ip) {
        if (!config_.enabled || config_.connections_per_minute == 0) {
            return true;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto& state = per_ip_[ip];
        size_t recent = state.connections.count_last(now_ms(), 60000);
        return recent < config_.connections_per_minute;
    }

    void RateLimiter::record_connection(const std::string& ip) {
        if (!config_.enabled) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto& state = per_ip_[ip];
        state.connections.add(now_ms());
    }

    // --- Handshake rate ---

    bool RateLimiter::check_handshake_rate(const std::string& ip) {
        if (!config_.enabled || config_.handshake_attempts_per_minute == 0) {
            return true;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto& state = per_ip_[ip];
        size_t recent = state.handshakes.count_last(now_ms(), 60000);
        return recent < config_.handshake_attempts_per_minute;
    }

    void RateLimiter::record_handshake(const std::string& ip) {
        if (!config_.enabled) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto& state = per_ip_[ip];
        state.handshakes.add(now_ms());
    }

    // --- Message rate ---

    bool RateLimiter::check_message_rate(uint64_t conn_id) {
        if (!config_.enabled || config_.messages_per_second == 0) {
            return true;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = message_buckets_.find(conn_id);
        if (it == message_buckets_.end()) {
            return true;  // not registered yet, will be created on record_message
        }
        int64_t now = now_us();
        auto& bucket = it->second;

        // Refill
        double elapsed_s = static_cast<double>(now - bucket.last_refill_us) / 1000000.0;
        bucket.tokens =
            std::min(bucket.tokens + elapsed_s * config_.messages_per_second,
                     static_cast<double>(config_.burst_size > 0 ? config_.burst_size : config_.messages_per_second));
        bucket.last_refill_us = now;

        return bucket.tokens >= 1.0;
    }

    void RateLimiter::record_message(uint64_t conn_id) {
        if (!config_.enabled) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = message_buckets_.find(conn_id);
        int64_t now = now_us();
        if (it == message_buckets_.end()) {
            TokenBucket bucket;
            bucket.tokens =
                static_cast<double>(config_.burst_size > 0 ? config_.burst_size : config_.messages_per_second);
            bucket.last_refill_us = now;
            if (bucket.tokens > 0) {
                bucket.tokens -= 1.0;
            }
            message_buckets_[conn_id] = bucket;
        } else {
            auto& bucket = it->second;
            double elapsed_s = static_cast<double>(now - bucket.last_refill_us) / 1000000.0;
            bucket.tokens = std::min(
                bucket.tokens + elapsed_s * config_.messages_per_second,
                static_cast<double>(config_.burst_size > 0 ? config_.burst_size : config_.messages_per_second));
            bucket.last_refill_us = now;
            if (bucket.tokens >= 1.0) {
                bucket.tokens -= 1.0;
            }
            // If tokens went negative, message was beyond rate — we still record but tokens stay negative
        }
    }

    // --- Active connection limits ---

    bool RateLimiter::check_active_connections(const std::string& ip) const {
        if (!config_.enabled) {
            return true;
        }
        bool ip_ok = true;
        bool total_ok = true;

        if (config_.connections_per_minute > 0) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = per_ip_.find(ip);
            if (it != per_ip_.end()) {
                ip_ok = it->second.active_connections < config_.connections_per_minute;
            }
        }

        if (config_.messages_per_second > 0) {
            total_ok = false;
        }

        return ip_ok && total_ok;
    }

    uint64_t RateLimiter::register_connection(const std::string& ip) {
        total_connections_.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t conn_id = next_conn_id_++;
        per_ip_[ip].active_connections++;
        conn_to_ip_[conn_id] = ip;
        return conn_id;
    }

    void RateLimiter::unregister_connection(uint64_t conn_id, const std::string& ip) {
        total_connections_.fetch_sub(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(mutex_);
        auto ip_it = per_ip_.find(ip);
        if (ip_it != per_ip_.end() && ip_it->second.active_connections > 0) {
            ip_it->second.active_connections--;
        }
        conn_to_ip_.erase(conn_id);
        message_buckets_.erase(conn_id);
    }

    // --- Cleanup ---

    void RateLimiter::cleanup() {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = now_ms();
        for (auto it = per_ip_.begin(); it != per_ip_.end();) {
            auto& state = it->second;
            state.connections.clean(now, 60000);
            state.handshakes.clean(now, 60000);
            if (state.active_connections == 0 && state.connections.timestamps_ms.empty() &&
                state.handshakes.timestamps_ms.empty()) {
                it = per_ip_.erase(it);
            } else {
                ++it;
            }
        }
    }

}  // namespace ObscuraProto
