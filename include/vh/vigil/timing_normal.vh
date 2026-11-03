#pragma once
/**
 * VanHooks — Behavioral timing normalisation
 *
 * Inserts configurable jitter at hook call sites to match
 * baseline timing profiles.  Defeats ML-based detection that
 * flags anomalous call-frequency patterns from hooked functions.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::timing {

struct TimingConfig {
    uint32_t min_jitter_ns    = 0;
    uint32_t max_jitter_ns    = 500;
    bool     match_baseline   = true;
    uint32_t baseline_samples = 100;
};

VH_API Status init(const TimingConfig& cfg = {}) noexcept;
VH_API Status shutdown() noexcept;

VH_API void calibrate_baseline(void* target) noexcept;

VH_API void apply_jitter() noexcept;

VH_API void apply_jitter_ns(uint32_t min_ns, uint32_t max_ns) noexcept;

VH_API uint64_t last_jitter_ns() noexcept;

struct TimingStats {
    uint64_t total_calls     = 0;
    uint64_t total_jitter_ns = 0;
    double   avg_jitter_ns   = 0.0;
};

VH_API TimingStats stats() noexcept;

} // namespace vh::timing
