#pragma once

/**
 * vh/vigil/timing_fence.vh — Timing integrity awareness
 *
 * Anti-cheat engines use timing checks to detect:
 *
 *   * **Hook presence** — RDTSC before/after a call; abnormal delta = hooked
 *   * **VM execution** — VM exit overhead inflates RDTSC/CPUID timing
 *   * **Speedhacks** — manipulated QPC/GetTickCount values
 *   * **Sleep skipping** — Sleep(N) returning too quickly
 *   * **Breakpoints** — single-step flag timing overhead
 *
 * Timing sources ACs use:
 *
 *   * `RDTSC` / `RDTSCP` — raw TSC counter
 *   * `QueryPerformanceCounter` — high-resolution OS timer
 *   * `GetTickCount64` — wall-clock milliseconds
 *   * `timeGetTime` — multimedia timer
 *   * `NtQueryPerformanceCounter` — kernel QPC
 *   * `KeQueryPerformanceCounter` (kernel) — ring-0 timing
 *
 * This module provides:
 *
 *   1. Per-engine timing check profiles (which sources, what thresholds).
 *   2. Baseline timing calibration (normal overhead for RDTSC/QPC).
 *   3. Anomaly detection — flag when our own timing looks abnormal.
 *
 * Cross-platform: Windows + Linux (RDTSC available on x86).
 *
 * Requires: VH_ENABLE_TIMING_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string_view>

namespace vh::ac::timing_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Timing sources
// ─────────────────────────────────────────────────────────────────────────────

enum class TimingSource : uint32_t {
    RDTSC               = 1u << 0,
    RDTSCP              = 1u << 1,
    QPC                 = 1u << 2,
    GetTickCount        = 1u << 3,
    TimeGetTime         = 1u << 4,
    NtQueryPerfCounter  = 1u << 5,
    CpuidSerialise      = 1u << 6,  // CPUID used as serialising fence before RDTSC
};

/// Bitmask of timing sources used by a specific AC engine.
VH_API uint32_t sources_used_by(ac::Engine engine) noexcept;

/// Human-readable name for a timing source.
VH_API std::string_view source_name(TimingSource source) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Calibration
// ─────────────────────────────────────────────────────────────────────────────

struct Calibration {
    uint64_t    rdtsc_overhead;         // cycles for a bare RDTSC pair
    uint64_t    qpc_overhead_ns;        // nanoseconds for a bare QPC pair
    uint64_t    cpuid_rdtsc_overhead;   // cycles for CPUID+RDTSC pair
    uint64_t    tsc_frequency_mhz;      // estimated TSC frequency
    bool        rdtscp_available;       // RDTSCP instruction supported
    bool        invariant_tsc;          // invariant TSC bit set
};

/// Run calibration: measures native timing overhead (100 iterations, median).
VH_API Calibration calibrate() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Anomaly detection
// ─────────────────────────────────────────────────────────────────────────────

struct TimingCheck {
    uint64_t    measured_cycles;     // actual delta
    uint64_t    expected_max;        // threshold for this operation
    bool        anomalous;           // measured > expected_max
    double      ratio;               // measured / expected_max
};

/// Check if a RDTSC delta looks anomalous (e.g. hook or VM overhead).
/// expected_cycles: calibrated baseline for the measured operation.
VH_API TimingCheck check_rdtsc(uint64_t start, uint64_t end,
                                uint64_t expected_cycles) noexcept;

/// Measure the overhead of calling a function pointer via RDTSC sandwich.
/// Returns the cycle count for the call.
VH_API uint64_t measure_call_cycles(void(*fn)()) noexcept;

/// Are we likely running under a hypervisor based on timing?
/// Uses calibration data if available.
VH_API bool timing_suggests_vm() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine timing thresholds
// ─────────────────────────────────────────────────────────────────────────────

struct EngineThresholds {
    ac::Engine  engine;
    uint64_t    rdtsc_max_cycles;       // max RDTSC delta for a "clean" call
    uint64_t    qpc_max_ns;             // max QPC delta in nanoseconds
    uint32_t    sleep_tolerance_pct;    // % tolerance on Sleep accuracy
};

/// Get the timing thresholds a specific AC engine uses.
VH_API vh::Result<EngineThresholds> thresholds_for(ac::Engine engine) noexcept;

} // namespace vh::ac::timing_fence
