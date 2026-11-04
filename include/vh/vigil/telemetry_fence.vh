#pragma once

/**
 * vh/vigil/telemetry_fence.vh — Gameplay telemetry awareness
 *
 * Anti-cheat engines collect behavioural telemetry:
 *
 *   * Mouse movement patterns (acceleration, jitter, smoothness)
 *   * Input timing regularity (inhuman consistency detection)
 *   * Camera/view angle change rates
 *   * Action frequency histograms (clicks per second, key patterns)
 *   * Movement prediction vs actual comparison (aim snapping)
 *
 * This module provides:
 *
 *   1. Per-engine telemetry collection profiles.
 *   2. Telemetry metric awareness — what each engine collects.
 *   3. Collection timing awareness — when telemetry is sampled.
 *
 * Platform: cross-platform (awareness only, no OS-specific APIs).
 *
 * Requires: VH_ENABLE_TELEMETRY_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>

namespace vh::ac::telemetry_fence {

enum class TelemetryMetric : uint32_t {
    MouseVelocity       = 1u << 0,  // mouse movement speed
    MouseAcceleration   = 1u << 1,  // rate of speed change
    MouseJitter         = 1u << 2,  // micro-movement noise
    MouseSmoothing      = 1u << 3,  // suspiciously smooth curves
    InputTiming         = 1u << 4,  // time between inputs
    InputRegularity     = 1u << 5,  // inhuman consistency
    ViewAngleRate       = 1u << 6,  // camera rotation speed
    ViewAngleSnap       = 1u << 7,  // sudden angle changes (flick)
    ActionFrequency     = 1u << 8,  // actions per second histogram
    KeyHoldDuration     = 1u << 9,  // how long keys are held
    MovementPrediction  = 1u << 10, // predicted vs actual path
    ReactionTime        = 1u << 11, // stimulus-to-action latency
};

struct EngineProfile {
    ac::Engine      engine;
    uint32_t        metrics;        // bitmask of TelemetryMetric
    uint32_t        sample_rate_ms; // typical sampling interval
    bool            uploads_raw;    // sends raw samples to server
    bool            uses_ml;        // server-side ML analysis
};

/// Get the telemetry profile for a specific AC engine.
VH_API EngineProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of telemetry metrics a specific AC engine collects.
VH_API uint32_t metrics_by(ac::Engine engine) noexcept;

/// Whether the engine uses server-side ML for detection.
VH_API bool uses_ml(ac::Engine engine) noexcept;

} // namespace vh::ac::telemetry_fence
