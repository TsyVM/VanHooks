#pragma once

/**
 * vh/vigil/replay_fence.vh — Replay / demo recording awareness
 *
 * Anti-cheat engines record and replay gameplay for analysis:
 *
 *   * Server-side demo recording (Overwatch, VALORANT kill-cam)
 *   * Client input recording for statistical analysis
 *   * Replay-based manual and automated review
 *   * Movement delta compression and integrity checks
 *   * Replay file tampering detection
 *
 * This module provides:
 *
 *   1. Per-engine replay/recording profiles.
 *   2. Recording method awareness — what each engine captures.
 *   3. Replay analysis awareness — how replays are inspected.
 *
 * Platform: cross-platform (awareness only, no OS-specific APIs).
 *
 * Requires: VH_ENABLE_REPLAY_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>

namespace vh::ac::replay_fence {

enum class ReplayCheck : uint32_t {
    ServerSideRecord    = 1u << 0,  // server records full match
    ClientInputCapture  = 1u << 1,  // client logs raw inputs
    KillCamReplay       = 1u << 2,  // kill-cam/death-cam playback
    MovementDelta       = 1u << 3,  // compressed movement deltas
    InputIntegrity      = 1u << 4,  // input sequence hashing
    ReplayFileSign      = 1u << 5,  // replay file signatures
    AutomatedReview     = 1u << 6,  // automated replay analysis
    ManualReview        = 1u << 7,  // human reviewer system
    StatisticalReplay   = 1u << 8,  // statistical anomaly in replay
    NetworkDeltaCheck   = 1u << 9,  // network vs local delta compare
};

struct ReplayProfile {
    ac::Engine  engine;
    uint32_t    checks;             // bitmask of ReplayCheck
    bool        stores_server_side; // replays kept on server
    bool        player_accessible;  // players can view replays
    uint32_t    retention_days;     // approximate replay retention
};

/// Get the replay profile for a specific AC engine.
VH_API ReplayProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of replay checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

/// Whether the engine stores replays server-side.
VH_API bool stores_server_side(ac::Engine engine) noexcept;

} // namespace vh::ac::replay_fence
