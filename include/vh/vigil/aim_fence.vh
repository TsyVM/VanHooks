#pragma once

/**
 * vh/vigil/aim_fence.vh — Aim analysis awareness
 *
 * Anti-cheat engines analyse aiming behaviour for anomalies:
 *
 *   * Pixel-perfect target tracking (aimbot signatures)
 *   * Inhuman snap angles and reaction times
 *   * Constant angular velocity (smoothing bot tell)
 *   * Recoil compensation patterns (perfect counter-spray)
 *   * Field-of-view cone adherence (aim-assist radius)
 *   * Target switching speed and prediction
 *
 * This module provides:
 *
 *   1. Per-engine aim-analysis profiles.
 *   2. Aim metric awareness — what each engine inspects.
 *   3. Detection method awareness — how engines classify aim.
 *
 * Platform: cross-platform (awareness only, no OS-specific APIs).
 *
 * Requires: VH_ENABLE_AIM_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>

namespace vh::ac::aim_fence {

enum class AimCheck : uint32_t {
    SnapDetection       = 1u << 0,  // sudden large angle changes to target
    TrackingAnalysis    = 1u << 1,  // smooth target-following accuracy
    RecoilCompensation  = 1u << 2,  // perfect counter-spray patterns
    AngularVelocity     = 1u << 3,  // constant rotation speed (bot tell)
    FOVConeAdherence    = 1u << 4,  // aim within specific FOV cone
    TargetSwitchSpeed   = 1u << 5,  // time between target acquisitions
    PredictionAccuracy  = 1u << 6,  // tracking moving targets too well
    ReactionTimeStats   = 1u << 7,  // statistical reaction time analysis
    SilentAimDetect     = 1u << 8,  // bullet trajectory != crosshair
    AimbotSignature     = 1u << 9,  // known aimbot movement patterns
    HeadshotRatio       = 1u << 10, // statistical headshot percentage
    FlickConsistency    = 1u << 11, // flick-shot timing uniformity
};

struct AimProfile {
    ac::Engine  engine;
    uint32_t    checks;             // bitmask of AimCheck
    bool        server_side;        // has server-side aim analysis
    bool        replay_analysis;    // analyses recorded gameplay
    bool        ml_classification;  // uses ML to classify aim
};

/// Get the aim analysis profile for a specific AC engine.
VH_API AimProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of aim checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

/// Whether the engine performs server-side aim analysis.
VH_API bool has_server_side(ac::Engine engine) noexcept;

} // namespace vh::ac::aim_fence
