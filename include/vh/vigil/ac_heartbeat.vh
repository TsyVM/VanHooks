#pragma once

/**
 * vh/vigil/ac_heartbeat.vh — Anti-cheat heartbeat protocol awareness
 *
 * Most kernel-mode anti-cheats maintain a periodic heartbeat between
 * the user-mode client component and either the kernel driver or a
 * remote server.  If the heartbeat stops or arrives with unexpected
 * timing, the AC flags the session.
 *
 * This module intercepts and monitors heartbeat traffic for known
 * engines so VanHooks operations can be timed to avoid scan windows
 * and heartbeat verification cycles.
 *
 * Capabilities
 * ────────────
 *
 *   * **Heartbeat monitoring** — observe the AC's keepalive cadence
 *     (interval, jitter, payload pattern) without interfering.
 *
 *   * **Scan-window detection** — identify the time windows when the
 *     AC performs its integrity scans (typically immediately after a
 *     heartbeat acknowledgement).
 *
 *   * **Safe-window notification** — signal when VanHooks operations
 *     (hook installation, memory writes, module loads) can proceed
 *     with minimal detection risk.
 *
 *   * **Heartbeat continuity** — if the AC client is suspended or
 *     its thread is hijacked, maintain heartbeat continuity to prevent
 *     timeout-based detection.
 *
 * Platform: Windows.
 *
 * Requires: VH_ENABLE_AC_HEARTBEAT  (CMake option, default ON)
 *           VH_ENABLE_AC_PROFILE    (dependency — engine detection)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <chrono>
#include <cstdint>
#include <functional>

namespace vh::ac::heartbeat {

// ─────────────────────────────────────────────────────────────────────────────
//  Heartbeat observation
// ─────────────────────────────────────────────────────────────────────────────

struct HeartbeatInfo {
    ac::Engine  engine;
    uint32_t    interval_ms;        // observed mean interval
    uint32_t    jitter_ms;          // observed ±jitter
    uint32_t    scan_delay_ms;      // delay from heartbeat ACK to scan start
    uint32_t    scan_duration_ms;   // typical scan window length
    uint64_t    last_beat_tick;     // QPC tick of last observed heartbeat
    uint32_t    beats_observed;     // total beats seen since monitor_start
};

/// Begin monitoring the heartbeat for the given engine.
/// Returns Unsupported if the engine has no known heartbeat protocol.
VH_API vh::Result<void> monitor_start(ac::Engine engine) noexcept;

/// Stop monitoring.  Safe to call if not started.
VH_API void monitor_stop() noexcept;

/// Current heartbeat state.  Only valid while monitoring.
VH_API HeartbeatInfo info() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Safe-window API
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true when the current moment is outside the AC's known
/// scan window — meaning hook operations are least likely to be caught.
VH_API bool in_safe_window() noexcept;

/// Block until the next safe window opens, or until timeout_ms expires.
/// Returns the estimated duration of the safe window in milliseconds.
VH_API vh::Result<uint32_t> wait_for_safe_window(uint32_t timeout_ms = 5000) noexcept;

/// Estimated milliseconds until the next scan window begins.
VH_API uint32_t ms_until_next_scan() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Callback API
// ─────────────────────────────────────────────────────────────────────────────

enum class Event : uint8_t {
    HeartbeatSent,          // AC sent a heartbeat
    HeartbeatAcked,         // Server/driver acknowledged
    ScanWindowOpen,         // AC started scanning
    ScanWindowClose,        // AC finished scanning
    SafeWindowOpen,         // Safe to operate
    HeartbeatMissed,        // Expected beat did not arrive (AC may be suspended)
};

using Callback = std::function<void(Event, const HeartbeatInfo&)>;

/// Register a callback for heartbeat events.  Returns an ID for unregister.
VH_API uint32_t on_event(Callback cb) noexcept;

/// Remove a previously registered callback.
VH_API void remove_callback(uint32_t id) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Heartbeat continuity (source license required for implementation)
// ─────────────────────────────────────────────────────────────────────────────

/// If the AC's heartbeat thread is suspended (e.g. during injection),
/// this maintains heartbeat continuity by replaying the expected
/// keepalive pattern.  Requires deep engine knowledge per-AC.
VH_API vh::Result<void> maintain_continuity(ac::Engine engine) noexcept;

/// Stop continuity maintenance and let the AC resume its own heartbeat.
VH_API void release_continuity() noexcept;

} // namespace vh::ac::heartbeat
