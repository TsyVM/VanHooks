#pragma once

/**
 * vh/vigil/net_aware.vh — Anti-cheat network traffic awareness
 *
 * AC engines communicate with their backend servers for:
 *
 *   * **Heartbeat / keep-alive** — periodic pings proving the client is alive
 *   * **Telemetry upload** — scan results, memory hashes, module lists
 *   * **Ban verdict download** — server-side decisions pushed to client
 *   * **Signature updates** — fresh detection signatures from CDN
 *   * **Screenshot upload** — captured frames sent for manual review
 *
 * This module identifies AC network traffic by destination (known AC
 * server domains/IPs) and by packet pattern (payload structure, timing).
 * It does NOT modify, block, or replay traffic — awareness only.
 *
 * Builds on the VanHooks net layer (VH_ENABLE_NET) for packet capture
 * when available, but also works standalone via Winsock hooks.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_NET_AWARE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vh::ac::net_aware {

// ─────────────────────────────────────────────────────────────────────────────
//  Known AC server endpoints
// ─────────────────────────────────────────────────────────────────────────────

struct Endpoint {
    std::string_view    domain;         // e.g. "easyanticheat.net"
    std::string_view    description;    // e.g. "EAC telemetry"
    ac::Engine          engine;
    bool                is_telemetry;   // uploads scan data
    bool                is_heartbeat;   // keep-alive traffic
    bool                is_update;      // signature/config download
};

/// All known AC server endpoints.
VH_API std::span<const Endpoint> known_endpoints() noexcept;

/// Filter to endpoints for a specific engine.
VH_API std::vector<Endpoint> endpoints_for(ac::Engine engine) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  DNS awareness
// ─────────────────────────────────────────────────────────────────────────────

struct DnsQuery {
    std::string     domain;
    uint64_t        timestamp_ms;
    uint64_t        caller_rip;
    std::string     caller_module;
    ac::Engine      matched_engine;     // Engine::Unknown if not AC
};

/// Check if a domain belongs to a known AC endpoint.
VH_API ac::Engine classify_domain(std::string_view domain) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Traffic classification
// ─────────────────────────────────────────────────────────────────────────────

enum class TrafficKind : uint8_t {
    Heartbeat,          // periodic keep-alive
    TelemetrySend,      // scan results / module lists sent to server
    BanCheck,           // verdict request or response
    SignatureUpdate,    // detection signature download
    ScreenshotUpload,   // captured screenshot sent to server
    ConfigPull,         // configuration / policy download
    Unknown,
};

struct TrafficEvent {
    TrafficKind     kind;
    ac::Engine      engine;
    std::string     destination;        // IP:port or domain
    uint32_t        payload_size;
    uint64_t        timestamp_ms;
    bool            is_encrypted;       // TLS or custom encryption
};

using TrafficCallback = void(*)(const TrafficEvent& event);

// ─────────────────────────────────────────────────────────────────────────────
//  Monitoring
// ─────────────────────────────────────────────────────────────────────────────

/// Start monitoring AC network traffic.
/// Uses Winsock hooks (send/WSASend/connect) to observe outbound traffic.
VH_API vh::Result<void> monitor_start(TrafficCallback cb) noexcept;

/// Stop monitoring.
VH_API void monitor_stop() noexcept;

/// Is monitoring active?
VH_API bool monitor_active() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Traffic statistics
// ─────────────────────────────────────────────────────────────────────────────

struct TrafficStats {
    uint64_t    total_bytes_sent = 0;
    uint64_t    total_bytes_recv = 0;
    uint32_t    heartbeat_count = 0;
    uint32_t    telemetry_count = 0;
    uint32_t    screenshot_count = 0;
    uint64_t    last_heartbeat_ms = 0;
    uint64_t    last_telemetry_ms = 0;
};

/// Get cumulative traffic statistics since monitor_start().
VH_API TrafficStats stats() noexcept;

} // namespace vh::ac::net_aware
