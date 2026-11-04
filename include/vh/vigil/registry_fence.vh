#pragma once

/**
 * vh/vigil/registry_fence.vh — Registry access awareness
 *
 * Anti-cheat engines query specific registry keys to:
 *
 *   * Fingerprint the machine (MachineGuid, ProductId, InstallDate)
 *   * Detect cheat tools (known registry artifacts)
 *   * Detect VMs/sandboxes (VirtualBox, VMware, Hyper-V keys)
 *   * Track game integrity (install paths, configuration)
 *
 * This module provides:
 *
 *   1. A database of registry paths each AC engine is known to query.
 *   2. Real-time monitoring of RegQueryValueEx / RegOpenKeyEx calls
 *      to detect when the AC is reading sensitive keys.
 *   3. Classification of each query as HWID / cheat-detect / VM-detect / other.
 *
 * All operations are read-only awareness.  This module never modifies
 * registry values or blocks AC queries.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_REGISTRY_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vh::ac::registry_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Query classification
// ─────────────────────────────────────────────────────────────────────────────

enum class QueryPurpose : uint8_t {
    HwidFingerprint,    // machine ID collection (MachineGuid, etc.)
    CheatDetection,     // known cheat tool registry artifacts
    VmDetection,        // VirtualBox / VMware / Hyper-V / QEMU keys
    GameIntegrity,      // game install path, config validation
    SystemInfo,         // general system information gathering
    Unknown,
};

// ─────────────────────────────────────────────────────────────────────────────
//  Known registry paths per engine
// ─────────────────────────────────────────────────────────────────────────────

struct KnownPath {
    std::string_view    path;       // full registry path (e.g. "HKLM\\SOFTWARE\\...")
    std::string_view    value;      // value name (empty = key existence check)
    QueryPurpose        purpose;
    uint32_t            engines;    // bitmask of Engine values that query this
};

/// Enumerate all known AC registry paths.
VH_API std::span<const KnownPath> known_paths() noexcept;

/// Filter known paths to those relevant to a specific engine.
VH_API std::vector<KnownPath> paths_for(ac::Engine engine) noexcept;

/// Filter known paths by purpose.
VH_API std::vector<KnownPath> paths_by_purpose(QueryPurpose purpose) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Real-time monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct RegistryHit {
    std::string     path;           // full registry path accessed
    std::string     value_name;     // value name (empty for key open)
    QueryPurpose    purpose;        // classified purpose
    uint64_t        caller_rip;     // return address
    std::string     caller_module;  // module containing caller
    bool            is_ac;          // true if caller is a known AC module
};

using RegistryCallback = void(*)(const RegistryHit& hit);

/// Start monitoring registry access for AC-relevant keys.
VH_API vh::Result<void> monitor_start(RegistryCallback cb) noexcept;

/// Stop monitoring.
VH_API void monitor_stop() noexcept;

/// Is monitoring active?
VH_API bool monitor_active() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Quick checks
// ─────────────────────────────────────────────────────────────────────────────

/// Does the detected AC query VM-detection registry keys?
VH_API bool ac_checks_vm_registry() noexcept;

/// Does the detected AC fingerprint via registry (HWID)?
VH_API bool ac_fingerprints_via_registry() noexcept;

/// Does the detected AC scan for cheat tool registry artifacts?
VH_API bool ac_scans_cheat_artifacts() noexcept;

} // namespace vh::ac::registry_fence
