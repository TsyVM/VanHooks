#pragma once

/**
 * vh/vigil/wmi_fence.vh — WMI query awareness
 *
 * Anti-cheat engines use WMI (Windows Management Instrumentation) to
 * collect hardware information, detect virtualisation, and fingerprint
 * the machine through COM-based queries to CIM classes.
 *
 * Common WMI classes queried by AC:
 *
 *   * Win32_DiskDrive          — disk serial, model, interface type
 *   * Win32_BaseBoard          — motherboard serial, manufacturer
 *   * Win32_BIOS               — BIOS serial, version, manufacturer
 *   * Win32_ComputerSystem     — model, manufacturer (VM indicators)
 *   * Win32_VideoController    — GPU device ID, driver version
 *   * Win32_NetworkAdapter     — MAC addresses, adapter type
 *   * Win32_OperatingSystem    — OS serial, install date
 *   * Win32_PhysicalMemory     — RAM serial, part number
 *   * Win32_Processor          — CPU ID, name, features
 *   * MSAcpi_ThermalZoneTemperature — VM detection (VMs lack thermals)
 *
 * This module:
 *
 *   1. Maintains a database of WMI classes each AC queries.
 *   2. Optionally monitors IWbemServices::ExecQuery via COM vtable hook.
 *   3. Classifies queries by purpose (HWID / VM detect / system info).
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_WMI_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vh::ac::wmi_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Query classification
// ─────────────────────────────────────────────────────────────────────────────

enum class WmiPurpose : uint8_t {
    HwidFingerprint,    // disk/board/BIOS serials for HWID ban
    VmDetection,        // manufacturer/model strings that reveal VMs
    SystemProfile,      // general telemetry (OS, CPU, GPU)
    ThermalCheck,       // thermal zone presence (absent in VMs)
    Unknown,
};

// ─────────────────────────────────────────────────────────────────────────────
//  Known WMI queries per engine
// ─────────────────────────────────────────────────────────────────────────────

struct KnownQuery {
    std::string_view    wmi_class;      // e.g. "Win32_DiskDrive"
    std::string_view    properties;     // e.g. "SerialNumber,Model" (empty = SELECT *)
    WmiPurpose          purpose;
    uint32_t            engines;        // bitmask of Engine values
};

/// All known AC WMI queries.
VH_API std::span<const KnownQuery> known_queries() noexcept;

/// Filter to queries for a specific engine.
VH_API std::vector<KnownQuery> queries_for(ac::Engine engine) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Real-time monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct WmiHit {
    std::string     query_text;     // full WQL string
    std::string     wmi_class;      // parsed class name
    WmiPurpose      purpose;        // classified
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using WmiCallback = void(*)(const WmiHit& hit);

/// Start monitoring WMI queries via IWbemServices::ExecQuery vtable hook.
VH_API vh::Result<void> monitor_start(WmiCallback cb) noexcept;

/// Stop monitoring.
VH_API void monitor_stop() noexcept;

/// Is monitoring active?
VH_API bool monitor_active() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Quick checks
// ─────────────────────────────────────────────────────────────────────────────

/// Does the detected AC use WMI for VM detection?
VH_API bool ac_uses_wmi_vm_check() noexcept;

/// Does the detected AC collect HWIDs via WMI?
VH_API bool ac_collects_wmi_hwid() noexcept;

} // namespace vh::ac::wmi_fence
