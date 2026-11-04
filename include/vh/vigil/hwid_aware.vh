#pragma once

/**
 * vh/vigil/hwid_aware.vh — Hardware ID collection awareness
 *
 * Anti-cheat engines fingerprint the machine by collecting hardware
 * and software identifiers.  When a ban is issued, these IDs form the
 * "HWID ban" that persists even after reinstalling the game.
 *
 * Each AC gathers a different subset of identifiers.  This module
 * knows which IDs each engine collects and can:
 *
 *   1. **Enumerate** which identifiers the detected AC is interested in.
 *   2. **Report** the current values the AC would see.
 *   3. **Monitor** API calls that read hardware identifiers (optional
 *      hook-based interception for research/awareness).
 *
 * This is read-only awareness.  Spoofing the actual values is out of
 * scope for VanHooks — that requires a kernel driver (VanGuard territory).
 * What this module provides is *knowledge* of what the AC is looking at,
 * so higher-level tools can decide what to protect.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_HWID_AWARE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace vh::ac::hwid {

// ─────────────────────────────────────────────────────────────────────────────
//  Identifier categories that AC engines collect
// ─────────────────────────────────────────────────────────────────────────────

enum class IdKind : uint32_t {
    DiskSerial          = 1u << 0,   // PhysicalDrive serial (SMART / IOCTL_STORAGE)
    VolumeSerial        = 1u << 1,   // GetVolumeInformation serial number
    MacAddress          = 1u << 2,   // Network adapter MAC (GetAdaptersAddresses)
    MachineGuid         = 1u << 3,   // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    ProductId           = 1u << 4,   // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
    ComputerName        = 1u << 5,   // GetComputerNameEx
    UserName            = 1u << 6,   // GetUserName / environment
    CpuId               = 1u << 7,   // CPUID brand string + feature flags
    GpuId               = 1u << 8,   // GPU device ID / driver version (DXGI / registry)
    SmbiosSerial        = 1u << 9,   // SMBIOS baseboard / system serial (WMI or GetSystemFirmwareTable)
    MotherboardSerial   = 1u << 10,  // Baseboard serial (WMI Win32_BaseBoard)
    BiosSerial          = 1u << 11,  // BIOS serial string
    TpmEkPublic         = 1u << 12,  // TPM Endorsement Key public portion
    WindowsInstallDate  = 1u << 13,  // InstallDate from registry
    MonitorEdid         = 1u << 14,  // Monitor EDID serial from SetupAPI
    UsbDevices          = 1u << 15,  // Connected USB device serials
};

/// Bitmask of all IdKind values a specific AC engine collects.
VH_API uint32_t collected_by(ac::Engine engine) noexcept;

/// Which IDs the *currently detected* primary AC collects.
VH_API uint32_t collected_by_primary() noexcept;

/// Human-readable name for an IdKind flag.
VH_API std::string_view id_kind_name(IdKind kind) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Current identifier values (what the AC would see right now)
// ─────────────────────────────────────────────────────────────────────────────

struct IdentifierValue {
    IdKind      kind;
    std::string label;      // e.g. "Disk 0", "Ethernet 0"
    std::string value;      // the raw value string
    bool        ac_relevant; // true if the primary AC collects this kind
};

/// Snapshot all readable hardware identifiers on this machine.
/// Filtered to `mask` (default = all).
VH_API vh::Result<std::vector<IdentifierValue>> snapshot(
    uint32_t mask = 0xFFFFFFFF) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  API call monitoring (optional, hooks WinAPI functions that read HWIDs)
// ─────────────────────────────────────────────────────────────────────────────

enum class MonitorEvent : uint8_t {
    RegistryQuery,          // RegQueryValueEx on an HWID key
    WmiQuery,               // IWbemServices::ExecQuery for HWID class
    DeviceIoControl,        // IOCTL_STORAGE_QUERY_PROPERTY etc.
    SetupApi,               // SetupDiGetDeviceRegistryProperty
    GetAdaptersInfo,        // GetAdaptersAddresses / GetAdaptersInfo
    CpuIdInstruction,       // __cpuid / __cpuidex intercept
    GetSystemFirmwareTable, // GetSystemFirmwareTable (SMBIOS)
};

struct MonitorHit {
    MonitorEvent    event;
    IdKind          kind;           // which ID was being read
    std::string     detail;         // registry path, WMI class, IOCTL code
    uint64_t        caller_rip;     // return address of the API call
    std::string     caller_module;  // module name containing caller_rip
};

using MonitorCallback = void(*)(const MonitorHit& hit);

/// Start monitoring HWID-reading API calls.
/// The callback fires each time a monitored API is invoked by any module.
VH_API vh::Result<void> monitor_start(MonitorCallback cb) noexcept;

/// Stop monitoring and remove all hooks.
VH_API void monitor_stop() noexcept;

/// Is the monitor currently active?
VH_API bool monitor_active() noexcept;

} // namespace vh::ac::hwid
