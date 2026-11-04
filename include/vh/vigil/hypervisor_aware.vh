#pragma once

/**
 * vh/vigil/hypervisor_aware.vh — Hypervisor detection awareness
 *
 * Anti-cheat engines detect virtualisation to prevent debugging and
 * analysis.  They use multiple vectors:
 *
 *   * **CPUID leaf 0x1** — ECX bit 31 (Hypervisor Present)
 *   * **CPUID leaf 0x40000000** — hypervisor vendor string
 *   * **RDTSC/RDTSCP timing** — VM exits add measurable overhead
 *   * **MSR reads** — IA32_VMX_BASIC etc. (requires ring 0)
 *   * **I/O port backdoors** — VMware ("VMXh"), VirtualBox, Hyper-V
 *   * **SIDT/SGDT/SLDT** — descriptor table relocation fingerprints
 *   * **Driver artifacts** — VBoxGuest.sys, vmci.sys, etc.
 *   * **MAC address OUI** — VMware, VirtualBox, Hyper-V MAC prefixes
 *   * **Device names** — \\.\VBoxGuest, \\.\vmci
 *
 * This module:
 *
 *   1. Detects the current hypervisor (if any) from VanHooks' perspective.
 *   2. Reports which detection vectors the active AC engine uses.
 *   3. Enumerates what artifacts are currently visible on this machine.
 *
 * Read-only awareness.  Does not attempt to hide or spoof hypervisor
 * presence — that requires EPT/hypervisor-level work.
 *
 * Platform: Windows + Linux.  macOS returns Unsupported for most.
 *
 * Requires: VH_ENABLE_HYPERVISOR_AWARE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <string_view>

namespace vh::ac::hypervisor {

// ─────────────────────────────────────────────────────────────────────────────
//  Hypervisor identification
// ─────────────────────────────────────────────────────────────────────────────

enum class HypervisorKind : uint8_t {
    None,
    VMware,
    VirtualBox,
    HyperV,
    KVM,
    QEMU,
    Xen,
    Parallels,
    ACRN,
    Unknown,        // CPUID says hypervisor present but vendor unrecognised
};

struct HypervisorInfo {
    HypervisorKind  kind           = HypervisorKind::None;
    std::string     vendor_string;  // 12-char CPUID 0x40000000 string
    bool            cpuid_present  = false;  // CPUID leaf 1 ECX bit 31
    uint32_t        max_leaf       = 0;      // CPUID 0x40000000 EAX
};

/// Detect the hypervisor from CPUID.  Cached after first call.
VH_API HypervisorInfo detect() noexcept;

/// Quick check: are we inside any hypervisor?
VH_API bool is_virtualised() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Detection vectors used by AC engines
// ─────────────────────────────────────────────────────────────────────────────

enum class DetectionVector : uint32_t {
    CpuidLeaf1          = 1u << 0,   // Hypervisor Present bit
    CpuidLeaf40         = 1u << 1,   // vendor string
    RdtscTiming         = 1u << 2,   // VM-exit timing delta
    IoPortBackdoor      = 1u << 3,   // VMware "VMXh" / VBox
    DescriptorTables    = 1u << 4,   // SIDT/SGDT/SLDT relocation
    DriverArtifacts     = 1u << 5,   // known VM driver names
    MacAddressOui       = 1u << 6,   // VM MAC OUI prefixes
    DeviceNames         = 1u << 7,   // \\.\VBoxGuest etc.
    RegistryKeys        = 1u << 8,   // VM-related registry keys
    WmiClasses          = 1u << 9,   // Win32_ComputerSystem Model
    FirmwareTables      = 1u << 10,  // SMBIOS strings
    ThermalZones        = 1u << 11,  // absence of thermal sensors
};

/// Bitmask of detection vectors used by a specific AC engine.
VH_API uint32_t vectors_used_by(ac::Engine engine) noexcept;

/// Which vectors the current primary AC uses.
VH_API uint32_t vectors_used_by_primary() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Artifact enumeration (what's visible right now)
// ─────────────────────────────────────────────────────────────────────────────

struct VisibleArtifact {
    DetectionVector     vector;
    std::string         detail;     // e.g. "VBoxGuest.sys loaded", "MAC 08:00:27:*"
    bool                ac_detects; // true if primary AC checks this vector
};

/// Enumerate all VM artifacts currently visible on this machine.
VH_API vh::Result<std::vector<VisibleArtifact>> enumerate_artifacts() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  RDTSC timing analysis
// ─────────────────────────────────────────────────────────────────────────────

struct TimingResult {
    uint64_t    rdtsc_overhead_cycles;  // median CPUID+RDTSC delta
    uint64_t    bare_metal_baseline;    // typical bare-metal value (~30-80)
    bool        likely_vm;              // overhead > 3× baseline
    double      confidence;             // 0.0 – 1.0
};

/// Run a RDTSC timing probe (100 iterations, median).
/// Same technique AC engines use to detect VM exits.
VH_API TimingResult timing_probe() noexcept;

} // namespace vh::ac::hypervisor
