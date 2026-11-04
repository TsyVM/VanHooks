#pragma once

/**
 * vh/vigil/hypervisor_fence.vh — Hypervisor-based cheat awareness
 *
 * Cheat tools use hypervisors to operate beneath the OS:
 *
 *   * Type-1 hypervisors for EPT-based memory read/write
 *   * VMX-root kit execution for stealth hooks
 *   * Hypervisor-based page table manipulation
 *   * VMCALL-based communication channels
 *   * Nested virtualization abuse
 *
 * Anti-cheat engines detect these via:
 *
 *   * CPUID leaf analysis for hypervisor presence
 *   * TSC timing analysis for VM exits
 *   * MSR access pattern monitoring
 *   * Exception bitmap analysis
 *   * Hypervisor brand string verification
 *
 * This module provides:
 *
 *   1. Per-engine hypervisor detection profiles.
 *   2. Detection method awareness — how each engine checks.
 *   3. Known hypervisor brand string fingerprinting.
 *
 * Platform: cross-platform for CPUID checks, extended on WIN32.
 *
 * Requires: VH_ENABLE_HYPERVISOR_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>

namespace vh::ac::hypervisor_fence {

enum class HypervisorCheck : uint32_t {
    CPUIDLeafPresence   = 1u << 0,  // CPUID leaf 1 ECX.31 hypervisor bit
    BrandStringVerify   = 1u << 1,  // CPUID leaf 0x40000000 brand string
    TSCTimingAnalysis   = 1u << 2,  // timing analysis for VM exits
    MSRAccessCheck      = 1u << 3,  // MSR read/write interception checks
    EPTPresenceDetect   = 1u << 4,  // EPT / SLAT feature detection
    NestedVMDetect      = 1u << 5,  // nested virtualisation detection
    VMCALLProbe         = 1u << 6,  // probe for VMCALL handlers
    IDTSIDTCheck        = 1u << 7,  // IDT/SIDT relocation detection
    ExceptionBitmap     = 1u << 8,  // exception bitmap analysis
    HypervisorArtifacts = 1u << 9,  // driver/device artifacts
};

struct HypervisorProfile {
    ac::Engine  engine;
    uint32_t    checks;             // bitmask of HypervisorCheck
    bool        blocks_unknown_hv;  // refuses to run under unknown HV
    bool        allows_vmware;      // allows VMware
    bool        allows_hyperv;      // allows Hyper-V
    bool        allows_kvm;         // allows KVM
};

struct HypervisorInfo {
    bool        present;
    std::string brand;              // e.g. "Microsoft Hv", "VMwareVMware"
    bool        is_known_legitimate;
};

/// Get the hypervisor detection profile for a specific AC engine.
VH_API HypervisorProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of hypervisor checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

/// Query the current hypervisor state via CPUID.
VH_API HypervisorInfo query_hypervisor() noexcept;

} // namespace vh::ac::hypervisor_fence
