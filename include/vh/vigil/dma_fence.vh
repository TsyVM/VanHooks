#pragma once

/**
 * vh/vigil/dma_fence.vh — DMA / PCIe device awareness
 *
 * Hardware-based cheats use DMA to bypass software protections:
 *
 *   * PCILeech / FPGA-based DMA boards (Squirrel, Screamer)
 *   * KMBox / KMBox.NET input emulation hardware
 *   * Arduino-based input injection devices
 *   * Thunderbolt DMA attack vectors
 *   * Custom PCIe devices with bus-master capability
 *
 * Anti-cheat engines detect these via:
 *
 *   * IOMMU / VT-d enforcement verification
 *   * PCIe device enumeration for unknown vendors
 *   * USB device enumeration for HID spoofing
 *   * DMA buffer monitoring via IOMMU page faults
 *
 * This module provides:
 *
 *   1. Per-engine DMA detection profiles.
 *   2. DMA check awareness — what each engine looks for.
 *   3. Known suspicious device vendor ID awareness.
 *
 * Platform: WIN32 for device enumeration, stubs on POSIX.
 *
 * Requires: VH_ENABLE_DMA_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::dma_fence {

enum class DMACheck : uint32_t {
    IOMMUVerify         = 1u << 0,  // verify IOMMU / VT-d is enabled
    PCIeDeviceEnum      = 1u << 1,  // enumerate PCIe devices
    UnknownVendorFlag   = 1u << 2,  // flag unknown/suspicious vendor IDs
    FPGASignatureDetect = 1u << 3,  // detect known FPGA board signatures
    ThunderboltCheck    = 1u << 4,  // check Thunderbolt controller state
    USBHIDEnum          = 1u << 5,  // enumerate USB HID devices
    KMBoxDetect         = 1u << 6,  // detect KMBox/KMBox.NET devices
    ArduinoDetect       = 1u << 7,  // detect Arduino HID spoofers
    BusResetMonitor     = 1u << 8,  // monitor bus reset events
    DMARegionMonitor    = 1u << 9,  // monitor DMA-accessible regions
};

struct DMAProfile {
    ac::Engine  engine;
    uint32_t    checks;             // bitmask of DMACheck
    bool        requires_iommu;     // refuses to run without IOMMU
    bool        blocks_dma_devices; // actively blocks suspicious devices
};

struct SuspiciousDevice {
    uint16_t    vendor_id;
    uint16_t    device_id;
    std::string description;
    bool        is_known_cheat_hw;
};

/// Get the DMA detection profile for a specific AC engine.
VH_API DMAProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of DMA checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

/// Whether the engine requires IOMMU to be enabled.
VH_API bool requires_iommu(ac::Engine engine) noexcept;

/// Check if VT-d / IOMMU appears enabled on the system.
VH_API bool is_iommu_likely_enabled() noexcept;

} // namespace vh::ac::dma_fence
