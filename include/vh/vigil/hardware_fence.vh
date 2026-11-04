#pragma once

/**
 * vh/vigil/hardware_fence.vh — Hardware-level cheat detection awareness
 *
 * Anti-cheat engines monitor hardware to detect:
 *
 *   * USB device changes (new HID devices appearing mid-game)
 *   * Controller emulation / macro devices
 *   * Mouse sensor spoofing (fake DPI / polling rate)
 *   * Hardware ID changes (HWID spoofing artifacts)
 *   * Custom firmware on peripherals
 *   * Display capture devices (HDMI splitters with USB output)
 *
 * This module provides:
 *
 *   1. Per-engine hardware detection profiles.
 *   2. Hardware check awareness — what each engine monitors.
 *   3. USB device change monitoring awareness.
 *
 * Platform: WIN32 for device enumeration, stubs on POSIX.
 *
 * Requires: VH_ENABLE_HARDWARE_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::hardware_fence {

enum class HardwareCheck : uint32_t {
    USBDeviceEnum       = 1u << 0,  // enumerate USB devices
    USBChangeMonitor    = 1u << 1,  // monitor device arrival/removal
    ControllerVerify    = 1u << 2,  // verify controller authenticity
    MouseSensorCheck    = 1u << 3,  // mouse sensor data validation
    MacroDetect         = 1u << 4,  // detect macro / script hardware
    HWIDConsistency     = 1u << 5,  // cross-reference hardware IDs
    PollingRateCheck    = 1u << 6,  // verify reported vs actual poll rate
    CaptureDeviceCheck  = 1u << 7,  // detect display capture hardware
    BluetoothEnum       = 1u << 8,  // enumerate Bluetooth devices
    SerialPortScan      = 1u << 9,  // scan serial/COM ports
};

struct HardwareProfile {
    ac::Engine  engine;
    uint32_t    checks;             // bitmask of HardwareCheck
    bool        monitors_live;      // real-time device monitoring
    bool        fingerprints_hw;    // hardware fingerprint collection
};

struct USBDeviceInfo {
    uint16_t    vendor_id;
    uint16_t    product_id;
    std::string description;
    std::string manufacturer;
    bool        is_hid;
    bool        is_suspicious;
};

/// Get the hardware detection profile for a specific AC engine.
VH_API HardwareProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of hardware checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

/// Whether the engine performs real-time device monitoring.
VH_API bool monitors_live(ac::Engine engine) noexcept;

} // namespace vh::ac::hardware_fence
