#pragma once

/**
 * vh/vigil/callback_fence.vh — Kernel callback awareness
 *
 * Anti-cheat engines register kernel callbacks to monitor:
 *
 *   * Process creation / termination (PsSetCreateProcessNotifyRoutine)
 *   * Thread creation (PsSetCreateThreadNotifyRoutine)
 *   * Image load (PsSetLoadImageNotifyRoutine)
 *   * Object operations (ObRegisterCallbacks)
 *   * Registry operations (CmRegisterCallback)
 *   * Minifilter file-system callbacks
 *
 * This module provides:
 *
 *   1. Per-engine kernel callback profiles.
 *   2. Callback type awareness — which kernel callbacks are used.
 *   3. Detection of loaded AC kernel drivers that register callbacks.
 *
 * Platform: WIN32 for driver detection, stubs on POSIX.
 *
 * Requires: VH_ENABLE_CALLBACK_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::callback_fence {

enum class KernelCallback : uint32_t {
    ProcessNotify       = 1u << 0,  // PsSetCreateProcessNotifyRoutine(Ex)
    ThreadNotify        = 1u << 1,  // PsSetCreateThreadNotifyRoutine
    ImageNotify         = 1u << 2,  // PsSetLoadImageNotifyRoutine
    ObjectCallback      = 1u << 3,  // ObRegisterCallbacks
    RegistryCallback    = 1u << 4,  // CmRegisterCallback(Ex)
    MinifilterCallback  = 1u << 5,  // FltRegisterFilter
    ShutdownNotify      = 1u << 6,  // IoRegisterShutdownNotification
    PowerCallback       = 1u << 7,  // PoRegisterPowerSettingCallback
    BugCheckCallback    = 1u << 8,  // KeRegisterBugCheckCallback
    DpcTimer            = 1u << 9,  // KeSetTimerEx / DPC watchdog
};

struct CallbackProfile {
    ac::Engine  engine;
    uint32_t    callbacks;      // bitmask of KernelCallback
    bool        has_kernel_driver;
    bool        uses_ob_callbacks;
    bool        strips_handle_access;
};

struct DriverInfo {
    std::string name;
    std::string service_name;
    bool        is_running;
};

/// Get the callback profile for a specific AC engine.
VH_API CallbackProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of kernel callbacks a specific AC engine registers.
VH_API uint32_t callbacks_by(ac::Engine engine) noexcept;

/// Enumerate loaded drivers that match known AC kernel components.
VH_API vh::Result<std::vector<DriverInfo>> detect_ac_drivers() noexcept;

} // namespace vh::ac::callback_fence
