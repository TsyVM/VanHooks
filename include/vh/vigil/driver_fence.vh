#pragma once

/**
 * vh/vigil/driver_fence.vh — Kernel driver detection & awareness
 *
 * Anti-cheat kernel drivers register callbacks, minifilters, and
 * device objects that intercept VanHooks operations from ring 0.
 * This module detects their presence and reports which kernel-level
 * observation points are active, so the engine can route around them.
 *
 * Detection vectors
 * ─────────────────
 *
 *   1. **Device objects** — known AC driver device names
 *   2. **Loaded drivers** — NtQuerySystemInformation SystemModuleInformation
 *   3. **Object callbacks** — ObRegisterCallbacks on process/thread
 *   4. **Image load notify** — PsSetLoadImageNotifyRoutine presence
 *   5. **Thread creation notify** — PsSetCreateThreadNotifyRoutine
 *   6. **Registry callbacks** — CmRegisterCallback
 *   7. **Minifilters** — FltEnumerateFilters / FltEnumerateInstances
 *   8. **ETW sessions** — registered real-time ETW consumers
 *
 * All queries are read-only.  The module never attempts to unload,
 * patch, or interfere with kernel drivers.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_DRIVER_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>

#include <cstdint>
#include <span>
#include <string_view>

namespace vh::ac::driver_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Kernel observation points that an AC driver may register
// ─────────────────────────────────────────────────────────────────────────────

enum class ObservationPoint : uint32_t {
    ProcessCallback     = 1u << 0,   // PsSetCreateProcessNotifyRoutine
    ThreadCallback      = 1u << 1,   // PsSetCreateThreadNotifyRoutine
    ImageLoadCallback   = 1u << 2,   // PsSetLoadImageNotifyRoutine
    ObjectCallback      = 1u << 3,   // ObRegisterCallbacks (process/thread handles)
    RegistryCallback    = 1u << 4,   // CmRegisterCallback
    Minifilter          = 1u << 5,   // FltRegisterFilter
    EtwConsumer         = 1u << 6,   // real-time ETW session
    DeviceObject        = 1u << 7,   // IoCreateDevice
    HandleTrace         = 1u << 8,   // NtOpenProcess / NtReadVirtualMemory monitoring
};

/// Bitwise OR of all detected observation points.
VH_API uint32_t active_observations() noexcept;

/// Check a specific observation point.
VH_API bool is_observed(ObservationPoint point) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Loaded driver enumeration
// ─────────────────────────────────────────────────────────────────────────────

struct DriverInfo {
    std::string_view    name;       // e.g. "bedaisy.sys"
    uint64_t            base;       // kernel-mode base address
    uint32_t            size;       // image size
    bool                known_ac;   // matches an AC fingerprint
};

/// Enumerate loaded kernel drivers.  Returns a snapshot valid until
/// the next call.  Requires SeDebugPrivilege for full results.
VH_API std::span<const DriverInfo> enumerate_drivers() noexcept;

/// Quick check: is a specific driver loaded?
VH_API bool is_driver_loaded(std::string_view name) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Minifilter awareness
// ─────────────────────────────────────────────────────────────────────────────

struct MinifilterInfo {
    std::string_view    name;
    uint32_t            altitude;   // filter altitude (lower = closer to filesystem)
    bool                known_ac;
};

/// Enumerate registered minifilter instances.
VH_API std::span<const MinifilterInfo> enumerate_minifilters() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Routing advice
// ─────────────────────────────────────────────────────────────────────────────

/// Given the active observation points, recommend whether a specific
/// VanHooks operation is safe to proceed.
enum class Operation : uint8_t {
    AllocateExecutable,     // VirtualAlloc PAGE_EXECUTE
    WriteRemoteMemory,      // NtWriteVirtualMemory
    CreateRemoteThread,     // NtCreateThreadEx
    OpenProcess,            // NtOpenProcess
    LoadImage,              // LdrLoadDll / LoadLibrary
    MapSection,             // NtMapViewOfSection
    ModifyPageProtection,   // NtProtectVirtualMemory
};

enum class Advice : uint8_t {
    Proceed,        // No known observation for this operation
    UseSyscall,     // Use indirect syscall to bypass user-mode hooks
    UseApc,         // Use APC instead of thread creation
    UseModuleStomp, // Use existing module cave instead of allocation
    Defer,          // Wait for a safe window (see ac_heartbeat)
    Abort,          // Operation is too risky with current driver state
};

VH_API Advice advise(Operation op) noexcept;

} // namespace vh::ac::driver_fence
