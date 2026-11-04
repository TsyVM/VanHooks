#pragma once

/**
 * vh/vigil/handle_fence.vh — Handle table awareness
 *
 * Anti-cheat engines inspect the system handle table to detect:
 *
 *   * Open handles to the game process from external tools
 *   * Debug object handles (NtQueryObject DebugObjectType)
 *   * Suspicious handle access rights (PROCESS_VM_READ/WRITE)
 *   * Cross-process handles from known cheat tool PIDs
 *
 * Detection methods:
 *
 *   * **NtQuerySystemInformation(SystemHandleInformation)** — full handle table
 *   * **NtQueryObject** — object type and name for a specific handle
 *   * **NtClose** trap — NtClose(invalid) raises STATUS_INVALID_HANDLE under debugger
 *   * **DuplicateHandle** monitoring — external tools duplicating game handles
 *
 * This module provides:
 *
 *   1. Handle table scanning (who has handles to us, with what access).
 *   2. Debug object detection.
 *   3. Per-engine handle inspection profiles.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_HANDLE_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::handle_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Handle risk classification
// ─────────────────────────────────────────────────────────────────────────────

enum class HandleCategory : uint8_t {
    ProcessRead,        // PROCESS_VM_READ
    ProcessWrite,       // PROCESS_VM_WRITE / PROCESS_VM_OPERATION
    ProcessAll,         // PROCESS_ALL_ACCESS
    DebugObject,        // debug object attached
    ThreadAccess,       // THREAD_SET_CONTEXT / THREAD_SUSPEND_RESUME
    Unknown,
};

struct HandleRisk {
    uint32_t        owner_pid;
    std::string     owner_name;     // process name holding the handle
    uintptr_t       handle_value;
    uint32_t        access_mask;
    HandleCategory  category;
    bool            is_debug;       // handle to a DebugObject
    bool            is_suspicious;  // from unknown process with write access
};

/// Scan for handles to the current process from other processes.
VH_API vh::Result<std::vector<HandleRisk>> scan_handles() noexcept;

/// Check if a debugger is attached via debug object detection.
VH_API bool debug_object_present() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine handle inspection profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class HandleCheck : uint32_t {
    SystemHandleEnum    = 1u << 0,  // NtQuerySystemInformation handle table
    DebugObjectQuery    = 1u << 1,  // NtQueryObject for debug objects
    CloseInvalidHandle  = 1u << 2,  // NtClose trap
    HandleAccessAudit   = 1u << 3,  // check granted access on own handles
    CrossProcessScan    = 1u << 4,  // scan for external handles to self
};

/// Bitmask of handle checks performed by a specific AC engine.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct HandleEvent {
    enum class Api : uint8_t {
        NtQuerySystemInformation_Handles,
        NtQueryObject, NtClose_Trap,
        DuplicateHandle, OpenProcess,
    };
    Api             api;
    uint32_t        source_pid;
    uint32_t        access_mask;
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using HandleCallback = void(*)(const HandleEvent& event);

VH_API vh::Result<void> monitor_start(HandleCallback cb) noexcept;
VH_API void monitor_stop() noexcept;
VH_API bool monitor_active() noexcept;

} // namespace vh::ac::handle_fence
