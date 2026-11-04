#pragma once

/**
 * vh/vigil/object_callback_fence.vh — Object callback awareness
 *
 * Anti-cheat engines use ObRegisterCallbacks to intercept:
 *
 *   * Process handle operations (open, duplicate)
 *   * Thread handle operations (open, duplicate)
 *   * Handle access stripping (removing VM_READ/VM_WRITE/SUSPEND rights)
 *   * Desktop handle operations (some engines)
 *
 * This module provides:
 *
 *   1. Per-engine object callback profiles.
 *   2. Handle access stripping awareness — what rights are removed.
 *   3. Protected process awareness — which processes are shielded.
 *
 * Platform: WIN32 for NtQuerySystemInformation probing, stubs on POSIX.
 *
 * Requires: VH_ENABLE_OBJECT_CALLBACK_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::object_callback_fence {

enum class ObjectOp : uint32_t {
    ProcessOpen         = 1u << 0,  // OB_OPERATION_HANDLE_CREATE for process
    ProcessDuplicate    = 1u << 1,  // OB_OPERATION_HANDLE_DUPLICATE for process
    ThreadOpen          = 1u << 2,  // OB_OPERATION_HANDLE_CREATE for thread
    ThreadDuplicate     = 1u << 3,  // OB_OPERATION_HANDLE_DUPLICATE for thread
    DesktopOpen         = 1u << 4,  // desktop object callback
};

enum class StrippedAccess : uint32_t {
    VmRead              = 1u << 0,  // PROCESS_VM_READ stripped
    VmWrite             = 1u << 1,  // PROCESS_VM_WRITE stripped
    VmOperation         = 1u << 2,  // PROCESS_VM_OPERATION stripped
    CreateThread        = 1u << 3,  // PROCESS_CREATE_THREAD stripped
    SuspendResume       = 1u << 4,  // THREAD_SUSPEND_RESUME stripped
    QueryInfo           = 1u << 5,  // PROCESS_QUERY_INFORMATION stripped
    DupHandle           = 1u << 6,  // PROCESS_DUP_HANDLE stripped
    Terminate           = 1u << 7,  // PROCESS_TERMINATE stripped
};

struct ObjectCallbackProfile {
    ac::Engine  engine;
    uint32_t    operations;         // bitmask of ObjectOp
    uint32_t    stripped_access;    // bitmask of StrippedAccess
    bool        whitelists_self;    // AC allows its own handles through
    bool        whitelists_system;  // allows SYSTEM process handles
};

struct ProtectedProcess {
    std::string name;
    uint32_t    pid;
    bool        is_ac_process;
};

/// Get the object callback profile for a specific AC engine.
VH_API ObjectCallbackProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of object operations a specific AC engine intercepts.
VH_API uint32_t operations_by(ac::Engine engine) noexcept;

/// Bitmask of handle access rights a specific AC engine strips.
VH_API uint32_t stripped_access_by(ac::Engine engine) noexcept;

} // namespace vh::ac::object_callback_fence
