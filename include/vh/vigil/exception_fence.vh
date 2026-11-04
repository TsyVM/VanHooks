#pragma once

/**
 * vh/vigil/exception_fence.vh — Exception handler chain awareness
 *
 * Anti-cheat engines inspect exception handler chains:
 *
 *   * VEH chain walk — validate all vectored handlers point into modules
 *   * SEH chain walk — validate fs:[0] / gs:[0] handler chain
 *   * Exception dispatcher hooks — NtContinue / KiUserExceptionDispatcher
 *   * Single-step trap detection (EFLAGS.TF)
 *   * INT3 / INT 2D scan around hooked functions
 *
 * This module provides:
 *
 *   1. Per-engine exception inspection profiles.
 *   2. VEH/SEH chain enumeration and origin classification.
 *   3. Exception dispatcher integrity checks.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_EXCEPTION_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::exception_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Handler classification
// ─────────────────────────────────────────────────────────────────────────────

enum class HandlerOrigin : uint8_t {
    KnownModule,        // handler inside a loaded, listed module
    UnbackedMemory,     // handler in MEM_COMMIT with no backing module
    ManualMapped,       // handler in MEM_IMAGE but no Ldr entry
    NullOrInvalid,      // null, unreadable, or kernel-range
};

enum class HandlerKind : uint8_t {
    VEH,                // vectored exception handler
    VCH,                // vectored continue handler
    SEH,                // structured exception handler (fs:[0] chain)
    UEF,                // unhandled exception filter
};

struct HandlerInfo {
    HandlerKind     kind;
    uintptr_t       callback_address;
    HandlerOrigin   origin;
    std::string     module_name;    // if KnownModule
    bool            is_suspicious;
};

/// Enumerate all registered exception handlers.
VH_API vh::Result<std::vector<HandlerInfo>> scan_handlers() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Dispatcher integrity
// ─────────────────────────────────────────────────────────────────────────────

struct DispatcherState {
    bool    ki_user_exception_hooked;   // KiUserExceptionDispatcher patched
    bool    nt_continue_hooked;         // NtContinue patched
    bool    rtl_dispatch_hooked;        // RtlDispatchException patched
    bool    single_step_active;         // EFLAGS.TF set on current thread
};

/// Check exception dispatcher integrity.
VH_API DispatcherState check_dispatchers() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine exception inspection profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class ExceptionCheck : uint32_t {
    VEHChainWalk        = 1u << 0,
    SEHChainWalk        = 1u << 1,
    VCHChainWalk        = 1u << 2,
    DispatcherIntegrity = 1u << 3,
    SingleStepDetect    = 1u << 4,
    Int3Scan            = 1u << 5,
    Int2DScan           = 1u << 6,
    UEFValidation       = 1u << 7,
};

/// Bitmask of exception checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::exception_fence
