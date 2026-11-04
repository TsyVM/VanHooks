#pragma once

/**
 * vh/vigil/stack_fence.vh — Call stack validation awareness
 *
 * Anti-cheat engines validate return addresses on the call stack:
 *
 *   * Return addresses must point into loaded module .text sections
 *   * Spoofed return addresses (gadgets) are detected by pattern
 *   * Stack frames must be well-formed (RBP chain or unwind data)
 *   * Kernel callbacks must originate from expected ntdll stubs
 *
 * Detection methods:
 *
 *   * **RtlCaptureStackBackTrace** — walk the stack
 *   * **RtlVirtualUnwind** — unwind data validation
 *   * **NtQueryVirtualMemory** — classify each return address
 *   * Manual RBP chain walk with module membership checks
 *
 * This module provides:
 *
 *   1. Per-engine stack validation profiles.
 *   2. Self-check — validate your own stack against AC expectations.
 *   3. Return address classification.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_STACK_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::stack_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Return address classification
// ─────────────────────────────────────────────────────────────────────────────

enum class ReturnAddrKind : uint8_t {
    ValidModule,        // inside a loaded module's .text
    ValidModuleNonText, // inside a loaded module but not .text
    UnbackedMemory,     // MEM_PRIVATE / MEM_COMMIT with no module
    ManualMapped,       // MEM_IMAGE but no Ldr entry
    GadgetSuspect,      // points after a CALL but caller module is unexpected
    NullOrInvalid,      // null, kernel-range, or unreadable
};

struct FrameInfo {
    uintptr_t       return_address;
    ReturnAddrKind  kind;
    std::string     module_name;    // if ValidModule
    uintptr_t       module_base;
    bool            has_unwind_info; // RtlLookupFunctionEntry found data
    bool            is_suspicious;
};

/// Capture and classify the current thread's call stack.
VH_API vh::Result<std::vector<FrameInfo>> capture_stack() noexcept;

/// Capture and classify another thread's call stack.
VH_API vh::Result<std::vector<FrameInfo>> capture_stack(uint32_t tid) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Stack health assessment
// ─────────────────────────────────────────────────────────────────────────────

struct StackHealth {
    uint32_t    total_frames;
    uint32_t    valid_frames;
    uint32_t    unbacked_frames;
    uint32_t    gadget_suspects;
    uint32_t    manual_mapped;
    bool        all_have_unwind;    // every frame has unwind data
    bool        is_clean;           // no suspicious frames
};

/// Quick stack health assessment.
VH_API StackHealth assess_stack() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine stack validation profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class StackCheck : uint32_t {
    ReturnAddrInModule  = 1u << 0,
    UnwindDataPresent   = 1u << 1,
    RBPChainValid       = 1u << 2,
    GadgetDetection     = 1u << 3,
    KernelReturnValid   = 1u << 4,
    StackPivotDetect    = 1u << 5,
};

/// Bitmask of stack checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::stack_fence
