#pragma once

/**
 * vh/vigil/syscall_fence.vh — Syscall stub integrity awareness
 *
 * Anti-cheat engines verify that ntdll syscall stubs are unmodified:
 *
 *   * Syscall stub prologue check (mov eax, SSN; syscall; ret)
 *   * SSN (System Service Number) consistency validation
 *   * Inline hook detection on Nt* exports
 *   * Indirect syscall gadget scanning
 *   * ntdll .text CRC vs KnownDlls mapping
 *
 * This module provides:
 *
 *   1. Per-engine syscall integrity profiles.
 *   2. Stub integrity audit — check specific Nt* functions.
 *   3. SSN extraction and validation.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_SYSCALL_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::syscall_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Stub state
// ─────────────────────────────────────────────────────────────────────────────

enum class StubState : uint8_t {
    Clean,              // standard syscall stub pattern
    Hooked,             // prologue patched (JMP / CALL)
    Modified,           // bytes differ from expected but not a JMP
    Redirected,         // syscall instruction replaced
    NotFound,           // export not found in ntdll
};

struct StubInfo {
    std::string     function_name;  // e.g. "NtAllocateVirtualMemory"
    uintptr_t       address;
    uint32_t        ssn;            // system service number (0 if unknown)
    StubState       state;
    uint8_t         prologue[16];   // first 16 bytes of the stub
    bool            has_syscall_insn; // contains 0F 05 (syscall) or 0F 34 (sysenter)
};

/// Check a specific ntdll export's stub integrity.
VH_API vh::Result<StubInfo> check_stub(const char* function_name) noexcept;

/// Audit all common Nt* syscall stubs.
VH_API vh::Result<std::vector<StubInfo>> audit_stubs() noexcept;

/// Count how many stubs are hooked.
VH_API uint32_t hooked_stub_count() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine syscall integrity profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class SyscallCheck : uint32_t {
    StubPrologueCheck   = 1u << 0,
    SSNConsistency      = 1u << 1,
    SyscallInsnPresent  = 1u << 2,
    NtdllTextCRC        = 1u << 3,
    IndirectGadgetScan  = 1u << 4,
    KnownDllsCompare    = 1u << 5,
    SyscallRetGadget    = 1u << 6,
};

/// Bitmask of syscall checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::syscall_fence
