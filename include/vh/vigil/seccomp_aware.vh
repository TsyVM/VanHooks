#pragma once
/**
 * VanHooks — seccomp filter awareness
 *
 * Detects active seccomp-bpf filters and determines which syscalls
 * are permitted before attempting direct syscall invocation.
 * Falls back to libc wrappers when seccomp blocks raw syscalls.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::seccomp_aware {

enum class SeccompMode : uint8_t {
    Disabled = 0,
    Strict   = 1,
    Filter   = 2,
};

VH_API SeccompMode query_mode() noexcept;

VH_API bool is_seccomp_active() noexcept;

VH_API bool is_syscall_allowed(long syscall_nr) noexcept;

VH_API bool can_use_direct_syscalls() noexcept;

VH_API bool can_use_ptrace() noexcept;

VH_API bool can_use_process_vm() noexcept;

} // namespace vh::seccomp_aware
