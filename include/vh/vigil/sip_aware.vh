#pragma once
/**
 * VanHooks — System Integrity Protection awareness
 *
 * Detects macOS SIP state and determines which hook strategies are
 * viable given the current protection level.  SIP restricts ptrace,
 * task_for_pid, DYLD_INSERT_LIBRARIES, and code injection for
 * Apple-signed binaries.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::sip_aware {

enum class SipStatus : std::uint8_t {
    Unknown  = 0,
    Enabled  = 1,
    Disabled = 2,
    Partial  = 3,
};

struct SipFlags {
    bool filesystem_protection     = false;
    bool kext_signing               = false;
    bool task_for_pid_restriction  = false;
    bool debugging_restriction     = false;
    bool dtrace_restriction        = false;
    bool nvram_protection          = false;
    bool apple_internal_reserved   = false;
};

VH_API SipStatus query_sip_status() noexcept;

VH_API SipFlags query_sip_flags() noexcept;

VH_API bool can_ptrace_targets() noexcept;

VH_API bool can_task_for_pid() noexcept;

VH_API bool can_inject_dyld_insert() noexcept;

VH_API bool can_load_unsigned_kexts() noexcept;

VH_API bool is_amfi_enforced() noexcept;

} // namespace vh::sip_aware
