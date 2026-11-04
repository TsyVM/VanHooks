#pragma once
/**
 * VanHooks — SELinux / AppArmor awareness
 *
 * Detects mandatory access control (MAC) policies and determines
 * how they constrain hooking operations.  Covers both SELinux
 * (enterprise / Android) and AppArmor (Ubuntu / SUSE).
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>

namespace vh::selinux_aware {

enum class MacSystem : uint8_t {
    None       = 0,
    SELinux    = 1,
    AppArmor   = 2,
    Both       = 3,
};

enum class EnforcementMode : uint8_t {
    Disabled   = 0,
    Permissive = 1,
    Enforcing  = 2,
};

struct MacInfo {
    MacSystem system            = MacSystem::None;
    EnforcementMode selinux     = EnforcementMode::Disabled;
    EnforcementMode apparmor    = EnforcementMode::Disabled;
    std::string selinux_context;
    std::string apparmor_profile;
};

VH_API MacInfo query_mac() noexcept;

VH_API MacSystem get_active_mac() noexcept;

VH_API EnforcementMode get_selinux_mode() noexcept;

VH_API std::string get_selinux_context() noexcept;

VH_API EnforcementMode get_apparmor_mode() noexcept;

VH_API std::string get_apparmor_profile() noexcept;

VH_API bool can_ptrace() noexcept;

VH_API bool can_mmap_exec() noexcept;

VH_API bool can_modify_proc() noexcept;

VH_API bool is_confined() noexcept;

} // namespace vh::selinux_aware
