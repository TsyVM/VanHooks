#pragma once
/**
 * VanHooks — Landlock awareness
 *
 * Detects Landlock LSM restrictions on file and network access.
 * Landlock is available on Linux 5.13+ and allows unprivileged
 * processes to sandbox themselves.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::landlock_aware {

enum class LandlockStatus : uint8_t {
    Unavailable  = 0,
    Available    = 1,
    Active       = 2,
};

struct LandlockInfo {
    LandlockStatus status = LandlockStatus::Unavailable;
    std::uint32_t abi_version = 0;
    bool fs_restrictions   = false;
    bool net_restrictions  = false;
};

VH_API LandlockInfo query_landlock() noexcept;

VH_API bool is_landlock_available() noexcept;

VH_API bool is_landlock_active() noexcept;

VH_API std::uint32_t get_abi_version() noexcept;

VH_API bool has_fs_restrictions() noexcept;

VH_API bool has_net_restrictions() noexcept;

VH_API bool can_write_path(const char* path) noexcept;

VH_API bool can_read_path(const char* path) noexcept;

} // namespace vh::landlock_aware
