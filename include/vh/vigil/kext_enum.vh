#pragma once
/**
 * VanHooks — Kernel extension enumeration
 *
 * macOS equivalent of driver_fence.  Enumerates loaded kexts via
 * IOKit and identifies known anti-cheat kernel extensions.
 * On macOS 11+ (Apple Silicon), kexts are deprecated in favour of
 * System Extensions (dexts), which are also detected.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::kext_enum {

struct KextInfo {
    std::string   bundle_id;
    std::string   version;
    std::uint64_t load_address  = 0;
    std::uint64_t size          = 0;
    bool          is_apple      = false;
    bool          is_ac_related = false;
};

struct SystemExtInfo {
    std::string bundle_id;
    std::string team_id;
    std::string category;
    bool        is_active     = false;
    bool        is_ac_related = false;
};

VH_API std::vector<KextInfo> enumerate_kexts() noexcept;

VH_API std::vector<SystemExtInfo> enumerate_system_extensions() noexcept;

VH_API bool has_ac_kext() noexcept;

VH_API bool has_ac_system_extension() noexcept;

VH_API std::vector<std::string> get_ac_kext_ids() noexcept;

} // namespace vh::kext_enum
