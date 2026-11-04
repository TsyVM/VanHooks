#pragma once
/**
 * VanHooks — Proton/Wine awareness
 *
 * Detects Wine and Proton (Steam Deck / Linux gaming) environments.
 * Determines which Windows API calls are translated vs native,
 * helping hooks adapt to the translation layer.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>

namespace vh::proton_aware {

enum class WineLayer : uint8_t {
    None       = 0,
    Wine       = 1,
    Proton     = 2,
    CrossOver  = 3,
};

struct WineInfo {
    WineLayer layer         = WineLayer::None;
    std::string version;
    std::string host_os;
    bool is_wow64           = false;
    bool has_esync          = false;
    bool has_fsync          = false;
    bool has_ntsync         = false;
};

VH_API WineInfo query_wine_environment() noexcept;

VH_API bool is_wine() noexcept;

VH_API bool is_proton() noexcept;

VH_API WineLayer get_wine_layer() noexcept;

VH_API std::string get_wine_version() noexcept;

VH_API bool has_native_wayland() noexcept;

VH_API bool has_native_vulkan() noexcept;

VH_API bool is_syscall_emulated(const char* dll, const char* func) noexcept;

VH_API bool should_use_native_hooks() noexcept;

VH_API bool should_use_windows_hooks() noexcept;

} // namespace vh::proton_aware
