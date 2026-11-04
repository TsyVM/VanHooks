#pragma once
/**
 * VanHooks — Android ARM64 hooking
 *
 * Inline hooks for native (NDK) libraries and ART method hooking
 * for Java/Kotlin methods.  Requires root + Magisk/KernelSU.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::android_hook {

enum class HookType : uint8_t {
    InlineNative   = 0,
    ArtMethod      = 1,
    PltGot         = 2,
};

struct NativeHookInfo {
    std::string library;
    std::string symbol;
    std::uintptr_t target    = 0;
    std::uintptr_t detour    = 0;
    std::uintptr_t original  = 0;
    HookType type            = HookType::InlineNative;
    bool active              = false;
};

struct ArtMethodInfo {
    std::string class_name;
    std::string method_name;
    std::string signature;
    std::uintptr_t art_method_ptr = 0;
    std::uintptr_t entry_point    = 0;
};

VH_API Result<NativeHookInfo> hook_native(const char* library, const char* symbol,
                                           void* detour) noexcept;

VH_API Result<void> unhook_native(const NativeHookInfo& info) noexcept;

VH_API Result<NativeHookInfo> hook_plt(const char* caller_lib, const char* target_lib,
                                        const char* symbol, void* detour) noexcept;

VH_API Result<ArtMethodInfo> resolve_art_method(const char* class_name,
                                                 const char* method_name,
                                                 const char* signature) noexcept;

VH_API Result<void> hook_art_method(const ArtMethodInfo& method,
                                     std::uintptr_t replacement) noexcept;

VH_API bool is_art_runtime() noexcept;

VH_API std::string get_art_version() noexcept;

VH_API std::vector<std::string> enumerate_native_libraries() noexcept;

} // namespace vh::android_hook
