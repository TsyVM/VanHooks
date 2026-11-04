#pragma once
/**
 * VanHooks — iOS research module
 *
 * Research-phase module for jailbreak-based hooking via
 * Substrate, Substitute, or Ellekit.  Includes PAC handling
 * on A12+ and runtime introspection of Objective-C methods.
 *
 * NOTE: highly restricted platform; this module provides
 * detection and capability queries, not full hooking yet.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ios_research {

enum class JailbreakType : uint8_t {
    None          = 0,
    Substrate     = 1,
    Substitute    = 2,
    Ellekit       = 3,
    Dopamine      = 4,
    Unknown       = 255,
};

struct JailbreakInfo {
    JailbreakType type    = JailbreakType::None;
    std::string version;
    bool has_tfp0         = false;
    bool has_pac_bypass   = false;
    bool rootless         = false;
};

struct ObjcMethodInfo {
    std::string class_name;
    std::string selector;
    std::uintptr_t imp    = 0;
    bool is_class_method  = false;
};

VH_API JailbreakInfo detect_jailbreak() noexcept;

VH_API bool is_jailbroken() noexcept;

VH_API bool has_substrate() noexcept;

VH_API bool has_substitute() noexcept;

VH_API bool has_ellekit() noexcept;

VH_API bool can_hook_objc() noexcept;

VH_API Result<ObjcMethodInfo> resolve_objc_method(const char* class_name,
                                                    const char* selector) noexcept;

VH_API std::vector<std::string> enumerate_loaded_classes() noexcept;

VH_API bool has_pac_on_device() noexcept;

VH_API std::uintptr_t strip_pac_ios(std::uintptr_t ptr) noexcept;

} // namespace vh::ios_research
