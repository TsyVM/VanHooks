#pragma once
/**
 * VanHooks — Android anti-cheat awareness
 *
 * Detects SafetyNet / Play Integrity, game-specific anti-cheat
 * solutions, root detection, and environment tampering checks
 * common on Android.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::android_ac_aware {

enum class IntegrityLevel : uint8_t {
    Unknown      = 0,
    NoIntegrity  = 1,
    BasicDevice  = 2,
    DeviceCts    = 3,
    StrongDevice = 4,
};

struct SafetyNetInfo {
    bool available          = false;
    bool cts_profile_match  = false;
    bool basic_integrity    = false;
    IntegrityLevel level    = IntegrityLevel::Unknown;
};

struct RootDetectionInfo {
    bool su_binary          = false;
    bool magisk_detected    = false;
    bool kernelsu_detected  = false;
    bool busybox_present    = false;
    bool test_keys          = false;
    bool selinux_permissive = false;
    bool props_modified     = false;
};

struct AcModuleInfo {
    std::string name;
    std::string package;
    std::string native_lib;
    bool detected           = false;
};

VH_API SafetyNetInfo query_safety_net() noexcept;

VH_API RootDetectionInfo query_root_detection() noexcept;

VH_API std::vector<AcModuleInfo> detect_ac_modules() noexcept;

VH_API bool is_play_integrity_active() noexcept;

VH_API bool is_root_hidden() noexcept;

VH_API bool is_frida_detected() noexcept;

VH_API bool is_xposed_present() noexcept;

VH_API bool has_tampered_signature() noexcept;

VH_API bool is_debuggable() noexcept;

VH_API bool is_emulator() noexcept;

} // namespace vh::android_ac_aware
