#pragma once
/**
 * VanHooks — Android injection
 *
 * Zygote injection, dlopen via linker namespace, /proc/pid/mem
 * writing.  Provides multiple injection vectors for Android
 * native library loading.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>

namespace vh::android_inject {

enum class InjectionMethod : uint8_t {
    ZygoteHook      = 0,
    PtraceDlopen    = 1,
    ProcMem         = 2,
    LinkerNamespace = 3,
};

struct InjectionResult {
    InjectionMethod method = InjectionMethod::PtraceDlopen;
    std::uintptr_t base    = 0;
    std::string library_path;
    bool success           = false;
};

VH_API Result<InjectionResult> inject_library(std::uint32_t pid,
                                               const char* library_path,
                                               InjectionMethod method) noexcept;

VH_API Result<InjectionResult> inject_library_auto(std::uint32_t pid,
                                                    const char* library_path) noexcept;

VH_API bool can_ptrace_pid(std::uint32_t pid) noexcept;

VH_API bool can_access_proc_mem(std::uint32_t pid) noexcept;

VH_API bool is_zygote_available() noexcept;

VH_API bool has_root() noexcept;

VH_API bool has_magisk() noexcept;

VH_API bool has_kernelsu() noexcept;

VH_API std::string get_linker_namespace(std::uint32_t pid) noexcept;

} // namespace vh::android_inject
