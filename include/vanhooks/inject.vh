#pragma once

/**
 * vanhooks/inject.vh — SDK-stripped injection internals.
 *
 * Exposes only the types that the public vh/inject.vh header needs:
 * InjHandle, Method enum, and InjRecord (for introspection).
 * The InjectManager class itself is private and not exposed.
 */

#include "vanhooks.vh"

#include <cstdint>
#include <string>
#include <optional>

#ifdef VH_PLATFORM_WINDOWS
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace vanhooks::inject {

struct InjHandle {
    uint64_t id = 0;
    bool valid()            const noexcept { return id != 0; }
    explicit operator bool()const noexcept { return valid(); }
    bool operator==(const InjHandle&) const noexcept = default;
};

enum class Method : uint8_t {
    LoadLibrary,
    ManualMap,
    ThreadHijack,
    ApcQueue,
};

struct InjRecord {
    uint64_t    id          = 0;
    uint32_t    pid         = 0;
    Method      method      = Method::LoadLibrary;
    std::string tag;

#ifdef VH_PLATFORM_WINDOWS
    HANDLE      proc_handle = INVALID_HANDLE_VALUE;
    uintptr_t   remote_base = 0;
    HMODULE     module_base = nullptr;
    bool        manual_map  = false;
#endif
};

} // namespace vanhooks::inject
