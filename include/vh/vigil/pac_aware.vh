#pragma once
/**
 * VanHooks — ARM64e PAC (Pointer Authentication) awareness
 *
 * Apple Silicon uses pointer authentication codes to sign return
 * addresses and function pointers.  PAC breaks traditional hooking
 * by invalidating tampered pointers.  This module detects PAC state,
 * provides PAC stripping utilities, and reports which hook strategies
 * remain viable under PAC enforcement.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::pac_aware {

enum class PacSupport : std::uint8_t {
    Unavailable = 0,
    Available   = 1,
    Enforced    = 2,
};

struct PacInfo {
    PacSupport data_pac  = PacSupport::Unavailable;
    PacSupport code_pac  = PacSupport::Unavailable;
    bool       arm64e    = false;
    bool       kernel_pac = false;
};

VH_API PacInfo query_pac_support() noexcept;

VH_API bool is_pac_enforced() noexcept;

VH_API std::uintptr_t strip_pac(std::uintptr_t ptr) noexcept;

VH_API void* strip_pac_ptr(void* ptr) noexcept;

VH_API bool is_pointer_signed(std::uintptr_t ptr) noexcept;

VH_API bool can_use_trampoline_hooks() noexcept;

VH_API bool can_use_got_hooks() noexcept;

VH_API bool can_use_vtable_hooks() noexcept;

} // namespace vh::pac_aware
