#pragma once
/**
 * VanHooks — CFG / XFG bypass hardening
 *
 * Registers trampoline addresses as valid Control Flow Guard call
 * targets so indirect calls through hooked functions pass CFG
 * validation on Windows 10+.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>

namespace vh::cfg {

VH_API bool is_cfg_enabled() noexcept;
VH_API bool is_xfg_enabled() noexcept;

VH_API Status register_valid_target(void* address) noexcept;
VH_API Status register_valid_targets(void** addresses, size_t count) noexcept;

VH_API Status unregister_valid_target(void* address) noexcept;

VH_API bool is_valid_target(void* address) noexcept;

} // namespace vh::cfg
