#pragma once
/**
 * VanHooks — link_map unlinking (LD_PRELOAD / dlopen stealth)
 *
 * Removes a loaded shared object from the dynamic linker's link_map
 * chain so dl_iterate_phdr, dlsym lookups, and /proc/self/maps
 * enumerations cannot find it.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::link_map_hide {

VH_API Status hide_module(const char* module_name) noexcept;

VH_API Status unhide_module(const char* module_name) noexcept;

VH_API bool is_hidden(const char* module_name) noexcept;

VH_API size_t hidden_count() noexcept;

VH_API Status hide_self() noexcept;

} // namespace vh::link_map_hide
