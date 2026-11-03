#pragma once
/**
 * VanHooks — /proc/self/maps scrubbing
 *
 * Hides VanHooks memory regions from /proc/self/maps by:
 *   1. Tracking all VH allocations (trampolines, pools, etc.)
 *   2. Hooking open/read on /proc/self/maps to filter our entries
 *   3. Renaming anonymous regions to look like legitimate mappings
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>

namespace vh::maps_scrub {

VH_API Status init() noexcept;
VH_API Status shutdown() noexcept;

VH_API Status register_region(void* addr, size_t size) noexcept;
VH_API Status unregister_region(void* addr) noexcept;

VH_API Status enable_filter() noexcept;
VH_API Status disable_filter() noexcept;

VH_API bool is_active() noexcept;

VH_API size_t hidden_region_count() noexcept;

} // namespace vh::maps_scrub
