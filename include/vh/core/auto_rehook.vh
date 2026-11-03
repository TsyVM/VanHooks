#pragma once
/**
 * VanHooks — Automatic re-hooking engine
 *
 * If a hook is detected and removed by an anti-cheat, the engine
 * transparently reinstalls from a cold backup — relocating to a
 * different code cave / trampoline address each time.  Combined
 * with polymorphic trampolines, each reinstallation looks unique.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>
#include <functional>

namespace vh::rehook {

struct RehookConfig {
    uint32_t check_interval_ms    = 100;
    uint32_t max_reinstall_count  = 10;
    bool     use_polymorphic      = true;
    bool     relocate_trampoline  = true;
    bool     silent               = true;
};

using RehookCallback = std::function<void(void* target, uint32_t attempt)>;

VH_API Status init(const RehookConfig& cfg = {}) noexcept;
VH_API Status shutdown() noexcept;

VH_API Status watch(void* target, void* detour, void** original_out,
                    RehookCallback on_rehook = {}) noexcept;

VH_API Status unwatch(void* target) noexcept;

VH_API Status unwatch_all() noexcept;

struct WatchStatus {
    void*    target          = nullptr;
    bool     hook_intact     = false;
    uint32_t reinstall_count = 0;
    uint64_t last_check_ms   = 0;
};

VH_API WatchStatus query(void* target) noexcept;

VH_API size_t watched_count() noexcept;
VH_API size_t total_reinstalls() noexcept;

} // namespace vh::rehook
