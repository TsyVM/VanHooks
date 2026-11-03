#pragma once

/**
 * vh/detail/callsite_bridge.vh
 * Shared forward-declaration of the eng_hook_callsite bridge function.
 *
 * Included by both vh.vh and group.vh to eliminate the duplicate declaration
 * (ODR/maintenance hazard fix — Issue 10).  If the signature ever changes,
 * update it here only.
 */

#include <string>
#include "../result.vh"
#include <vanhooks/vanhooks.vh>

namespace vh::detail {
    Result<vanhooks::HookHandle> eng_hook_callsite(
        vanhooks::Engine*, uintptr_t site_addr,
        void* detour, void** orig,
        bool thread_safe, std::string tag);
} // namespace vh::detail
