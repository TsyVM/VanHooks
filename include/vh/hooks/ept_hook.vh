#pragma once
/**
 * VanHooks — EPT / hypervisor-assisted hooking
 *
 * Splits a page's execute and read permissions at the EPT (Extended
 * Page Table) level.  Read/write accesses see the original bytes;
 * execute accesses see the hooked bytes.  Completely invisible to
 * usermode memory scanners.
 *
 * Requires a compatible hypervisor driver loaded in ring-0.
 * The user-mode API communicates via DeviceIoControl (Windows)
 * or ioctl (Linux) to the VanHooks hypervisor component.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>

namespace vh::ept {

struct EptConfig {
    bool     auto_detect_hypervisor = true;
    uint32_t max_split_pages        = 256;
};

VH_API Status init(const EptConfig& cfg = {}) noexcept;
VH_API Status shutdown() noexcept;

VH_API bool is_available() noexcept;

struct EptHook {
    void*    target_page    = nullptr;
    void*    hooked_page    = nullptr;
    void*    original_page  = nullptr;
    uint64_t page_pfn       = 0;
    bool     active         = false;
};

VH_API Result<EptHook> install(void* target_addr, const void* patch,
                               size_t patch_size) noexcept;

VH_API Status remove(EptHook& hook) noexcept;

VH_API Status enable(EptHook& hook) noexcept;
VH_API Status disable(EptHook& hook) noexcept;

VH_API size_t active_hook_count() noexcept;

VH_API bool verify_split(const EptHook& hook) noexcept;

} // namespace vh::ept
