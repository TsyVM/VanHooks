#pragma once
/**
 * VanHooks — Tamper detection + anti-dump
 *
 * Integrity canaries on trampoline pages and engine allocations.
 * If an AC patches a trampoline or dumps engine memory, the system
 * detects it and can scrub, relocate, or alert.  Guard pages on
 * VanHooks' own allocations trigger on external reads.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>
#include <functional>

namespace vh::tamper {

enum class TamperAction : uint8_t {
    Alert,
    Scrub,
    Relocate,
    Rehook,
    Silent,
};

using TamperCallback = std::function<void(void* address, TamperAction suggested)>;

struct TamperConfig {
    bool           enable_canaries    = true;
    bool           enable_guard_pages = true;
    bool           enable_crc_check   = true;
    uint32_t       check_interval_ms  = 250;
    TamperAction   default_action     = TamperAction::Rehook;
    TamperCallback on_tamper;
};

VH_API Status init(const TamperConfig& cfg = {}) noexcept;
VH_API Status shutdown() noexcept;

VH_API Status protect_region(void* base, size_t size) noexcept;
VH_API Status unprotect_region(void* base, size_t size) noexcept;

VH_API Status place_canary(void* page, size_t page_size) noexcept;
VH_API bool   verify_canary(void* page) noexcept;
VH_API bool   verify_all() noexcept;

VH_API Status enable_guard(void* base, size_t size) noexcept;
VH_API Status disable_guard(void* base, size_t size) noexcept;

VH_API uint32_t compute_crc(const void* base, size_t size) noexcept;
VH_API bool     verify_crc(const void* base, size_t size, uint32_t expected) noexcept;

VH_API size_t tamper_count() noexcept;

} // namespace vh::tamper
