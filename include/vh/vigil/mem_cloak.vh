#pragma once

/**
 * vh/vigil/mem_cloak.vh — Memory cloaking against AC scanners
 *
 * Anti-cheat engines scan process memory at predictable intervals,
 * looking for:
 *
 *   * Modified .text sections (hook bytes)
 *   * Executable pages that are not backed by a PE image (MEM_PRIVATE)
 *   * Signature patterns (byte sequences known to belong to cheat tools)
 *   * Anomalous page protections (RWX, or RW→RX transitions)
 *
 * This module provides per-technique cloaking that hides VanHooks'
 * memory footprint from these scans.
 *
 * Techniques
 * ──────────
 *
 *   **Page cloak** — temporarily restore original bytes before a scan
 *   window and re-apply hooks after.  Requires ac_heartbeat timing.
 *
 *   **Signature morph** — continuously mutate trampoline byte patterns
 *   so static signatures never match.  Builds on polymorphic.vh.
 *
 *   **Allocation disguise** — make MEM_PRIVATE executable pages appear
 *   as MEM_IMAGE by creating a SEC_IMAGE mapping as backing.
 *
 *   **Protection normalise** — ensure all VanHooks pages follow the
 *   RW→RX lifecycle and never expose RWX, which is a universal red flag.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_MEM_CLOAK  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>

#include <cstdint>
#include <span>
#include <string_view>

namespace vh::ac::mem_cloak {

// ─────────────────────────────────────────────────────────────────────────────
//  Page cloaking — scan-window-aware hook toggling
// ─────────────────────────────────────────────────────────────────────────────

/// Enable page cloaking for all active VanHooks.
/// During AC scan windows (from ac_heartbeat), hooks are temporarily
/// removed and original bytes restored.  After the scan window closes,
/// hooks are re-applied.
///
/// Requires ac_heartbeat monitoring to be active.
VH_API vh::Result<void> enable_page_cloak() noexcept;

/// Disable page cloaking.  Hooks remain in their current state.
VH_API void disable_page_cloak() noexcept;

/// Is page cloaking currently active?
VH_API bool page_cloak_active() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Signature morphing — continuous trampoline mutation
// ─────────────────────────────────────────────────────────────────────────────

struct MorphConfig {
    uint32_t    interval_ms = 3000;     // re-morph every N ms
    bool        junk_insertion = true;   // insert random dead code
    bool        register_shuffle = true; // randomise register allocation
    bool        nop_sled_vary = true;    // vary NOP sled lengths/encodings
};

/// Enable continuous signature morphing on all active trampolines.
/// Builds on top of vh::polymorphic — requires VH_ENABLE_POLYMORPHIC.
VH_API vh::Result<void> enable_sig_morph(const MorphConfig& cfg = {}) noexcept;

/// Disable morphing.  Trampolines stay in their current (last-morphed) form.
VH_API void disable_sig_morph() noexcept;

/// Force an immediate re-morph of all trampolines.
VH_API vh::Result<uint32_t> morph_now() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Allocation disguise — MEM_PRIVATE → MEM_IMAGE
// ─────────────────────────────────────────────────────────────────────────────

/// Allocate an executable region that appears as MEM_IMAGE in
/// NtQueryVirtualMemory.  Uses a SEC_IMAGE mapping backed by a
/// temporary PE on disk (or an existing sacrificial DLL).
///
/// The returned address is usable for trampoline code.  Free it
/// with disguised_free().
VH_API vh::Result<void*> disguised_alloc(
    uint32_t    size,
    std::string_view sacrificial_dll = {}) noexcept;

/// Free a region allocated with disguised_alloc().
VH_API void disguised_free(void* addr) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Protection normalisation — enforce RW→RX lifecycle
// ─────────────────────────────────────────────────────────────────────────────

/// Audit all VanHooks-owned pages and fix any that violate the
/// RW→RX lifecycle (no RWX, no W+X simultaneous).
/// Returns the number of pages corrected.
VH_API vh::Result<uint32_t> normalise_protections() noexcept;

/// Enable continuous monitoring that prevents VanHooks from ever
/// leaving a page in an anomalous protection state.
VH_API vh::Result<void> enable_protection_monitor() noexcept;

/// Disable continuous monitoring.
VH_API void disable_protection_monitor() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Region inventory — what VanHooks owns
// ─────────────────────────────────────────────────────────────────────────────

struct OwnedRegion {
    void*       base;
    uint32_t    size;
    uint32_t    protection;     // current PAGE_* flags
    bool        disguised;      // allocated via disguised_alloc
    bool        cloaked;        // currently in cloaked (original bytes) state
};

/// Enumerate all memory regions owned by VanHooks.
VH_API std::span<const OwnedRegion> owned_regions() noexcept;

} // namespace vh::ac::mem_cloak
