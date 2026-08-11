#pragma once

/**
 * vh/breakpoint.hpp — Software and Hardware Breakpoints (public API)
 *
 * Re-exports vanhooks::breakpoint under vh::breakpoint, matching the
 * style of vh/pe.hpp and vh/symbols.hpp.
 *
 * Quick start:
 * ────────────
 *   #include <vh/vh.hpp>   // or just <vh/breakpoint.hpp>
 *
 *   // Software breakpoint — INT3 + VEH (Windows) / SIGTRAP (Linux)
 *   auto bp = vh::breakpoint::set_software(target_addr, [](uintptr_t addr) {
 *       printf("SW hit @ 0x%llx\n", (unsigned long long)addr);
 *       return vh::breakpoint::Action::Continue;
 *   });
 *   if (!bp) { /* handle error */ }
 *
 *   // Hardware breakpoint — DR0-DR3 (x86-64 only)
 *   auto hw = vh::breakpoint::set_hardware(
 *       addr,
 *       vh::breakpoint::HwCondition::Execute,
 *       vh::breakpoint::HwSize::Byte,
 *       [](uintptr_t a){ return vh::breakpoint::Action::Continue; });
 *
 *   // Breakpoints are removed automatically when the guard goes out of scope.
 *   bp->remove();  // or let it destruct
 *
 * Guard on new threads (Windows, hardware BPs only):
 *   // Call from DLL_THREAD_ATTACH:
 *   hw->apply_to_new_thread(hthread_of_new_thread);
 *
 * Requires: VH_BREAKPOINT_ENABLED (set by CMake option VH_ENABLE_BREAKPOINT).
 */

#include <vanhooks/breakpoint.hpp>
#include "result.hpp"

namespace vh::breakpoint {

// ── Re-export core types ──────────────────────────────────────────────────────

using Action      = vanhooks::breakpoint::Action;
using HwCondition = vanhooks::breakpoint::HwCondition;
using HwSize      = vanhooks::breakpoint::HwSize;
using Callback    = vanhooks::breakpoint::Callback;
using Breakpoint  = vanhooks::breakpoint::Breakpoint;

// ── Convenience factories ─────────────────────────────────────────────────────

/**
 * Install a software breakpoint (INT3) at @p address.
 * @returns Owning Breakpoint RAII guard on success.
 */
[[nodiscard]]
inline Result<Breakpoint> set_software(uintptr_t address, Callback cb) {
    return vanhooks::breakpoint::set_software(address, std::move(cb));
}

/**
 * Install a hardware (DR0–DR3) breakpoint at @p address on all current threads.
 * x86-64 only; returns Error::Unsupported on other architectures.
 * Returns Error::BreakpointSlotExhausted if all four DR slots are taken.
 */
[[nodiscard]]
inline Result<Breakpoint> set_hardware(uintptr_t   address,
                                        HwCondition condition,
                                        HwSize      size,
                                        Callback    cb) {
    return vanhooks::breakpoint::set_hardware(address, condition, size, std::move(cb));
}

} // namespace vh::breakpoint
