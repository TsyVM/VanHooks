#pragma once

/**
 * vh/veh_hook.vh — Vectored-exception-handler hook.
 *
 * Places a software breakpoint (``0xCC`` on x86/x64, ``BRK #0`` on ARM64)
 * at the target address.  A process-wide VEH filter catches the resulting
 * exception, invokes the user callback with a :cpp:class:`vanhooks::MidContext`,
 * temporarily removes the breakpoint, single-steps past the original
 * instruction, then reinstalls the breakpoint.
 *
 * Coexists with :cpp:enum:`vanhooks::HookKind::HwBp` (which uses DR
 * registers) — this variant works on ARM64 and on x86 which have DR limits
 * or no DRs at all.  Only one breakpoint byte is written per hook, and it
 * lives inside the target's ``.text``, so ``.text`` hashes will notice
 * the same way they notice a trampoline patch.
 *
 * Up to 256 concurrent VEH hooks per process.
 */

#include "result.vh"
#include <vanhooks/vanhooks.vh>

#include <cstddef>
#include <cstdint>
#include <string>

namespace vh::veh_hook {

/// Options.
struct Options {
    std::string tag;
};

/// Opaque handle identifying an installed VEH hook.
struct Handle {
    std::uint64_t id = 0;
    [[nodiscard]] bool valid() const noexcept { return id != 0; }
};

/// Install a VEH hook at ``target``.  ``callback`` fires each time execution
/// reaches ``target``; on return the original instruction is re-executed and
/// the breakpoint reinstalls itself for the next hit.
[[nodiscard]] vh::Result<Handle> install(void*                target,
                                         vanhooks::MidCallback callback,
                                         Options              opts = {}) noexcept;

/// Remove the hook and restore the original byte at the target address.
[[nodiscard]] vh::Result<void> remove(Handle h) noexcept;

/// Remove all VEH hooks installed by this module.  Called automatically
/// from :cpp:func:`shutdown`.
void remove_all() noexcept;

/// Detach the VEH filter and forget all installed hooks.  Idempotent.
void shutdown() noexcept;

/// Number of hooks currently active.
[[nodiscard]] std::size_t active_count() noexcept;

} // namespace vh::veh_hook
