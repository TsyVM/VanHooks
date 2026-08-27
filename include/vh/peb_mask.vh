#pragma once

/**
 * vh/peb_mask.vh — PEB anti-analysis masking.
 *
 * Cleans the PEB fields user-mode anti-debug and behavioural analysers
 * classically read:
 *
 *   * ``PEB.BeingDebugged``              — the ``IsDebuggerPresent`` bit.
 *   * ``PEB.NtGlobalFlag``               — set to ``0x70`` under a debugger;
 *     cleared to ``0`` to match a clean process.
 *   * ``PEB.ProcessHeap.Flags`` /
 *     ``PEB.ProcessHeap.ForceFlags``     — set to ``2/0`` (matches ``HEAP_GROWABLE``);
 *     cleared under-debugger flags ``0x40000060`` / ``0x40000060``.
 *
 * Optional (``unlink_modules``): unlink one or more modules from the three
 * ``PEB.Ldr`` module lists (``InLoad`` / ``InMemory`` / ``InInit``).  The
 * module remains loaded and executable — it just stops appearing in
 * ``PEB.Ldr`` walks (which is what ``EnumProcessModules`` and every
 * user-mode module enumerator use).
 *
 * All changes are recorded so :cpp:func:`restore` reverses them exactly.
 *
 * Platform: Windows.  POSIX returns ``Unsupported``.
 */

#include "result.vh"
#include <vanhooks/vanhooks.hpp>

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace vh::peb_mask {

/// Individual switches — combine with bitwise OR.
enum Flags : std::uint32_t {
    None            = 0,
    BeingDebugged   = 1u << 0,
    NtGlobalFlag    = 1u << 1,
    HeapFlags       = 1u << 2,
    All             = BeingDebugged | NtGlobalFlag | HeapFlags,
};

/// Apply the specified masks.  Idempotent; re-applying is a no-op.
[[nodiscard]] vh::Result<void> apply(std::uint32_t flags = All) noexcept;

/// Restore everything :cpp:func:`apply` modified.  Idempotent.
[[nodiscard]] vh::Result<void> restore() noexcept;

/// Which masks are currently applied.
[[nodiscard]] std::uint32_t active_flags() noexcept;

/**
 * Unlink ``module_name`` (case-insensitive) from all three ``PEB.Ldr`` module
 * lists.  The module stays loaded; a subsequent :cpp:func:`relink` puts it
 * back at the tail of each list.
 */
[[nodiscard]] vh::Result<void> unlink_module(std::string_view module_name) noexcept;

/// Reverse a prior :cpp:func:`unlink_module`.  No-op if not unlinked.
[[nodiscard]] vh::Result<void> relink_module(std::string_view module_name) noexcept;

/// Names of currently-unlinked modules.
[[nodiscard]] std::vector<std::string> unlinked_modules() noexcept;

} // namespace vh::peb_mask
