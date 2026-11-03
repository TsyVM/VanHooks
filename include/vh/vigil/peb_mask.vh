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

#include <vh/result.vh>
#include <vanhooks/vanhooks.vh>

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

// ─────────────────────────────────────────────────────────────────────────────
//  LDR / memory integrity validation  (derived from CfAcCompat, NiHooks-CF)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validate that ``hModule``'s PEB LDR entry has the expected base name.
 *
 * Walks ``PEB.Ldr.InMemoryOrderModuleList`` to find the entry whose
 * ``DllBase`` matches ``hModule``, then compares the last path component of
 * ``FullDllName`` against ``expected_name`` (case-insensitive).
 *
 * Anti-cheat engines (XIGNCODE3, BattlEye) walk the LDR list on every scan
 * cycle.  A DLL loaded by proxy whose entry shows a mismatched name is
 * trivially flagged.  Call this during ``DLL_PROCESS_ATTACH`` (before any
 * hook installation) to confirm the OS loader registered the module under the
 * name it expects.
 *
 * Returns ``true`` if the entry is found and the name matches.
 * Returns ``false`` if the module is not in the LDR list or the name differs.
 * Returns ``Error::Unsupported`` on non-Windows platforms.
 */
[[nodiscard]] vh::Result<bool> validate_ldr_entry(
    void*            hModule,
    std::string_view expected_name) noexcept;

/**
 * Verify that all committed memory pages belonging to ``hModule`` are
 * ``MEM_IMAGE`` (not ``MEM_PRIVATE``).
 *
 * Kernel-mode anti-cheat drivers (HGWC, Ricochet) flag ``MEM_PRIVATE``
 * committed pages inside an image range as injected shellcode.  A legitimate
 * proxy DLL loaded through the Windows loader will have only ``MEM_IMAGE``
 * regions; any ``MEM_PRIVATE`` page is evidence of post-load patching.
 *
 * The watchdog calls this automatically for every hooked module when
 * ``Config::enable_integrity_watchdog`` and
 * ``Config::watchdog_check_mem_image`` are both ``true``.
 *
 * Returns ``true`` if all committed regions are ``MEM_IMAGE``.
 * Returns ``false`` and populates ``*out_private_count`` (if non-null) with
 * the number of offending regions found.
 * Returns ``Error::Unsupported`` on non-Windows platforms.
 */
[[nodiscard]] vh::Result<bool> validate_mem_image(
    void*     hModule,
    uint32_t* out_private_count = nullptr) noexcept;

} // namespace vh::peb_mask
