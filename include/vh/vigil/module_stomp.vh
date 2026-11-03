#pragma once

/**
 * vh/module_stomp.vh — Module stomping / phantom-DLL payload placement.
 *
 * Loads a benign signed system DLL into the process (or reuses one that's
 * already loaded), then overwrites a slice of its ``.text`` with a
 * caller-supplied shellcode payload.  The payload thereafter executes at
 * an address that:
 *
 *   * belongs to a signed, on-disk-backed image (``MEM_IMAGE`` VAD, not
 *     ``MEM_PRIVATE``);
 *   * is inside a section marked ``IMAGE_SCN_MEM_EXECUTE``;
 *   * is attributed to the host module by every user-mode module walker;
 *   * carries the host module's real name in memory scanners' string
 *     enumerations.
 *
 * The overwritten host bytes are recorded so :cpp:func:`restore` puts them
 * back exactly (assuming no cross-thread execution of the stomped range
 * during payload runtime — that's on the caller).
 *
 * Requirements
 * ------------
 *
 * The host module must have a ``.text`` region at least ``payload.size()``
 * bytes long and mapped writable-after-``VirtualProtect`` (all standard
 * Windows system DLLs qualify — Code Integrity Guard on the current process
 * will block the write, which the API surfaces as
 * :cpp:enum:`vanhooks::Error::MemoryProtectFailed`).
 *
 * Auto-selection: :cpp:func:`find_stomp_target` walks a curated shortlist
 * of "safe" hosts (rarely-called Windows utility DLLs whose ``.text``
 * regions are large and whose functions aren't hot-path) and returns a
 * pointer suitable to pass to :cpp:func:`stomp_at`.
 *
 * Platform: Windows.  POSIX returns ``Unsupported``.
 */

#include <vh/result.vh>
#include <vanhooks/vanhooks.vh>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace vh::module_stomp {

/// A single active stomp — returned by :cpp:func:`stomp` for later restore.
struct Stomp {
    void*                    address = nullptr;   ///< Where the payload was written.
    std::size_t              size    = 0;
    std::string              host_module;         ///< e.g. "amsi.dll"
    std::vector<std::uint8_t> saved;              ///< Original host bytes at [address, address+size).
    void*                    entry   = nullptr;   ///< Same as ``address`` unless a per-payload prologue was requested.
};

/// Options for :cpp:func:`stomp`.
struct Options {
    /// Host module name (base name, ".dll" appended if missing).  If empty,
    /// auto-select via :cpp:func:`find_stomp_target`.
    std::string_view host_module;

    /// Force ``LoadLibraryW(host_module)`` if the host isn't already loaded.
    bool load_if_absent = true;

    /// Offset inside the host's ``.text``.  0 = start; use a large offset to
    /// avoid overwriting the module's entry / dispatch table.  When 0 and
    /// ``auto_pick_offset`` is true, we scan for a stretch of ``.text``
    /// that appears to be padding / cold code.
    std::size_t offset = 0;

    /// Auto-choose an offset inside ``.text`` when ``offset == 0``.
    bool auto_pick_offset = true;

    /// Restore original protection after the write.  Default true — leaves
    /// the region ``PAGE_EXECUTE_READ`` after the stomp.
    bool restore_protection = true;
};

// ─────────────────────────────────────────────
//  Public entry points
// ─────────────────────────────────────────────

/**
 * Write ``payload`` into a host module's ``.text`` and return a
 * :cpp:class:`Stomp` handle.  Cast ``stomp.entry`` to your entry-point
 * signature and call it.
 */
[[nodiscard]] vh::Result<Stomp> stomp(std::span<const std::uint8_t> payload,
                                      Options opts = {}) noexcept;

/**
 * Lower-level: write to a specific address.  The address must be inside
 * a loaded PE image's executable region; the writer clears the enclosing
 * page's protection with ``VirtualProtect``.
 */
[[nodiscard]] vh::Result<Stomp> stomp_at(void*                            address,
                                         std::span<const std::uint8_t>    payload,
                                         Options                          opts = {}) noexcept;

/**
 * Reverse a stomp: rewrite the saved original bytes and restore protection.
 * The ``Stomp`` handle is consumed on success.
 */
[[nodiscard]] vh::Result<void> restore(Stomp&& stomp) noexcept;

/**
 * Return a candidate address inside a stomp-friendly module's ``.text`` with
 * at least ``bytes`` free.  Auto-loads a suitable host if one isn't already
 * present.
 */
[[nodiscard]] vh::Result<void*> find_stomp_target(std::size_t bytes,
                                                   std::string_view host_hint = {}) noexcept;

/// The curated list of host modules considered "safe" (rarely-called,
/// large ``.text``, no hot-path dispatch).  Purely informational.
[[nodiscard]] std::vector<std::string_view> default_host_list() noexcept;

} // namespace vh::module_stomp
