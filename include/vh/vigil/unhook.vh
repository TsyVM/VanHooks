#pragma once

/**
 * vh/unhook.vh — User-mode module unhooking.
 *
 * Restores the ``.text`` section of a loaded module by comparing it against a
 * pristine copy of the same image and rewriting any bytes that differ.  This
 * strips EDR / AV inline hooks placed in system DLLs (ntdll, kernel32,
 * kernelbase, user32, …) before VanHooks itself installs anything.
 *
 * Two acquisition paths (Windows):
 *
 *   1. ``\KnownDlls\<name>`` — the loader's cached section object.  Mapped
 *      via ``NtOpenSection`` + ``NtMapViewOfSection``.  No file I/O; no path
 *      resolution; exact same image the loader used for the *first* copy.
 *
 *   2. Disk fallback — ``MapViewOfFile`` on ``System32\<name>``.  Used for
 *      modules not in ``\KnownDlls`` (user32 on some SKUs, third-party DLLs).
 *
 * On POSIX every entry point returns :cpp:enum:`vanhooks::Error::Unsupported`.
 *
 * Quick start
 * -----------
 *
 *   #include <vh/vh.vh>
 *
 *   // Restore the four DLLs EDRs most commonly hook, in one call.
 *   auto report = vh::unhook::restore_defaults();
 *   if (report) {
 *       for (auto& r : *report)
 *           std::printf("%s: %zu bytes rewritten across %zu regions\n",
 *                       r.module_name.c_str(), r.bytes_rewritten,
 *                       r.regions_rewritten);
 *   }
 *
 *   // Restore an arbitrary module (auto: KnownDlls, then disk fallback).
 *   auto r = vh::unhook::restore_module("wininet.dll");
 *
 *   // Peek only — see which bytes differ without writing anything.
 *   auto diff = vh::unhook::diff_module("ntdll.dll");
 *
 * Ordering guidance
 * -----------------
 *
 * ``restore_defaults()`` should run **once**, as early in your DLL's
 * ``DLL_PROCESS_ATTACH`` as possible, before any VanHooks hook is installed
 * — otherwise VanHooks' own inline patches will be reverted along with the
 * EDR's.  The engine's :cpp:class:`vanhooks::detail::TrampolineAllocator`
 * does not touch loaded DLL ``.text``, so its allocations survive.
 */

#include <vh/result.vh>
#include <vanhooks/vanhooks.vh>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace vh::unhook {

// ─────────────────────────────────────────────
//  Public types
// ─────────────────────────────────────────────

/**
 * A single contiguous run of differing bytes discovered by :cpp:func:`diff_module`.
 */
struct DiffRegion {
    uintptr_t rva;                       ///< RVA of the first differing byte within the module.
    void*     loaded_address;            ///< Address in the loaded module.
    std::vector<std::uint8_t> loaded;    ///< Bytes currently in the loaded module.
    std::vector<std::uint8_t> pristine;  ///< Bytes from the pristine reference copy.
};

/**
 * Result of a diff-only pass.
 */
struct DiffReport {
    std::string             module_name;      ///< As-passed module name.
    void*                   module_base = nullptr;
    std::size_t             image_size  = 0;
    std::vector<DiffRegion> regions;
};

/**
 * Result of a restore pass.  ``regions_rewritten * region_max_size >= bytes_rewritten``.
 */
struct RestoreReport {
    std::string module_name;
    void*       module_base       = nullptr;
    std::size_t bytes_rewritten   = 0;
    std::size_t regions_rewritten = 0;
};

/**
 * Options for a restore or diff call.  Defaults are safe for the common
 * "restore .text of a system DLL" case.
 */
struct Options {
    /// Only compare / rewrite the ``.text`` section (default).  When ``false``,
    /// every executable section is compared.
    bool text_section_only = true;

    /// Prefer ``\KnownDlls`` before falling back to disk (default).  Windows-only.
    bool prefer_knowndlls  = true;

    /// Skip disk fallback entirely.  Useful for pure ``\KnownDlls`` policies.
    bool knowndlls_only    = false;

    /// Maximum contiguous run of matching bytes to bridge before splitting a
    /// diff region in two.  0 = never split (single monolithic write per
    /// contiguous mismatch, which is what you want for hook removal).
    std::size_t merge_gap  = 0;
};

// ─────────────────────────────────────────────
//  Public entry points
// ─────────────────────────────────────────────

/**
 * Restore the ``.text`` of one loaded module.
 *
 * @param module_name  Base name (``"ntdll.dll"``, case-insensitive on Windows).
 *                     Passing the module without extension is accepted; the
 *                     ``.dll`` suffix is added automatically on Windows.
 */
[[nodiscard]]
vh::Result<RestoreReport> restore_module(std::string_view module_name,
                                         Options          opts = {}) noexcept;

/**
 * Restore ``ntdll.dll``, ``kernel32.dll``, ``kernelbase.dll`` and ``user32.dll``
 * in one call.  Returns per-module reports in load order.  A module that is
 * not loaded is skipped silently (no error).
 */
[[nodiscard]]
vh::Result<std::vector<RestoreReport>> restore_defaults(Options opts = {}) noexcept;

/**
 * Diff one module without writing.  Every hooked byte in the loaded image is
 * reported in the returned regions.
 */
[[nodiscard]]
vh::Result<DiffReport> diff_module(std::string_view module_name,
                                   Options          opts = {}) noexcept;

/**
 * Convenience: is any byte in the ``.text`` of ``module_name`` currently
 * different from its pristine reference?  Returns ``false`` on error.
 */
[[nodiscard]]
bool module_is_hooked(std::string_view module_name,
                      Options          opts = {}) noexcept;

} // namespace vh::unhook
