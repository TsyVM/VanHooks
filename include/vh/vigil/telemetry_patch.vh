#pragma once

/**
 * vh/telemetry_patch.vh — ETW + AMSI runtime suppression.
 *
 * Silences user-mode telemetry by patching the first bytes of the standard
 * emitters:
 *
 *   * ``ntdll!EtwEventWrite``          → ``xor eax, eax; ret``  (returns ERROR_SUCCESS)
 *   * ``ntdll!NtTraceEvent``           → same
 *   * ``ntdll!EtwEventWriteFull``      → same (if present)
 *   * ``amsi!AmsiScanBuffer``          → sets ``*AMSI_RESULT = CLEAN``, returns S_OK
 *   * ``amsi!AmsiScanString``          → same shape
 *
 * Every patch is applied through :cpp:func:`vanhooks::memory::protect` +
 * in-process ``memcpy`` (never ``WriteProcessMemory``).  Original bytes are
 * saved in a per-target record so :cpp:func:`restore` returns them exactly.
 *
 * If AMSI or a specific ETW export isn't present in the process (common —
 * amsi.dll only loads in .NET / PowerShell / Office / opt-in hosts), that
 * target is silently skipped and reported in the returned per-target vector.
 *
 * Platform: Windows.  Every entry point returns Unsupported on POSIX.
 *
 * Ordering: call :cpp:func:`disable_all` **after** ``vh::unhook::restore_defaults()``.
 * If you patch first, the unhook pass restores the original bytes and undoes
 * your suppression.
 */

#include <vh/result.vh>
#include <vanhooks/vanhooks.vh>

#include <string>
#include <string_view>
#include <vector>

namespace vh::telemetry {

/// Outcome of one target patch.
struct PatchOutcome {
    std::string   name;          ///< e.g. "EtwEventWrite"
    void*         target = nullptr;
    bool          patched = false;  ///< false if the export was absent
    std::size_t   bytes_written = 0;
    vanhooks::Error error = vanhooks::Error::Ok;  ///< non-Ok when patch attempt failed
};

using Report = std::vector<PatchOutcome>;

// ─────────────────────────────────────────────
//  Individual switches
// ─────────────────────────────────────────────

[[nodiscard]] vh::Result<Report> disable_etw()  noexcept;
[[nodiscard]] vh::Result<Report> disable_amsi() noexcept;

/// Convenience — ETW then AMSI, one merged report.
[[nodiscard]] vh::Result<Report> disable_all()  noexcept;

/**
 * Undo every patch applied by earlier ``disable_*`` calls in this process.
 * Returns per-target outcomes; a target that was never patched is skipped.
 * Idempotent — safe to call multiple times.
 */
[[nodiscard]] vh::Result<Report> restore() noexcept;

// ─────────────────────────────────────────────
//  Diagnostics
// ─────────────────────────────────────────────

/// True if any patch is currently applied.
[[nodiscard]] bool any_patched() noexcept;

/// Copy of the current internal patch table.  Useful for logging.
[[nodiscard]] Report status() noexcept;

} // namespace vh::telemetry
