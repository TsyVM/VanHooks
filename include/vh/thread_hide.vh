#pragma once

/**
 * vh/thread_hide.vh — Thread & DR-register concealment.
 *
 * Two related surfaces:
 *
 *   1. **Thread hiding** — ``NtSetInformationThread(ThreadHideFromDebugger)``
 *      marks a thread invisible to ``DBG_*`` events and to
 *      ``NtQuerySystemInformation(SystemProcessInformation)``.  Useful for
 *      VanHooks worker threads (trampoline slab reclamation, sleep-obf timer
 *      workers) that a memory scanner shouldn't correlate with the payload.
 *
 *   2. **DR-register camouflage** — ``hwbp.vh`` sets DR0..DR3 to install
 *      no-write hooks, but leaves the registers observable to a user-mode
 *      ``GetThreadContext`` scanner.  ``dr_camouflage_scope`` clears DR0..DR3
 *      when a peer thread requests them and restores after — behind the
 *      scenes it installs a ``NtGetContextThread`` inline hook that filters
 *      the DR fields for the calling process' own thread queries.
 *
 * The camouflage is best-effort: kernel-mode drivers reading via
 * ``PsGetContextThread`` bypass it.  It's aimed at user-mode scanners.
 *
 * Platform: Windows.  POSIX returns ``Unsupported``.
 */

#include "result.vh"
#include <vanhooks/vanhooks.vh>

#include <cstdint>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace vh::thread_hide {

// ─────────────────────────────────────────────
//  Thread hiding
// ─────────────────────────────────────────────

/**
 * Mark ``thread`` invisible to attached debuggers and to
 * ``SystemProcessInformation`` thread enumerations.  Pass ``nullptr`` for
 * the current thread.
 *
 * Returns ``Ok`` if the call succeeded, ``OsError`` if the syscall
 * returned a failure NTSTATUS.
 */
[[nodiscard]] vh::Result<void> hide_thread(void* thread_handle = nullptr) noexcept;

/// Convenience: hide the calling thread.
[[nodiscard]] inline vh::Result<void> hide_current_thread() noexcept {
    return hide_thread(nullptr);
}

// ─────────────────────────────────────────────
//  DR-register camouflage
// ─────────────────────────────────────────────

/**
 * Install the ``NtGetContextThread`` filter that masks DR0..DR3 in
 * ``CONTEXT.Dr0..Dr3`` on returns for THIS process' own threads.  The
 * filter is a single trampoline hook via VanHooks; it's kept alive until
 * :cpp:func:`uninstall_dr_camouflage` runs (or process exit).
 *
 * Callers who already installed the camouflage receive
 * :cpp:enum:`vanhooks::Error::HookAlreadyExists`.
 */
[[nodiscard]] vh::Result<void> install_dr_camouflage() noexcept;

/// Remove the ``NtGetContextThread`` filter.
[[nodiscard]] vh::Result<void> uninstall_dr_camouflage() noexcept;

/// True if the camouflage hook is currently installed.
[[nodiscard]] bool dr_camouflage_active() noexcept;

} // namespace vh::thread_hide
