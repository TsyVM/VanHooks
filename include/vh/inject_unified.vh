#pragma once

/**
 * vh/inject_unified.vh — Unified InjectMethod enum + one-call dispatcher.
 *
 * Ships alongside the existing ``vh/inject.vh`` (which defines the original
 * 4-value :cpp:enum:`vh::InjectMethod` and :cpp:class:`vh::Injection`) and
 * ``vh/inject_ex.vh`` (17 supplementary free-function techniques).  This
 * header pulls the two together:
 *
 *   * :cpp:enum:`vh::InjectMethodEx` — 21-value superset of the original
 *     enum.  Values 0..3 numerically match :cpp:enum:`vh::InjectMethod` so
 *     ``static_cast<InjectMethod>(m)`` is well-defined for those four.
 *
 *   * :cpp:struct:`vh::InjectRequest` — carries every possible parameter
 *     the 21 techniques might need.  Unused fields are ignored.
 *
 *   * :cpp:func:`vh::inject_by_method` — one call, dispatches to the
 *     right underlying implementation.  Returns a
 *     :cpp:struct:`vh::inject_ex::RemoteHandle` for the new 17 and, for
 *     the original 4, wraps the existing :cpp:class:`Injection` into the
 *     same handle shape (``remote_base`` is the module load address).
 *
 * Existing ``vh::inject(pid, dll, {method})`` and
 * ``vh::inject_from_memory(...)`` calls continue to work unchanged — this
 * header is additive.
 */

#include "inject.vh"
#include "inject_ex.vh"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace vh {

// ─────────────────────────────────────────────
//  Unified enum
// ─────────────────────────────────────────────

enum class InjectMethodEx : std::uint8_t {
    // ── Original 4 (values must match vh::InjectMethod) ─────────────────
    LoadLibrary            = 0,
    ManualMap              = 1,
    ThreadHijack           = 2,
    ApcQueue               = 3,

    // ── inject_ex: process-birth ────────────────────────────────────────
    EarlyBirdApc           = 4,
    Herpaderping           = 5,
    Ghosting               = 6,
    Doppelganging          = 7,

    // ── inject_ex: remote-thread modern ─────────────────────────────────
    NtCreateThreadEx       = 8,
    RtlCreateUserThread    = 9,
    Reflective             = 10,
    SetWindowsHookEx       = 11,

    // ── inject_ex: APC-modern ───────────────────────────────────────────
    NtQueueApcThreadEx2    = 12,
    WaitingThreadHijack    = 13,

    // ── inject_ex: callback-hijack ──────────────────────────────────────
    KernelCallbackTable    = 14,
    ThreadlessCallback     = 15,
    ModuleStompRemote      = 16,

    // ── inject_ex: window-message ───────────────────────────────────────
    PROPagate              = 17,
    ExtraWindowMemory      = 18,

    // ── inject_ex: esoteric ─────────────────────────────────────────────
    AtomBombing            = 19,
    LdrRegisterNotification= 20,
};

// ─────────────────────────────────────────────
//  Request struct
// ─────────────────────────────────────────────

/// Superset of every parameter the 21 techniques accept.  Unused fields
/// for a given method are ignored — see the per-method requirement table
/// in ``INTEGRATION_INJECT.md`` or the ``inject_by_method`` doc-comment.
struct InjectRequest {
    // ── Target selection ────────────────────────────────────────────────
    std::uint32_t             pid           = 0;   ///< Existing-process methods.
    std::wstring_view         exe_path;             ///< Spawn methods (target EXE).
    std::wstring_view         scratch_path;         ///< Herpaderp/Ghost/Doppel scratch file.
    std::wstring_view         dll_path;             ///< SetWindowsHookEx / LdrNotify / module-stomp host.
    void*                     hwnd          = nullptr;   ///< PROPagate / EWM.
    std::uintptr_t            callback_slot_va = 0; ///< Threadless callback slot in target VA.

    // ── Payload ─────────────────────────────────────────────────────────
    std::span<const std::uint8_t> shellcode;         ///< Most techniques.
    std::span<const std::uint8_t> pe_bytes;          ///< ManualMap / Reflective / Herpaderp/Ghost/Doppel.
    std::span<const std::uint8_t> decoy_bytes;       ///< Herpaderping only.

    // ── Per-technique options ───────────────────────────────────────────
    inject_ex::SpawnOptions        spawn_opts;
    inject_ex::AtomBombingOptions  atom_opts;
    inject_ex::KctOptions          kct_opts;
    inject_ex::StompRemoteOptions  stomp_opts;
    inject_ex::LdrNotifyOptions    ldr_opts;

    std::string                    tag;
};

// ─────────────────────────────────────────────
//  Dispatcher
// ─────────────────────────────────────────────

/**
 * Route ``req`` to the technique named by ``method``.
 *
 * Required fields per method group:
 *
 * ============================= ==========================================================
 *  Method                        Required
 * ============================= ==========================================================
 *  LoadLibrary / ThreadHijack / pid, dll_path
 *   ApcQueue
 *  ManualMap                    pid, pe_bytes
 *  EarlyBirdApc                 exe_path, shellcode
 *  Herpaderping                 scratch_path, pe_bytes, decoy_bytes  (opt: spawn_opts)
 *  Ghosting                     scratch_path, pe_bytes               (opt: spawn_opts)
 *  Doppelganging                scratch_path, pe_bytes               (opt: spawn_opts)
 *  NtCreateThreadEx /           pid, shellcode
 *   RtlCreateUserThread /
 *   NtQueueApcThreadEx2 /
 *   WaitingThreadHijack
 *  Reflective                   pid, pe_bytes
 *  SetWindowsHookEx             pid, dll_path                        (pid = UI-thread pid)
 *  KernelCallbackTable          pid, shellcode                       (opt: kct_opts)
 *  ThreadlessCallback           pid, callback_slot_va, shellcode
 *  ModuleStompRemote            pid, dll_path, shellcode             (opt: stomp_opts)
 *  PROPagate / ExtraWindowMemory hwnd, shellcode
 *  AtomBombing                  pid, shellcode                       (opt: atom_opts)
 *  LdrRegisterNotification      pid, dll_path                        (opt: ldr_opts)
 * ============================= ==========================================================
 *
 * Returns the technique-specific :cpp:struct:`vh::inject_ex::RemoteHandle`
 * on success.  For the four original methods this handle is a thin
 * translation of the underlying :cpp:class:`vh::Injection` result — call
 * :cpp:func:`vh::inject_ex::eject` to release it.
 */
[[nodiscard]] Result<inject_ex::RemoteHandle>
inject_by_method(InjectMethodEx method, const InjectRequest& req) noexcept;

/// String name for a method value (for logging).
[[nodiscard]] std::string_view method_name(InjectMethodEx m) noexcept;

/// Same enum, narrower.  Widening back is
/// ``static_cast<InjectMethodEx>(m)`` — the numeric values line up.
[[nodiscard]] constexpr InjectMethodEx to_ex(InjectMethod m) noexcept {
    return static_cast<InjectMethodEx>(static_cast<std::uint8_t>(m));
}

} // namespace vh
