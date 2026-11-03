#pragma once

/**
 * vh/inject_ex.vh — Extended injection catalogue (20 techniques).
 *
 * Companion to :cpp:enum:`vh::InjectMethod` (which already covers the
 * original 4: LoadLibrary / ManualMap / ThreadHijack / ApcQueue).  This
 * header exposes 17 additional techniques as free functions in
 * ``vh::inject_ex``, and — via :cpp:func:`vh::inject_by_method` in
 * ``vh/inject.vh`` — as extra values on the unified :cpp:enum:`vh::InjectMethod`
 * enum.
 *
 * Groupings
 * ---------
 *
 * Process-birth (spawn a fresh process, land payload during loader init):
 *   * :cpp:func:`spawn_earlybird_apc`
 *   * :cpp:func:`spawn_herpaderped`
 *   * :cpp:func:`spawn_ghosted`
 *   * :cpp:func:`spawn_doppelganged`
 *
 * Remote-thread modern:
 *   * :cpp:func:`inject_ntcreatethreadex`
 *   * :cpp:func:`inject_rtlcreateuserthread`
 *   * :cpp:func:`inject_reflective`
 *   * :cpp:func:`inject_setwindowshook`
 *
 * APC-modern:
 *   * :cpp:func:`inject_queueapcex2`
 *   * :cpp:func:`inject_waiting_thread_hijack`
 *
 * Callback-hijack:
 *   * :cpp:func:`inject_kernelcallbacktable`
 *   * :cpp:func:`inject_threadless_callback`
 *   * :cpp:func:`inject_module_stomp_remote`
 *
 * Window-message:
 *   * :cpp:func:`inject_propagate`
 *   * :cpp:func:`inject_ewm`
 *
 * Esoteric:
 *   * :cpp:func:`inject_atombombing`   — chunked, unbounded shellcode size
 *   * :cpp:func:`inject_ldr_notification` — per-arch shellcode bootstrap
 *
 * Every technique returns :cpp:struct:`RemoteHandle`.  Call
 * :cpp:func:`eject` to release remote memory and close handles.
 */

#include "result.vh"
#include <vanhooks/vanhooks.vh>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace vh::inject_ex {

// ─────────────────────────────────────────────
//  Common handle
// ─────────────────────────────────────────────

struct RemoteHandle {
    std::uint64_t id           = 0;
    std::uint32_t pid          = 0;
#if defined(_WIN32)
    HANDLE        process      = nullptr;
    HANDLE        thread       = nullptr;   ///< First thread (may be nullptr for threadless).
#else
    void*         process      = nullptr;
    void*         thread       = nullptr;
#endif
    void*         remote_base  = nullptr;
    std::size_t   remote_size  = 0;
    std::string   technique;
};

// ─────────────────────────────────────────────
//  Per-technique options
// ─────────────────────────────────────────────

/// Common options for the four spawn-a-fresh-process techniques.
struct SpawnOptions {
    /// After the process is created (still suspended), automatically stage
    /// the first thread at the image's entry point using
    /// :cpp:func:`inject_ntcreatethreadex` and resume it.  Default true.
    ///
    /// Set to ``false`` if you want to hand-stage the thread with a
    /// different technique.  When ``false``, the returned handle's
    /// ``thread`` field is ``nullptr`` and the process is left suspended.
    bool auto_stage_entry = true;

    /// If ``auto_stage_entry`` is true, run the image entry point once and
    /// let the payload take over.  If your shellcode overrides
    /// ``ImageBase``'s entry point via an earlier hook, leave this true;
    /// otherwise it's the standard PE entry point.
    bool run_image_entry  = true;
};

/// Options for :cpp:func:`inject_atombombing`.
struct AtomBombingOptions {
    /// Automatically chunk shellcode across multiple atoms when it exceeds
    /// the 254-wchar per-atom limit.  Default true.  Each chunk uses one
    /// atom + one APC; the target executes them in order.
    bool auto_chunk = true;
};

/// Options for :cpp:func:`inject_kernelcallbacktable`.
struct KctOptions {
    /// Which callback-table slot to overwrite.  ``-1`` = auto-detect based
    /// on Windows build (default).  ``0`` = fnCOPYDATA on modern builds.
    /// Legal range: 0..127.
    int slot = -1;
};

/// Options for :cpp:func:`inject_module_stomp_remote`.
struct StompRemoteOptions {
    /// If ``true``, walk the target's ``PEB.Ldr`` to discover the host
    /// module's real base in the target rather than assuming it matches
    /// this process' ASLR base.  Default ``true``.
    bool walk_target_peb = true;
};

/// Options for :cpp:func:`inject_ldr_notification`.
struct LdrNotifyOptions {
    /// If ``true``, use per-arch handwritten shellcode that calls
    /// ``LdrRegisterDllNotification`` directly (no ``LoadLibrary``, no
    /// user DLL required).  Default ``true``.
    ///
    /// When ``true``, the caller supplies the notification callback via
    /// ``notify_cb_shellcode`` (a self-contained function body that will
    /// run inside the target for every subsequent DLL load).
    ///
    /// When ``false``, the classic path is used: LoadLibrary the caller's
    /// DLL and let it register the notification in its own DllMain.
    bool shellcode_bootstrap = true;

    /// The DLL-load notification callback, provided as position-independent
    /// shellcode with the standard ntdll signature
    /// ``VOID (NTAPI*)(ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA, PVOID)``.
    ///
    /// Ignored when ``shellcode_bootstrap == false``.
    std::span<const std::uint8_t> notify_cb_shellcode;
};

// ─────────────────────────────────────────────
//  Process-birth
// ─────────────────────────────────────────────

[[nodiscard]] vh::Result<RemoteHandle>
spawn_earlybird_apc(std::wstring_view          target_exe,
                    std::span<const std::uint8_t> shellcode) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
spawn_herpaderped(std::wstring_view          scratch_path,
                  std::span<const std::uint8_t> real_pe,
                  std::span<const std::uint8_t> decoy_bytes,
                  SpawnOptions opts = {}) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
spawn_ghosted(std::wstring_view              scratch_path,
              std::span<const std::uint8_t>  real_pe,
              SpawnOptions opts = {}) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
spawn_doppelganged(std::wstring_view              scratch_path,
                   std::span<const std::uint8_t>  real_pe,
                   SpawnOptions opts = {}) noexcept;

// ─────────────────────────────────────────────
//  Remote-thread modern
// ─────────────────────────────────────────────

[[nodiscard]] vh::Result<RemoteHandle>
inject_ntcreatethreadex(std::uint32_t pid,
                        std::span<const std::uint8_t> shellcode) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
inject_rtlcreateuserthread(std::uint32_t pid,
                           std::span<const std::uint8_t> shellcode) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
inject_reflective(std::uint32_t pid,
                  std::span<const std::uint8_t> pe_bytes) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
inject_setwindowshook(std::uint32_t     pid_of_target_ui,
                      std::wstring_view dll_path) noexcept;

// ─────────────────────────────────────────────
//  APC-modern
// ─────────────────────────────────────────────

[[nodiscard]] vh::Result<RemoteHandle>
inject_queueapcex2(std::uint32_t pid,
                   std::span<const std::uint8_t> shellcode) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
inject_waiting_thread_hijack(std::uint32_t pid,
                             std::span<const std::uint8_t> shellcode) noexcept;

// ─────────────────────────────────────────────
//  Callback-hijack
// ─────────────────────────────────────────────

[[nodiscard]] vh::Result<RemoteHandle>
inject_kernelcallbacktable(std::uint32_t pid_with_ui,
                           std::span<const std::uint8_t> shellcode,
                           KctOptions opts = {}) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
inject_threadless_callback(std::uint32_t pid,
                           std::uintptr_t callback_slot_va,
                           std::span<const std::uint8_t> shellcode) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
inject_module_stomp_remote(std::uint32_t pid,
                           std::wstring_view host_dll,
                           std::span<const std::uint8_t> shellcode,
                           StompRemoteOptions opts = {}) noexcept;

// ─────────────────────────────────────────────
//  Window-message
// ─────────────────────────────────────────────

[[nodiscard]] vh::Result<RemoteHandle>
inject_propagate(void* target_hwnd,
                 std::span<const std::uint8_t> shellcode) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
inject_ewm(void* target_hwnd,
           std::span<const std::uint8_t> shellcode) noexcept;

// ─────────────────────────────────────────────
//  Esoteric
// ─────────────────────────────────────────────

[[nodiscard]] vh::Result<RemoteHandle>
inject_atombombing(std::uint32_t pid,
                   std::span<const std::uint8_t> shellcode,
                   AtomBombingOptions opts = {}) noexcept;

[[nodiscard]] vh::Result<RemoteHandle>
inject_ldr_notification(std::uint32_t pid,
                        std::wstring_view dll_path,
                        LdrNotifyOptions opts = {}) noexcept;

// ─────────────────────────────────────────────
//  Lifecycle
// ─────────────────────────────────────────────

vh::Result<void> eject(RemoteHandle& h) noexcept;

[[nodiscard]] bool technique_available(std::string_view technique) noexcept;

// ─────────────────────────────────────────────
//  Process manipulation
// ─────────────────────────────────────────────

/// Options for :cpp:func:`inject_process_hollow`.
struct HollowOptions {
    /// If true, NtUnmapViewOfSection the original image before mapping
    /// the payload.  Default true.
    bool unmap_original = true;
    /// If true, patch the PEB.ImageBaseAddress to match the payload's
    /// preferred base.  Default true.
    bool patch_peb      = true;
};

/// Options for :cpp:func:`inject_pool_party`.
struct PoolPartyOptions {
    /// Which pool-party variant to use (0 = worker, 1 = timer, 2 = wait,
    /// 3 = I/O completion).  Default 0 (worker factory insert).
    std::uint8_t variant = 0;
};

/// Options for :cpp:func:`inject_ntmapview`.
struct NtMapViewOptions {
    /// Section protection for the shared mapping.  Default PAGE_EXECUTE_READ.
    std::uint32_t protection = 0x20; /* PAGE_EXECUTE_READ */
};

/**
 * Process Hollowing (RunPE).  Create target suspended, unmap its image,
 * map payload PE in its place, fix context to payload's entry point.
 * Classic — heavily signatured but effective for testing.
 */
[[nodiscard]] vh::Result<RemoteHandle>
inject_process_hollow(std::wstring_view          target_exe,
                      std::span<const std::uint8_t> pe_bytes,
                      HollowOptions opts = {}) noexcept;

/**
 * Pool Party injection.  Abuse Windows Thread Pool internals to queue
 * shellcode execution without creating a remote thread or APC.
 * Four variants target different pool objects:
 *   0 — TpAllocWork   (worker factory)
 *   1 — TpAllocTimer  (timer callback)
 *   2 — TpAllocWait   (wait callback)
 *   3 — TpAllocIo     (I/O completion callback)
 */
[[nodiscard]] vh::Result<RemoteHandle>
inject_pool_party(std::uint32_t pid,
                  std::span<const std::uint8_t> shellcode,
                  PoolPartyOptions opts = {}) noexcept;

/**
 * NtMapViewOfSection injection.  Create a shared section, map it into
 * both this process and the target, write shellcode into our view
 * (appears in the target's view), then trigger execution via
 * NtQueueApcThread.  No VirtualAllocEx / WriteProcessMemory calls.
 */
[[nodiscard]] vh::Result<RemoteHandle>
inject_ntmapview(std::uint32_t pid,
                 std::span<const std::uint8_t> shellcode,
                 NtMapViewOptions opts = {}) noexcept;
} // namespace vh::inject_ex


