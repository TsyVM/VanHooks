#pragma once

/**
 * vh/vigil/screenshot_fence.vh — Screenshot capture awareness
 *
 * Anti-cheat engines periodically capture screenshots to verify the
 * game window contents match what the player should see.  Methods:
 *
 *   * **BitBlt / StretchBlt** — GDI screen capture from the game DC
 *   * **PrintWindow** — capture a specific window's contents
 *   * **DWM thumbnails** — DwmRegisterThumbnail for composited capture
 *   * **DXGI desktop duplication** — IDXGIOutputDuplication (Windows 8+)
 *   * **D3D present hook** — hook the game's own Present/SwapBuffers
 *   * **GDI+ DrawImage** — alternative GDI capture path
 *
 * This module:
 *
 *   1. Detects which screenshot method(s) the active AC uses.
 *   2. Optionally monitors capture API calls to know *when* a
 *      screenshot is being taken (timing awareness).
 *   3. Reports capture statistics (frequency, resolution, target window).
 *
 * Read-only awareness.  Does not block, modify, or replace captured
 * frames — that would require a present-hook or DWM interception.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_SCREENSHOT_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::screenshot_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Capture methods
// ─────────────────────────────────────────────────────────────────────────────

enum class CaptureMethod : uint32_t {
    BitBlt              = 1u << 0,
    StretchBlt          = 1u << 1,
    PrintWindow         = 1u << 2,
    DwmThumbnail        = 1u << 3,
    DxgiDuplication     = 1u << 4,
    D3DPresentHook      = 1u << 5,
    GdiPlusDrawImage    = 1u << 6,
    DirectXScreenshot   = 1u << 7,   // IDXGISwapChain::GetBuffer → copy
};

/// Bitmask of capture methods used by a specific AC engine.
VH_API uint32_t methods_used_by(ac::Engine engine) noexcept;

/// Which methods the current primary AC uses.
VH_API uint32_t methods_used_by_primary() noexcept;

/// Human-readable name for a CaptureMethod.
VH_API std::string_view method_name(CaptureMethod method) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Capture event monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct CaptureEvent {
    CaptureMethod   method;
    uint32_t        width;
    uint32_t        height;
    uint64_t        timestamp_ms;       // QPC-derived
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;              // caller belongs to a known AC module
};

using CaptureCallback = void(*)(const CaptureEvent& event);

/// Start monitoring screenshot capture APIs.
/// Hooks BitBlt, PrintWindow, and related functions.
VH_API vh::Result<void> monitor_start(CaptureCallback cb) noexcept;

/// Stop monitoring.
VH_API void monitor_stop() noexcept;

/// Is monitoring active?
VH_API bool monitor_active() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Statistics
// ─────────────────────────────────────────────────────────────────────────────

struct CaptureStats {
    uint32_t    total_captures = 0;
    uint32_t    ac_captures = 0;        // captures by known AC modules
    uint64_t    last_capture_ms = 0;
    uint32_t    avg_interval_ms = 0;    // average time between captures
    uint32_t    last_width = 0;
    uint32_t    last_height = 0;
};

/// Get capture statistics since monitor_start().
VH_API CaptureStats capture_stats() noexcept;

/// Is the AC likely capturing screenshots right now?
/// Based on recent capture activity patterns.
VH_API bool capture_active() noexcept;

} // namespace vh::ac::screenshot_fence
