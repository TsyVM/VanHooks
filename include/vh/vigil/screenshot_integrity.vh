#pragma once

/**
 * vh/vigil/screenshot_integrity.vh — Screenshot capture awareness
 *
 * Anti-cheat engines capture screenshots for review:
 *
 *   * Random screenshot capture at intervals
 *   * Triggered capture on suspicious events
 *   * Framebuffer reading bypassing overlays
 *   * Screenshot comparison / hash matching
 *   * Screenshot integrity (tampering detection)
 *   * GPU-side capture to bypass user-space hooks
 *
 * This module provides:
 *
 *   1. Per-engine screenshot capture profiles.
 *   2. Capture method awareness — how screenshots are taken.
 *   3. Integrity verification awareness — tamper detection.
 *
 * Platform: WIN32 for capture method detection, stubs on POSIX.
 *
 * Requires: VH_ENABLE_SCREENSHOT_INTEGRITY  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>

namespace vh::ac::screenshot_integrity {

enum class CaptureMethod : uint32_t {
    GDIBitBlt       = 1u << 0,  // GDI BitBlt screen capture
    DXGIDuplication = 1u << 1,  // DXGI desktop duplication API
    D3DPresent      = 1u << 2,  // intercept Present() for frame
    GPUReadback     = 1u << 3,  // GPU-side readback (bypass hooks)
    PrintWindow     = 1u << 4,  // PrintWindow API capture
    DWMCapture      = 1u << 5,  // DWM thumbnail capture
};

enum class ScreenshotCheck : uint32_t {
    RandomCapture       = 1u << 0,  // periodic random screenshots
    EventTriggered      = 1u << 1,  // capture on suspicious event
    OverlayBypass       = 1u << 2,  // capture beneath overlays
    FramebufferHash     = 1u << 3,  // hash comparison of frames
    TamperDetection     = 1u << 4,  // detect modified screenshots
    GPUSideCapture      = 1u << 5,  // capture directly from GPU
    CaptureHookDetect   = 1u << 6,  // detect hooked capture APIs
    VisualDiffing       = 1u << 7,  // compare client vs server view
};

struct ScreenshotProfile {
    ac::Engine  engine;
    uint32_t    capture_methods;    // bitmask of CaptureMethod
    uint32_t    checks;             // bitmask of ScreenshotCheck
    uint32_t    interval_min_sec;   // minimum capture interval
    uint32_t    interval_max_sec;   // maximum capture interval
    bool        uploads_to_server;  // screenshots sent to server
};

/// Get the screenshot profile for a specific AC engine.
VH_API ScreenshotProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of screenshot checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

/// Bitmask of capture methods a specific AC engine uses.
VH_API uint32_t capture_methods_by(ac::Engine engine) noexcept;

/// Whether a specific capture API appears hooked in the current process.
VH_API bool is_capture_hooked() noexcept;

} // namespace vh::ac::screenshot_integrity
