#pragma once

/**
 * vh/vigil/overlay_fence.vh — Render overlay detection awareness
 *
 * Anti-cheat engines detect graphical overlays at the rendering level:
 *
 *   * DXGI swapchain hooking (Present/ResizeBuffers vtable)
 *   * D3D9 EndScene/Reset vtable hooks
 *   * D3D11 draw-call interception
 *   * Vulkan layer injection (VK_LAYER_*)
 *   * GDI overlay windows (WS_EX_TOPMOST + WS_EX_TRANSPARENT + WS_EX_LAYERED)
 *   * DWM composition state queries
 *
 * This module provides:
 *
 *   1. Per-engine overlay detection profiles.
 *   2. Render API hook detection — check if Present/EndScene are patched.
 *   3. Overlay DLL presence scan.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_OVERLAY_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::overlay_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Overlay indicators
// ─────────────────────────────────────────────────────────────────────────────

enum class OverlayKind : uint8_t {
    DXGIPresent,        // IDXGISwapChain::Present hooked
    D3D9EndScene,       // IDirect3DDevice9::EndScene hooked
    D3D11DrawCall,      // ID3D11DeviceContext draw hooked
    VulkanLayer,        // suspicious Vulkan layer loaded
    GDIOverlay,         // GDI-based transparent overlay window
    ExternalOverlay,    // known external overlay tool (Steam, Discord, etc.)
};

struct OverlayDll {
    std::string     module_name;
    bool            is_known_tool;  // Steam, Discord, GeForce, etc.
    bool            is_suspicious;  // unknown overlay DLL
};

struct OverlayRisk {
    OverlayKind     kind;
    std::string     detail;         // module name or window class
    bool            is_legitimate;  // known legitimate overlay
    bool            is_suspicious;
};

/// Scan for overlay indicators.
VH_API vh::Result<std::vector<OverlayRisk>> scan_overlays() noexcept;

/// Check which known overlay DLLs are loaded.
VH_API vh::Result<std::vector<OverlayDll>> scan_overlay_dlls() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine overlay detection profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class OverlayCheck : uint32_t {
    DXGIPresentHook     = 1u << 0,
    D3D9VtableCheck     = 1u << 1,
    D3D11VtableCheck    = 1u << 2,
    VulkanLayerEnum     = 1u << 3,
    OverlayWindowScan   = 1u << 4,
    OverlayDllScan      = 1u << 5,
    DWMCompositionQuery = 1u << 6,
    PresentTimingCheck  = 1u << 7,
};

/// Bitmask of overlay checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::overlay_fence
