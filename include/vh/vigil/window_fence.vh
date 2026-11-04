#pragma once

/**
 * vh/vigil/window_fence.vh — Window enumeration awareness
 *
 * Anti-cheat engines enumerate visible windows to detect:
 *
 *   * Overlay/ESP tools (transparent topmost windows)
 *   * Cheat tool GUIs (by window class name or title)
 *   * Debugger windows (OllyDbg, x64dbg, WinDbg, IDA)
 *   * Process injection UIs (ReClass, Cheat Engine)
 *
 * Detection methods:
 *
 *   * **EnumWindows / EnumDesktopWindows** — full window list
 *   * **FindWindowA/W** — targeted search by class/title
 *   * **GetForegroundWindow** — focus tracking
 *   * **GetWindowText** — title string harvesting
 *   * **GetClassName** — class name matching
 *   * **IsWindowVisible / GetWindowLong** — overlay detection (WS_EX_TOPMOST + WS_EX_TRANSPARENT)
 *
 * This module provides:
 *
 *   1. A database of window class names and titles each AC looks for.
 *   2. Monitoring of enumeration/find calls to detect when the AC is scanning.
 *   3. Overlay risk assessment — are your windows detectable?
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_WINDOW_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vh::ac::window_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Known window signatures that ACs look for
// ─────────────────────────────────────────────────────────────────────────────

enum class SignatureKind : uint8_t {
    ClassName,      // window class name match
    TitleSubstring, // window title contains
    TitleExact,     // window title equals
};

struct WindowSignature {
    std::string_view    pattern;        // class name or title text
    SignatureKind       kind;
    std::string_view    tool_name;      // what tool this detects (e.g. "Cheat Engine")
    uint32_t            engines;        // bitmask of engines that look for this
};

/// All known window signatures ACs search for.
VH_API std::span<const WindowSignature> known_signatures() noexcept;

/// Filter to signatures relevant to a specific engine.
VH_API std::vector<WindowSignature> signatures_for(ac::Engine engine) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Current window scan
// ─────────────────────────────────────────────────────────────────────────────

struct WindowRisk {
    uintptr_t           hwnd;
    std::string         title;
    std::string         class_name;
    bool                is_topmost;
    bool                is_transparent;
    bool                is_overlay;     // topmost + transparent + layered
    bool                matches_signature;
    std::string_view    matched_tool;   // which tool signature matched
};

/// Scan all visible windows and assess risk against known AC signatures.
VH_API vh::Result<std::vector<WindowRisk>> scan_windows() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Enumeration monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct EnumEvent {
    enum class Api : uint8_t {
        EnumWindows, EnumDesktopWindows, FindWindowA, FindWindowW,
        FindWindowExA, FindWindowExW, GetForegroundWindow,
    };
    Api             api;
    std::string     search_class;   // for FindWindow calls
    std::string     search_title;   // for FindWindow calls
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using EnumCallback = void(*)(const EnumEvent& event);

/// Start monitoring window enumeration APIs.
VH_API vh::Result<void> monitor_start(EnumCallback cb) noexcept;

/// Stop monitoring.
VH_API void monitor_stop() noexcept;

/// Is monitoring active?
VH_API bool monitor_active() noexcept;

} // namespace vh::ac::window_fence
