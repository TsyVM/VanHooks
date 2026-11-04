#pragma once

/**
 * vh/vigil/input_fence.vh — Keyboard/mouse hook detection awareness
 *
 * Anti-cheat engines detect input manipulation:
 *
 *   * SetWindowsHookEx (WH_KEYBOARD_LL, WH_MOUSE_LL) — global hooks
 *   * Raw Input registration (GetRawInputDeviceList)
 *   * DirectInput device enumeration
 *   * SendInput / mouse_event / keybd_event API monitoring
 *   * HID device stack inspection
 *   * Input timing analysis (sub-ms precision detection)
 *
 * This module provides:
 *
 *   1. Per-engine input monitoring profiles.
 *   2. Scan for installed input hooks (LL keyboard/mouse).
 *   3. Detect synthetic input sources.
 *   4. Input API monitoring.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_INPUT_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::input_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Input hook types
// ─────────────────────────────────────────────────────────────────────────────

enum class HookKind : uint8_t {
    KeyboardLL,         // WH_KEYBOARD_LL
    MouseLL,            // WH_MOUSE_LL
    Keyboard,           // WH_KEYBOARD
    Mouse,              // WH_MOUSE
    GetMessage,         // WH_GETMESSAGE
    CallWndProc,        // WH_CALLWNDPROC
};

struct InstalledHook {
    HookKind        kind;
    uintptr_t       callback_address;
    std::string     owner_module;       // DLL that owns the callback
    uint32_t        owner_tid;          // 0 = global hook
    bool            is_own_process;     // installed by our process
};

/// Enumerate installed low-level input hooks.
VH_API vh::Result<std::vector<InstalledHook>> scan_hooks() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Raw input devices
// ─────────────────────────────────────────────────────────────────────────────

enum class DeviceKind : uint8_t {
    Mouse,
    Keyboard,
    HID,
};

struct InputDevice {
    DeviceKind      kind;
    std::string     name;           // device interface path
    std::string     product;        // HID product string if available
    uint16_t        vendor_id;
    uint16_t        product_id;
    bool            is_virtual;     // no physical HID backing
};

/// Enumerate raw input devices.
VH_API vh::Result<std::vector<InputDevice>> enum_devices() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Synthetic input detection
// ─────────────────────────────────────────────────────────────────────────────

struct InputEvent {
    enum class Api : uint8_t {
        SendInput, MouseEvent, KeybdEvent,
        SetCursorPos, BlockInput,
    };
    Api             api;
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using InputCallback = void(*)(const InputEvent& event);

VH_API vh::Result<void> monitor_start(InputCallback cb) noexcept;
VH_API void monitor_stop() noexcept;
VH_API bool monitor_active() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine input monitoring profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class InputCheck : uint32_t {
    LLHookScan          = 1u << 0,  // scan for LL keyboard/mouse hooks
    RawInputEnum        = 1u << 1,  // enumerate raw input devices
    SendInputMonitor    = 1u << 2,  // monitor SendInput calls
    DirectInputEnum     = 1u << 3,  // enumerate DirectInput devices
    HIDStackInspect     = 1u << 4,  // inspect HID device stack
    InputTimingAnalysis = 1u << 5,  // sub-ms input timing checks
    GetAsyncKeyState    = 1u << 6,  // monitor GetAsyncKeyState patterns
    ClipCursorDetect    = 1u << 7,  // detect cursor confinement changes
};

/// Bitmask of input checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::input_fence
