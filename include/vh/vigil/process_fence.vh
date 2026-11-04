#pragma once

/**
 * vh/vigil/process_fence.vh — Process enumeration awareness
 *
 * Anti-cheat engines enumerate running processes to detect:
 *
 *   * Cheat tools (Cheat Engine, trainers, memory editors)
 *   * Debuggers (x64dbg, OllyDbg, WinDbg, IDA)
 *   * Reverse-engineering tools (ReClass, Ghidra, Binary Ninja)
 *   * Injection tools (Process Hacker, DLL injectors)
 *   * Virtualisation (VMware, VirtualBox)
 *   * Recording / overlay (OBS, Discord, FRAPS)
 *
 * Detection methods:
 *
 *   * **CreateToolhelp32Snapshot** + Process32First/Next — full process list
 *   * **EnumProcesses** (psapi) — PID list
 *   * **NtQuerySystemInformation(SystemProcessInformation)** — kernel query
 *   * **OpenProcess** — targeted handle with PROCESS_QUERY_INFORMATION
 *   * **QueryFullProcessImageName** — path verification
 *
 * This module provides:
 *
 *   1. A database of executable names each AC engine looks for.
 *   2. Risk assessment of currently running processes.
 *   3. Monitoring of enumeration API calls.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_PROCESS_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vh::ac::process_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Known process signatures
// ─────────────────────────────────────────────────────────────────────────────

enum class ProcessCategory : uint8_t {
    MemoryEditor,       // Cheat Engine, ArtMoney, etc.
    Debugger,           // x64dbg, OllyDbg, WinDbg, IDA
    ReverseEngineering, // Ghidra, Binary Ninja, ReClass
    Injector,           // Process Hacker, Extreme Injector
    PacketCapture,      // Wireshark, Fiddler
    Virtualisation,     // VMware, VirtualBox tools
    Overlay,            // FRAPS, RivaTuner, Discord overlay
    Automation,         // AutoHotkey, AutoIt, macro tools
    Generic,            // catch-all for blacklisted names
};

struct ProcessSignature {
    std::string_view    exe_name;       // e.g. "cheatengine-x86_64.exe"
    ProcessCategory     category;
    std::string_view    tool_name;      // e.g. "Cheat Engine"
    uint32_t            engines;        // bitmask of engines that check this
};

/// All known process signatures ACs look for.
VH_API std::span<const ProcessSignature> known_signatures() noexcept;

/// Filter to signatures relevant to a specific engine.
VH_API std::vector<ProcessSignature> signatures_for(ac::Engine engine) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Current process scan
// ─────────────────────────────────────────────────────────────────────────────

struct ProcessRisk {
    uint32_t            pid;
    std::string         exe_name;
    std::string         full_path;
    ProcessCategory     category;
    std::string_view    matched_tool;   // which tool signature matched
    bool                matches_signature;
};

/// Scan running processes and assess risk against known AC signatures.
VH_API vh::Result<std::vector<ProcessRisk>> scan_processes() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Enumeration monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct EnumEvent {
    enum class Api : uint8_t {
        CreateToolhelp32Snapshot, Process32First, Process32Next,
        EnumProcesses, NtQuerySystemInformation,
        OpenProcess, QueryFullProcessImageName,
    };
    Api             api;
    uint32_t        target_pid;     // for OpenProcess
    uint32_t        access_mask;    // for OpenProcess
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using EnumCallback = void(*)(const EnumEvent& event);

/// Start monitoring process enumeration APIs.
VH_API vh::Result<void> monitor_start(EnumCallback cb) noexcept;

/// Stop monitoring.
VH_API void monitor_stop() noexcept;

/// Is monitoring active?
VH_API bool monitor_active() noexcept;

} // namespace vh::ac::process_fence
