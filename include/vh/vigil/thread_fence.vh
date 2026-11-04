#pragma once

/**
 * vh/vigil/thread_fence.vh — Thread enumeration awareness
 *
 * Anti-cheat engines enumerate threads to detect:
 *
 *   * Injected threads (no associated module, suspicious start address)
 *   * Manual-map threads (start address in unbacked memory)
 *   * Hidden threads (NtSetInformationThread ThreadHideFromDebugger)
 *   * Thread pool abuse (threads started via TP_WORK / NtAlertResumeThread)
 *
 * Detection methods:
 *
 *   * **CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)** + Thread32First/Next
 *   * **NtQuerySystemInformation(SystemProcessInformation)** — thread list
 *   * **NtQueryInformationThread** — start address, hide status
 *   * **GetThreadContext** — instruction pointer / debug register inspection
 *
 * This module provides:
 *
 *   1. Thread risk assessment (start address classification).
 *   2. Monitoring of thread enumeration API calls.
 *   3. Per-engine thread scanning behaviour profiles.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_THREAD_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::thread_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Thread classification
// ─────────────────────────────────────────────────────────────────────────────

enum class ThreadOrigin : uint8_t {
    KnownModule,        // start address inside a loaded module
    UnbackedMemory,     // start address in committed but unbacked region
    ManualMapped,       // start address in MEM_IMAGE region with no module
    ThreadPool,         // started via TpAllocWork / NtAlertResumeThread
    CLR,                // .NET thread pool
    Unknown,
};

struct ThreadRisk {
    uint32_t        tid;
    uint32_t        owner_pid;
    uintptr_t       start_address;
    std::string     start_module;       // module name if KnownModule
    ThreadOrigin    origin;
    bool            is_hidden;          // ThreadHideFromDebugger set
    bool            is_suspended;
    bool            has_debug_regs;     // DR0-DR3 non-zero
    bool            is_suspicious;      // heuristic: unbacked + hidden, etc.
};

/// Scan all threads in the current process and classify risk.
VH_API vh::Result<std::vector<ThreadRisk>> scan_threads() noexcept;

/// Scan threads in a specific process.
VH_API vh::Result<std::vector<ThreadRisk>> scan_threads(uint32_t pid) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine thread inspection profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class ThreadCheck : uint32_t {
    EnumViaToolhelp         = 1u << 0,
    EnumViaNtQuery          = 1u << 1,
    CheckStartAddress       = 1u << 2,
    CheckHideFromDebugger   = 1u << 3,
    CheckDebugRegisters     = 1u << 4,
    CheckSuspendedState     = 1u << 5,
    CheckStackIntegrity     = 1u << 6,
    CheckThreadContext      = 1u << 7,
};

/// Bitmask of thread checks performed by a specific AC engine.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Enumeration monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct EnumEvent {
    enum class Api : uint8_t {
        CreateToolhelp32Snapshot, Thread32First, Thread32Next,
        NtQuerySystemInformation, NtQueryInformationThread,
        GetThreadContext, SuspendThread, ResumeThread,
    };
    Api             api;
    uint32_t        target_tid;
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using EnumCallback = void(*)(const EnumEvent& event);

/// Start monitoring thread enumeration APIs.
VH_API vh::Result<void> monitor_start(EnumCallback cb) noexcept;

/// Stop monitoring.
VH_API void monitor_stop() noexcept;

/// Is monitoring active?
VH_API bool monitor_active() noexcept;

} // namespace vh::ac::thread_fence
