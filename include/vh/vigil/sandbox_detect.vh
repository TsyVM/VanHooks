#pragma once

/**
 * vh/sandbox_detect.vh — Sandbox / analysis environment detection
 *
 * Detects virtualized, sandboxed, or instrumented environments using
 * multiple heuristics.  Designed to defer execution of sensitive
 * operations (injection, hooking) when running inside:
 *
 *   - Malware analysis sandboxes (Any.Run, Cuckoo, Joe Sandbox, CAPE)
 *   - Virtual machines (VMware, VirtualBox, Hyper-V, QEMU/KVM)
 *   - Debuggers and instrumentation tools
 *   - Automated detonation chambers
 *
 * Detection heuristics
 * ────────────────────
 *
 *   1. **Timing checks** — RDTSC delta measurement across a calibrated
 *      delay.  Sandboxes often accelerate time or intercept RDTSC,
 *      producing deltas that are too small or too uniform.
 *
 *   2. **Hardware fingerprinting** — Core count < 2, RAM < 2 GB,
 *      disk < 60 GB are sandbox indicators.  Real endpoints have more.
 *
 *   3. **VM artifact detection** — Known device names, registry keys,
 *      and loaded DLLs that indicate VM hypervisors.
 *
 *   4. **User interaction checks** — Cursor movement, foreground window
 *      changes, recent user input timestamps.  Sandboxes typically have
 *      no real user interaction.
 *
 *   5. **Sleep acceleration** — Request a 2-second sleep, measure the
 *      wall-clock delta.  If it completes in < 1.5s, the sandbox is
 *      fast-forwarding sleeps.
 *
 *   6. **Process environment** — Known sandbox process names, recently
 *      created DLLs in the module list, suspiciously clean environments.
 *
 * Usage
 * ─────
 *
 *   #include <vh/vigil/sandbox_detect.vh>
 *
 *   // Quick check (runs fastest heuristics only):
 *   if (vh::sandbox::is_sandboxed())
 *       return;  // Bail out silently
 *
 *   // Detailed report:
 *   auto report = vh::sandbox::full_scan();
 *   if (report.score >= vh::sandbox::kHighConfidence)
 *       return;
 *
 *   // RAII guard: defers execution if sandboxed
 *   vh::sandbox::SafeExecGuard guard;
 *   if (!guard.is_safe()) return;
 *   // ... sensitive operations ...
 *
 * Platform: Windows x64/x86.  POSIX stubs return false/safe.
 */

#include <vanhooks/vanhooks.vh>
#include <cstdint>
#include <string>

namespace vh::sandbox {

/// Confidence thresholds for sandbox detection.
constexpr int kLowConfidence   = 20;   ///< Might be sandboxed
constexpr int kMedConfidence   = 50;   ///< Likely sandboxed
constexpr int kHighConfidence  = 75;   ///< Almost certainly sandboxed

/// Individual heuristic flags.
enum Heuristic : std::uint32_t {
    None              = 0,
    TimingAnomaly     = 1 << 0,   ///< RDTSC delta is suspicious
    LowCoreCount      = 1 << 1,   ///< < 2 logical processors
    LowMemory         = 1 << 2,   ///< < 2 GB physical RAM
    SmallDisk         = 1 << 3,   ///< < 60 GB total disk
    VmArtifact        = 1 << 4,   ///< VM-specific device/registry/DLL found
    NoUserInteraction = 1 << 5,   ///< No cursor movement or input events
    SleepAcceleration = 1 << 6,   ///< Sleep was fast-forwarded
    SandboxProcess    = 1 << 7,   ///< Known sandbox process in task list
    DebuggerPresent   = 1 << 8,   ///< Debugger attached or debug flags set
    RecentBoot        = 1 << 9,   ///< System uptime < 5 minutes (fresh sandbox)
};

/// Result of a full sandbox scan.
struct ScanReport {
    int           score      = 0;      ///< Aggregate confidence (0-100)
    std::uint32_t heuristics = 0;      ///< Bitmask of triggered Heuristic flags
    std::string   detail;              ///< Human-readable summary
};

/// Quick check: returns true if any high-confidence heuristic fires.
/// Fast — runs only timing + core count + debugger checks.
[[nodiscard]] bool is_sandboxed() noexcept;

/// Full scan: runs all heuristics and returns a detailed report.
/// Slower (~2-3 seconds due to sleep acceleration test).
[[nodiscard]] ScanReport full_scan() noexcept;

/// Check a single heuristic.
[[nodiscard]] bool check_timing() noexcept;
[[nodiscard]] bool check_hardware() noexcept;
[[nodiscard]] bool check_vm_artifacts() noexcept;
[[nodiscard]] bool check_user_interaction() noexcept;
[[nodiscard]] bool check_sleep_acceleration() noexcept;
[[nodiscard]] bool check_sandbox_processes() noexcept;
[[nodiscard]] bool check_debugger() noexcept;
[[nodiscard]] bool check_uptime() noexcept;

/// RAII guard: checks if environment is safe for sensitive operations.
class SafeExecGuard {
public:
    /// Runs quick heuristics on construction.
    SafeExecGuard() noexcept : safe_(!is_sandboxed()) {}

    [[nodiscard]] bool is_safe() const noexcept { return safe_; }

private:
    bool safe_;
};

} // namespace vh::sandbox

