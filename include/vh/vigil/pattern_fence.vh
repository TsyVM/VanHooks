#pragma once

/**
 * vh/vigil/pattern_fence.vh — Memory pattern / signature scanning awareness
 *
 * Anti-cheat engines scan process memory for known cheat signatures:
 *
 *   * Byte-pattern scanning (IDA-style signatures with wildcards)
 *   * String literal scanning (cheat menu text, debug strings)
 *   * YARA-like rule matching
 *   * Heuristic code pattern detection (NOP sleds, shellcode prologues)
 *   * Cross-reference scanning (pointers to known cheat structures)
 *
 * This module provides:
 *
 *   1. Per-engine signature scanning profiles.
 *   2. Self-scan — detect scannable artifacts in your own memory.
 *   3. Common cheat byte patterns that ACs look for.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_PATTERN_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::pattern_fence {

enum class PatternKind : uint8_t {
    ByteSignature,      // known cheat byte pattern
    StringLiteral,      // scannable string constant
    NopSled,            // long NOP sequences (shellcode indicator)
    ShellcodePrologue,  // common shellcode entry patterns
    TrampolineIsland,   // dense JMP relay blocks
};

struct DetectablePattern {
    PatternKind     kind;
    uintptr_t       address;
    size_t          length;
    std::string     description;
};

/// Scan own process memory for patterns that ACs would flag.
VH_API vh::Result<std::vector<DetectablePattern>> self_scan() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Scanning method awareness
// ─────────────────────────────────────────────────────────────────────────────

struct ScanEvent {
    enum class Api : uint8_t {
        ReadProcessMemory, NtReadVirtualMemory,
        VirtualQuery, NtQueryVirtualMemory,
    };
    Api             api;
    uintptr_t       target_address;
    size_t          scan_size;
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using ScanCallback = void(*)(const ScanEvent& event);

VH_API vh::Result<void> monitor_start(ScanCallback cb) noexcept;
VH_API void monitor_stop() noexcept;
VH_API bool monitor_active() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine scanning profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class PatternCheck : uint32_t {
    BytePatternScan     = 1u << 0,
    StringScan          = 1u << 1,
    YaraRules           = 1u << 2,
    HeuristicCodeScan   = 1u << 3,
    CrossRefScan        = 1u << 4,
    PeriodicRescan      = 1u << 5,
    CloudSignatures     = 1u << 6,
};

VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::pattern_fence
