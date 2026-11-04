#pragma once

/**
 * vh/vigil/heap_fence.vh — Heap metadata scanning awareness
 *
 * Anti-cheat engines inspect process heaps for:
 *
 *   * Heap corruption indicators (freed blocks reused for code)
 *   * Executable heap blocks (HeapAlloc + VirtualProtect RWX)
 *   * Custom heap creation (HeapCreate with HEAP_CREATE_ENABLE_EXECUTE)
 *   * Heap spray patterns (repeated allocations of similar size)
 *   * Debug heap flags (indicating attached debugger)
 *
 * This module provides:
 *
 *   1. Per-engine heap inspection profiles.
 *   2. Heap audit — enumerate process heaps and flag anomalies.
 *   3. Debug heap detection.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_HEAP_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <vector>

namespace vh::ac::heap_fence {

enum class HeapAnomaly : uint8_t {
    ExecutableBlocks,       // heap contains executable allocations
    ExecuteEnabled,         // heap created with HEAP_CREATE_ENABLE_EXECUTE
    DebugFlags,             // heap has debug flags set (debugger attached)
    UnusualCount,           // abnormal number of process heaps
    LargeUnusedReserve,     // heap reserves much more than committed
};

struct HeapInfo {
    uintptr_t               base;
    uint32_t                flags;
    size_t                  committed;
    size_t                  reserved;
    uint32_t                block_count;
    std::vector<HeapAnomaly> anomalies;
    bool                    is_default;     // GetProcessHeap()
    bool                    is_suspicious;
};

/// Audit all process heaps.
VH_API vh::Result<std::vector<HeapInfo>> audit_heaps() noexcept;

/// Quick check: any heap has debug flags?
VH_API bool debug_heap_active() noexcept;

/// Quick check: any heap has executable blocks?
VH_API bool executable_heap_present() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine heap inspection profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class HeapCheck : uint32_t {
    ExecutableBlockScan = 1u << 0,
    DebugFlagCheck      = 1u << 1,
    HeapCountCheck      = 1u << 2,
    HeapSprayDetect     = 1u << 3,
    CustomHeapDetect    = 1u << 4,
    HeapWalk            = 1u << 5,
};

VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::heap_fence
