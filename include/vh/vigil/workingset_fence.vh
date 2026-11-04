#pragma once

/**
 * vh/vigil/workingset_fence.vh — Working set inspection awareness
 *
 * Anti-cheat engines inspect the working set to detect:
 *
 *   * Pages recently accessed (working set age analysis)
 *   * Executable pages not belonging to known modules
 *   * Memory access pattern anomalies (page fault monitoring)
 *   * Working set trimming as a side-channel probe
 *
 * Detection methods:
 *
 *   * QueryWorkingSet / QueryWorkingSetEx
 *   * K32GetProcessMemoryInfo / GetProcessMemoryInfo
 *   * NtQueryVirtualMemory (MemoryWorkingSetInformation)
 *
 * This module provides:
 *
 *   1. Per-engine working set inspection profiles.
 *   2. Working set audit — find executable pages outside known modules.
 *   3. Memory usage statistics.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_WORKINGSET_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::workingset_fence {

struct PageInfo {
    uintptr_t       virtual_address;
    bool            is_executable;
    bool            is_shared;
    bool            is_in_module;
    std::string     module_name;
    bool            is_suspicious;  // executable + not in module
};

struct WorkingSetStats {
    size_t          total_pages;
    size_t          executable_pages;
    size_t          executable_unowned;  // executable pages outside modules
    size_t          working_set_size;    // bytes
    size_t          peak_working_set;
    size_t          page_fault_count;
};

/// Get working set statistics.
VH_API WorkingSetStats get_stats() noexcept;

/// Find executable pages not belonging to known modules.
VH_API vh::Result<std::vector<PageInfo>> find_suspicious_pages() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine working set inspection profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class WorkingSetCheck : uint32_t {
    ExecutablePageScan      = 1u << 0,
    UnownedExecutableScan   = 1u << 1,
    WorkingSetSizeCheck     = 1u << 2,
    PageFaultMonitor        = 1u << 3,
    WorkingSetTrimProbe     = 1u << 4,
    AccessBitAnalysis       = 1u << 5,
};

VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::workingset_fence
