#pragma once

/**
 * vh/vigil/vad_fence.vh — Virtual Address Descriptor awareness
 *
 * Anti-cheat engines query the VAD tree to find:
 *
 *   * MEM_PRIVATE + PAGE_EXECUTE_READWRITE allocations (code caves)
 *   * MEM_IMAGE regions with no backing module (manual-mapped DLLs)
 *   * Large committed private regions (cheat payload staging)
 *   * Allocations near game modules (trampoline islands)
 *   * Guard pages used for single-step memory access detection
 *
 * Detection methods:
 *
 *   * NtQueryVirtualMemory (MemoryBasicInformation)
 *   * NtQueryVirtualMemory (MemoryMappedFilenameInformation)
 *   * VirtualQuery walk of the entire address space
 *
 * This module provides:
 *
 *   1. Per-engine VAD scanning profiles.
 *   2. Address space audit — find suspicious regions.
 *   3. Region classification.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_VAD_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::vad_fence {

enum class RegionRisk : uint8_t {
    Clean,              // normal module or system allocation
    ExecutablePrivate,  // MEM_PRIVATE + PAGE_EXECUTE*
    UnbackedImage,      // MEM_IMAGE with no module entry
    LargePrivate,       // large committed private region (>1MB)
    NearModule,         // private allocation adjacent to a game module
    GuardPage,          // PAGE_GUARD present
    NoAccess,           // PAGE_NOACCESS large block (potential staging)
};

struct RegionInfo {
    uintptr_t       base_address;
    size_t          region_size;
    uint32_t        protect;        // PAGE_* flags
    uint32_t        type;           // MEM_IMAGE / MEM_PRIVATE / MEM_MAPPED
    uint32_t        state;          // MEM_COMMIT / MEM_RESERVE / MEM_FREE
    RegionRisk      risk;
    std::string     module_name;    // if backed by a module
    std::string     mapped_file;    // if backed by a file
};

/// Walk the address space and classify suspicious regions.
VH_API vh::Result<std::vector<RegionInfo>> scan_regions() noexcept;

/// Count executable private regions.
VH_API uint32_t executable_private_count() noexcept;

/// Count unbacked MEM_IMAGE regions.
VH_API uint32_t unbacked_image_count() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine VAD scanning profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class VadCheck : uint32_t {
    ExecutablePrivateScan   = 1u << 0,
    UnbackedImageScan       = 1u << 1,
    LargePrivateScan        = 1u << 2,
    NearModuleScan          = 1u << 3,
    GuardPageDetect         = 1u << 4,
    MappedFileValidation    = 1u << 5,
    ProtectionHistoryCheck  = 1u << 6,
};

VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::vad_fence
