#pragma once

/**
 * vh/vigil/minifilter_fence.vh — Minifilter driver awareness
 *
 * Anti-cheat engines deploy minifilter drivers to monitor:
 *
 *   * File creation / opening (IRP_MJ_CREATE pre/post callbacks)
 *   * File reads and writes (IRP_MJ_READ / IRP_MJ_WRITE)
 *   * File rename / delete operations
 *   * Directory enumeration interception
 *   * Section (mapped file) creation monitoring
 *
 * This module provides:
 *
 *   1. Per-engine minifilter profiles.
 *   2. Minifilter operation awareness — which IRPs are intercepted.
 *   3. Known AC minifilter altitude detection.
 *
 * Platform: WIN32 for FilterFindFirst/Next enumeration, stubs on POSIX.
 *
 * Requires: VH_ENABLE_MINIFILTER_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::minifilter_fence {

enum class FilterOp : uint32_t {
    PreCreate       = 1u << 0,  // IRP_MJ_CREATE pre-operation
    PostCreate      = 1u << 1,  // IRP_MJ_CREATE post-operation
    PreRead         = 1u << 2,  // IRP_MJ_READ pre-operation
    PostRead        = 1u << 3,  // IRP_MJ_READ post-operation
    PreWrite        = 1u << 4,  // IRP_MJ_WRITE pre-operation
    PostWrite       = 1u << 5,  // IRP_MJ_WRITE post-operation
    PreSetInfo      = 1u << 6,  // IRP_MJ_SET_INFORMATION (rename/delete)
    PreDirEnum      = 1u << 7,  // IRP_MJ_DIRECTORY_CONTROL
    PreSection      = 1u << 8,  // IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION
    PreCleanup      = 1u << 9,  // IRP_MJ_CLEANUP
};

struct MinifilterProfile {
    ac::Engine  engine;
    uint32_t    operations;         // bitmask of FilterOp
    bool        blocks_file_access; // can deny file opens
    bool        hides_files;        // hides own files from enumeration
    bool        monitors_game_dir;  // watches game installation directory
};

struct LoadedFilter {
    std::string name;
    std::string altitude;
    uint32_t    frame_id;
    uint32_t    num_instances;
};

/// Get the minifilter profile for a specific AC engine.
VH_API MinifilterProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of minifilter operations a specific AC engine intercepts.
VH_API uint32_t operations_by(ac::Engine engine) noexcept;

/// Enumerate loaded minifilter drivers on the system.
VH_API vh::Result<std::vector<LoadedFilter>> enumerate_filters() noexcept;

} // namespace vh::ac::minifilter_fence
