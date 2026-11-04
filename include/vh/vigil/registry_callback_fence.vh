#pragma once

/**
 * vh/vigil/registry_callback_fence.vh — Registry callback awareness
 *
 * Anti-cheat engines use CmRegisterCallbackEx to monitor:
 *
 *   * Registry key creation and opening
 *   * Value set / delete operations
 *   * Key enumeration and value enumeration
 *   * Key rename and key delete
 *   * Callback-based blocking of suspicious registry access
 *
 * This module provides:
 *
 *   1. Per-engine registry callback profiles.
 *   2. Registry operation awareness — which operations are monitored.
 *   3. Protected key awareness — which registry paths are shielded.
 *
 * Platform: cross-platform (awareness only, no OS-specific APIs).
 *
 * Requires: VH_ENABLE_REGISTRY_CALLBACK_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>

namespace vh::ac::registry_callback_fence {

enum class RegistryOp : uint32_t {
    KeyCreate       = 1u << 0,  // RegNtPreCreateKeyEx
    KeyOpen         = 1u << 1,  // RegNtPreOpenKeyEx
    KeyDelete       = 1u << 2,  // RegNtPreDeleteKey
    KeyRename       = 1u << 3,  // RegNtPreRenameKey
    ValueSet        = 1u << 4,  // RegNtPreSetValueKey
    ValueDelete     = 1u << 5,  // RegNtPreDeleteValueKey
    KeyEnum         = 1u << 6,  // RegNtPreEnumerateKey
    ValueEnum       = 1u << 7,  // RegNtPreEnumerateValueKey
    QueryKey        = 1u << 8,  // RegNtPreQueryKey
    QueryValue      = 1u << 9,  // RegNtPreQueryValueKey
};

struct RegistryCallbackProfile {
    ac::Engine  engine;
    uint32_t    operations;         // bitmask of RegistryOp
    bool        blocks_writes;      // can deny registry writes
    bool        hides_keys;         // hides own registry keys
    bool        monitors_ac_keys;   // watches AC-specific registry paths
};

/// Get the registry callback profile for a specific AC engine.
VH_API RegistryCallbackProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of registry operations a specific AC engine monitors.
VH_API uint32_t operations_by(ac::Engine engine) noexcept;

/// Whether the engine blocks registry writes to protected keys.
VH_API bool blocks_writes(ac::Engine engine) noexcept;

} // namespace vh::ac::registry_callback_fence
