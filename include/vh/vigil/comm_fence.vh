#pragma once

/**
 * vh/vigil/comm_fence.vh — IPC / communication channel awareness
 *
 * Anti-cheat engines scan for inter-process communication channels
 * that cheats use to relay data between an external tool and the game:
 *
 *   * Named pipes — CreateNamedPipe / ConnectNamedPipe
 *   * Shared memory sections — CreateFileMapping(INVALID_HANDLE_VALUE)
 *   * Mailslots — CreateMailslot
 *   * Memory-mapped files with suspicious names
 *   * Device I/O — DeviceIoControl to custom kernel drivers
 *
 * This module provides:
 *
 *   1. Per-engine IPC scanning profiles.
 *   2. Named object enumeration — find suspicious pipes/sections.
 *   3. IPC creation monitoring.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_COMM_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::comm_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  IPC channel types
// ─────────────────────────────────────────────────────────────────────────────

enum class ChannelKind : uint8_t {
    NamedPipe,
    SharedSection,
    Mailslot,
    MappedFile,
    DeviceHandle,
};

struct ChannelRisk {
    ChannelKind     kind;
    std::string     name;           // object name (\\.\pipe\X, Global\X, etc.)
    uint32_t        owner_pid;      // if determinable
    std::string     owner_name;
    bool            is_suspicious;  // matches known cheat patterns
};

/// Scan for suspicious named IPC objects.
VH_API vh::Result<std::vector<ChannelRisk>> scan_channels() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct CommEvent {
    enum class Api : uint8_t {
        CreateNamedPipe, ConnectNamedPipe,
        CreateFileMapping, OpenFileMapping, MapViewOfFile,
        CreateMailslot,
        DeviceIoControl,
    };
    Api             api;
    std::string     object_name;
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using CommCallback = void(*)(const CommEvent& event);

VH_API vh::Result<void> monitor_start(CommCallback cb) noexcept;
VH_API void monitor_stop() noexcept;
VH_API bool monitor_active() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine IPC scanning profiles
// ─────────────────────────────────────────────────────────────────────────────

enum class CommCheck : uint32_t {
    NamedPipeScan       = 1u << 0,
    SharedSectionScan   = 1u << 1,
    MailslotScan        = 1u << 2,
    MappedFileScan      = 1u << 3,
    DeviceIoMonitor     = 1u << 4,
    ObjectDirectoryWalk = 1u << 5,
    CrossProcessComm    = 1u << 6,
};

/// Bitmask of IPC checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::comm_fence
