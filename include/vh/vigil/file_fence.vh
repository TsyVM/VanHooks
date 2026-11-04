#pragma once

/**
 * vh/vigil/file_fence.vh — File system scanning awareness
 *
 * Anti-cheat engines scan the file system to detect:
 *
 *   * Known cheat tool binaries on disk
 *   * Modified game files (hash comparison)
 *   * Cheat configuration files (INI, JSON, XML in known paths)
 *   * Recently modified files in game / temp directories
 *   * DLL injection artifacts (dropped DLLs in game folder)
 *
 * Scan methods:
 *
 *   * **FindFirstFile / FindNextFile** — directory enumeration
 *   * **GetFileAttributes** — existence checks on known paths
 *   * **CreateFile + ReadFile** — hash-reading game files
 *   * **NtQueryDirectoryFile** — low-level directory queries
 *   * **GetFileTime** — modification timestamp checks
 *
 * This module provides:
 *
 *   1. A database of file paths / names each AC engine looks for.
 *   2. Risk assessment of files present on disk.
 *   3. Monitoring of file system enumeration APIs.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_FILE_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vh::ac::file_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Known file signatures
// ─────────────────────────────────────────────────────────────────────────────

enum class FileCategory : uint8_t {
    CheatBinary,        // known cheat tool executable
    CheatConfig,        // cheat tool config / settings file
    InjectionArtifact,  // dropped DLLs, shellcode files
    DebugTool,          // debugger binaries
    ModifiedGame,       // altered game file (hash mismatch)
    TempArtifact,       // suspicious temp files
};

enum class MatchKind : uint8_t {
    ExactName,          // filename matches exactly
    NameSubstring,      // filename contains
    PathSubstring,      // full path contains
    Extension,          // file extension matches
};

struct FileSignature {
    std::string_view    pattern;
    MatchKind           match;
    FileCategory        category;
    std::string_view    tool_name;      // what tool this identifies
    uint32_t            engines;        // bitmask of engines that scan for this
};

/// All known file signatures ACs look for.
VH_API std::span<const FileSignature> known_signatures() noexcept;

/// Filter to signatures relevant to a specific engine.
VH_API std::vector<FileSignature> signatures_for(ac::Engine engine) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Disk scan
// ─────────────────────────────────────────────────────────────────────────────

struct FileRisk {
    std::string         path;
    std::string         filename;
    FileCategory        category;
    std::string_view    matched_tool;
    uint64_t            file_size;
    uint64_t            last_modified;  // FILETIME as uint64
    bool                matches_signature;
};

/// Scan common directories for known AC-flagged files.
/// Checks: game directory, %TEMP%, %APPDATA%, Desktop.
VH_API vh::Result<std::vector<FileRisk>> scan_common_paths() noexcept;

/// Scan a specific directory for AC-flagged files.
VH_API vh::Result<std::vector<FileRisk>> scan_directory(std::string_view path) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  File access monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct AccessEvent {
    enum class Api : uint8_t {
        FindFirstFile, FindNextFile, GetFileAttributes,
        CreateFile, NtQueryDirectoryFile, GetFileTime,
    };
    Api             api;
    std::string     path;
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using AccessCallback = void(*)(const AccessEvent& event);

/// Start monitoring file system access APIs.
VH_API vh::Result<void> monitor_start(AccessCallback cb) noexcept;

/// Stop monitoring.
VH_API void monitor_stop() noexcept;

/// Is monitoring active?
VH_API bool monitor_active() noexcept;

} // namespace vh::ac::file_fence
