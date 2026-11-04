#pragma once

/**
 * vh/vigil/module_integrity.vh — Module integrity checking awareness
 *
 * Anti-cheat engines verify loaded module integrity to detect:
 *
 *   * **Inline hooks** — CRC mismatch in .text section vs on-disk image
 *   * **IAT patches** — modified import table entries
 *   * **Manual-mapped DLLs** — MEM_IMAGE regions with no module entry
 *   * **Hollowed modules** — legitimate module base with replaced .text
 *   * **Trampolines** — JMP/CALL instructions at function prologues
 *
 * Verification methods:
 *
 *   * `.text` section CRC32/SHA256 against on-disk PE
 *   * IAT slot comparison vs fresh GetProcAddress resolution
 *   * Module list walk (PEB.Ldr vs NtQueryVirtualMemory)
 *   * PE header validation (checksum, section alignment, entry point)
 *
 * This module provides:
 *
 *   1. Per-engine integrity check profiles.
 *   2. Self-audit — check your own modules for detectable modifications.
 *   3. Monitoring of integrity-checking API calls.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_MODULE_INTEGRITY  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace vh::ac::module_integrity {

// ─────────────────────────────────────────────────────────────────────────────
//  Integrity check types
// ─────────────────────────────────────────────────────────────────────────────

enum class CheckKind : uint32_t {
    TextSectionCRC      = 1u << 0,  // .text CRC vs on-disk
    TextSectionHash     = 1u << 1,  // .text SHA256 vs on-disk
    IATValidation       = 1u << 2,  // IAT entries vs GetProcAddress
    PEHeaderCheck       = 1u << 3,  // PE checksum + section table
    ModuleListWalk      = 1u << 4,  // PEB.Ldr vs VirtualQuery walk
    EntryPointCheck     = 1u << 5,  // AddressOfEntryPoint integrity
    PrologueCheck       = 1u << 6,  // function prologue byte inspection
    RelocationCheck     = 1u << 7,  // relocation table integrity
};

/// Bitmask of checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Module audit
// ─────────────────────────────────────────────────────────────────────────────

struct ProloguePatch {
    uintptr_t           address;
    std::string         function_name;  // if resolvable
    uint8_t             original_bytes[16];
    uint8_t             current_bytes[16];
    uint8_t             patch_size;
    bool                is_jmp;         // starts with JMP / JMP [rip+disp]
    bool                is_call;        // starts with CALL
};

struct ModuleAudit {
    std::string         module_name;
    std::string         module_path;
    uintptr_t           base_address;
    uint32_t            text_section_crc;       // current .text CRC32
    uint32_t            disk_text_crc;          // on-disk .text CRC32
    bool                text_modified;          // CRC mismatch
    uint32_t            iat_patches;            // number of IAT entries diverging
    uint32_t            prologue_patches;       // number of hooked functions found
    std::vector<ProloguePatch> patched_functions;
    bool                is_manual_mapped;       // MEM_IMAGE but not in Ldr list
    bool                header_valid;           // PE header passes checks
};

/// Audit a specific loaded module for detectable modifications.
VH_API vh::Result<ModuleAudit> audit_module(std::string_view module_name) noexcept;

/// Audit all loaded modules.
VH_API vh::Result<std::vector<ModuleAudit>> audit_all() noexcept;

/// Quick check: is a specific module's .text section modified?
VH_API bool text_modified(std::string_view module_name) noexcept;

/// Quick check: how many IAT patches are detectable in a module?
VH_API uint32_t iat_patch_count(std::string_view module_name) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Monitoring
// ─────────────────────────────────────────────────────────────────────────────

struct IntegrityEvent {
    enum class Api : uint8_t {
        ReadProcessMemory, NtReadVirtualMemory,
        CreateFileMapping, MapViewOfFile,
        GetModuleHandleEx, GetProcAddress,
        NtQueryVirtualMemory,
    };
    Api             api;
    std::string     target_module;  // which module is being read
    uint64_t        caller_rip;
    std::string     caller_module;
    bool            is_ac;
};

using IntegrityCallback = void(*)(const IntegrityEvent& event);

VH_API vh::Result<void> monitor_start(IntegrityCallback cb) noexcept;
VH_API void monitor_stop() noexcept;
VH_API bool monitor_active() noexcept;

} // namespace vh::ac::module_integrity
