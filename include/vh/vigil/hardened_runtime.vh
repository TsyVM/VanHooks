#pragma once
/**
 * VanHooks — Hardened Runtime awareness
 *
 * Detects macOS Hardened Runtime entitlements, code-signing status,
 * and library validation enforcement.  Required for macOS 10.15+
 * where unsigned or non-entitled code is blocked from JIT, debugging,
 * and DYLD environment variable injection.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::hardened_runtime {

struct EntitlementInfo {
    bool allow_jit                    = false;
    bool allow_unsigned_executable_memory = false;
    bool allow_dyld_environment_variables = false;
    bool disable_library_validation   = false;
    bool disable_executable_page_protection = false;
    bool com_apple_security_cs_debugger = false;
};

struct CodeSignInfo {
    bool          is_signed        = false;
    bool          is_valid         = false;
    bool          hardened_runtime = false;
    bool          library_validation = false;
    std::uint32_t flags            = 0;
    std::string   team_id;
    std::string   signing_id;
};

VH_API CodeSignInfo query_code_signing() noexcept;

VH_API CodeSignInfo query_code_signing_for(const char* path) noexcept;

VH_API EntitlementInfo query_entitlements() noexcept;

VH_API bool is_hardened_runtime_active() noexcept;

VH_API bool is_library_validation_active() noexcept;

VH_API bool can_execute_jit() noexcept;

VH_API bool can_modify_executable_pages() noexcept;

VH_API bool can_use_dyld_env_vars() noexcept;

} // namespace vh::hardened_runtime
