#pragma once
/**
 * VanHooks — Linux vigil full implementation
 *
 * Replaces generic POSIX stubs with real Linux-specific
 * implementations using /proc, syscalls, and kernel interfaces.
 * Provides comprehensive process/module/memory introspection.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::linux_vigil {

struct ModuleInfo {
    std::string name;
    std::string path;
    std::uint64_t base    = 0;
    std::uint64_t end     = 0;
    std::uint64_t size    = 0;
    bool is_executable    = false;
    bool is_shared_object = false;
};

struct MemoryRegion {
    std::uint64_t start       = 0;
    std::uint64_t end         = 0;
    bool readable             = false;
    bool writable             = false;
    bool executable           = false;
    bool is_private           = false;
    bool is_anonymous         = false;
    std::string pathname;
};

struct ThreadInfo {
    std::uint32_t tid     = 0;
    std::string name;
    char state            = '?';
    std::int64_t nice     = 0;
    std::uint64_t utime   = 0;
    std::uint64_t stime   = 0;
};

VH_API std::vector<ModuleInfo> enumerate_modules() noexcept;

VH_API std::vector<MemoryRegion> enumerate_memory_regions() noexcept;

VH_API std::vector<ThreadInfo> enumerate_threads() noexcept;

VH_API bool is_being_traced() noexcept;

VH_API bool is_running_as_root() noexcept;

VH_API std::uint32_t get_parent_pid() noexcept;

VH_API std::string get_process_name(std::uint32_t pid) noexcept;

VH_API std::string get_exe_path() noexcept;

VH_API bool has_capability(int cap) noexcept;

VH_API bool is_namespace_sandboxed() noexcept;

} // namespace vh::linux_vigil
