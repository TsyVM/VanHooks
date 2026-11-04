#pragma once
/**
 * VanHooks — procfs vigil modules
 *
 * /proc-based process, thread, and memory analysis native to Linux.
 * More capable than Windows API equivalents for certain introspection
 * tasks: FD enumeration, cgroup inspection, namespace detection.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::procfs_vigil {

struct FdInfo {
    int fd              = -1;
    std::string path;
    std::string type;
    bool is_socket      = false;
    bool is_pipe        = false;
};

struct CgroupInfo {
    std::string hierarchy;
    std::string controller;
    std::string path;
    bool is_v2          = false;
};

struct NamespaceInfo {
    std::string type;
    std::uint64_t inode = 0;
    bool is_root        = true;
};

struct StatusField {
    std::string key;
    std::string value;
};

VH_API std::vector<FdInfo> enumerate_fds(std::uint32_t pid = 0) noexcept;

VH_API std::vector<CgroupInfo> query_cgroups(std::uint32_t pid = 0) noexcept;

VH_API std::vector<NamespaceInfo> query_namespaces(std::uint32_t pid = 0) noexcept;

VH_API std::vector<StatusField> read_proc_status(std::uint32_t pid = 0) noexcept;

VH_API std::string read_proc_field(const char* field, std::uint32_t pid = 0) noexcept;

VH_API std::uint64_t read_proc_mem_value(std::uint64_t address, std::uint32_t pid = 0) noexcept;

VH_API bool is_in_container() noexcept;

VH_API bool is_in_docker() noexcept;

VH_API bool has_proc_access(std::uint32_t pid) noexcept;

} // namespace vh::procfs_vigil
