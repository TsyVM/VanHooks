#pragma once
/**
 * VanHooks — eBPF awareness
 *
 * Detects eBPF programs that monitor system calls, network traffic,
 * and file access.  Modern Linux anti-cheat solutions use eBPF for
 * low-overhead kernel-level monitoring.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ebpf_aware {

enum class BpfProgType : uint8_t {
    Unknown         = 0,
    SocketFilter    = 1,
    Kprobe          = 2,
    Tracepoint      = 3,
    Xdp             = 4,
    PerfEvent       = 5,
    CgroupSkb       = 6,
    CgroupSock      = 7,
    LwtIn           = 8,
    LwtOut          = 9,
    LsmMac          = 10,
    Tracing         = 11,
};

struct BpfProgInfo {
    std::uint32_t id      = 0;
    BpfProgType type      = BpfProgType::Unknown;
    std::string name;
    std::uint32_t run_count = 0;
    std::uint64_t run_time_ns = 0;
    bool is_gpl           = false;
};

struct BpfMapInfo {
    std::uint32_t id      = 0;
    std::string name;
    std::uint32_t type    = 0;
    std::uint32_t key_size   = 0;
    std::uint32_t value_size = 0;
    std::uint32_t max_entries = 0;
};

VH_API std::vector<BpfProgInfo> enumerate_bpf_programs() noexcept;

VH_API std::vector<BpfMapInfo> enumerate_bpf_maps() noexcept;

VH_API bool has_bpf_monitoring() noexcept;

VH_API bool has_syscall_tracing() noexcept;

VH_API bool has_network_monitoring() noexcept;

VH_API bool has_file_monitoring() noexcept;

VH_API bool has_lsm_bpf() noexcept;

VH_API bool can_load_bpf() noexcept;

} // namespace vh::ebpf_aware
