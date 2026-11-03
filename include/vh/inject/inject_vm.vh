#pragma once
/**
 * VanHooks — process_vm_writev injection (Linux)
 *
 * Uses process_vm_writev to write shellcode directly into a remote
 * process's address space without ptrace.  Requires the same UID
 * or CAP_SYS_PTRACE.  Combined with /proc/<pid>/mem for execution
 * trigger.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>

namespace vh::inject_vm {

struct VmConfig {
    int      target_pid     = 0;
    void*    shellcode      = nullptr;
    size_t   shellcode_size = 0;
    bool     use_direct_syscalls = true;
};

VH_API Result<void*> inject(const VmConfig& cfg) noexcept;

VH_API Result<void*> write_memory(int pid, void* remote_addr, const void* local_buf,
                                  size_t size) noexcept;

VH_API Result<void*> allocate_remote(int pid, size_t size, int prot) noexcept;

} // namespace vh::inject_vm
