#pragma once
/**
 * VanHooks — Native Linux syscall stubs
 *
 * Direct syscall invocation without libc, preventing LD_PRELOAD
 * and GOT/PLT hooks from intercepting our calls.  Each wrapper
 * issues the syscall instruction directly with inline assembly.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>

namespace vh::linux_sys {

VH_API long raw_syscall(long nr, long a0 = 0, long a1 = 0, long a2 = 0,
                        long a3 = 0, long a4 = 0, long a5 = 0) noexcept;

// Memory
VH_API long sys_mmap(void* addr, size_t len, int prot, int flags, int fd, long off) noexcept;
VH_API long sys_munmap(void* addr, size_t len) noexcept;
VH_API long sys_mprotect(void* addr, size_t len, int prot) noexcept;

// Process
VH_API long sys_getpid() noexcept;
VH_API long sys_gettid() noexcept;
VH_API long sys_kill(int pid, int sig) noexcept;
VH_API long sys_tgkill(int tgid, int tid, int sig) noexcept;

// Files
VH_API long sys_open(const char* path, int flags, int mode = 0) noexcept;
VH_API long sys_close(int fd) noexcept;
VH_API long sys_read(int fd, void* buf, size_t count) noexcept;
VH_API long sys_write(int fd, const void* buf, size_t count) noexcept;

// ptrace
VH_API long sys_ptrace(int request, int pid, void* addr, void* data) noexcept;

// process_vm
VH_API long sys_process_vm_readv(int pid, const void* local_iov, unsigned long liovcnt,
                                 const void* remote_iov, unsigned long riovcnt,
                                 unsigned long flags) noexcept;
VH_API long sys_process_vm_writev(int pid, const void* local_iov, unsigned long liovcnt,
                                  const void* remote_iov, unsigned long riovcnt,
                                  unsigned long flags) noexcept;

} // namespace vh::linux_sys
