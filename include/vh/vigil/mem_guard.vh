#pragma once

/**
 * vh/mem_guard.vh — Memory permission rotation guard
 *
 * Prevents RWX regions from ever existing and rotates executable memory
 * through three states to evade memory scanners:
 *
 *   RW  (write phase)  → shellcode / trampoline bytes are written
 *   RX  (execute phase) → code runs with no write permission
 *   NA  (idle phase)    → PAGE_NOACCESS when not executing; invisible
 *                         to scanners looking for RX/RWX private pages
 *
 * Designed to integrate with:
 *   - Trampoline allocator (engine.vh)
 *   - Sleep obfuscation (sleep_obf.vh)
 *   - Heap encryption (heap_crypt.vh)
 *   - Injection routines (inject_process_manip.vh)
 *
 * Usage
 * ─────
 *
 *   #include <vh/vigil/mem_guard.vh>
 *
 *   // Register a memory region for rotation
 *   auto handle = vh::mem_guard::protect(base, size);
 *
 *   // When you need to write:
 *   {
 *       vh::mem_guard::WriteGuard wg(handle);
 *       memcpy(base, payload, size);
 *   }  // auto-flips to RX
 *
 *   // When you need to execute:
 *   {
 *       vh::mem_guard::ExecGuard eg(handle);
 *       fn_ptr();  // runs at RX
 *   }  // auto-flips to NA
 *
 *   // Manual control
 *   vh::mem_guard::make_writable(handle);   // → RW
 *   vh::mem_guard::make_executable(handle); // → RX
 *   vh::mem_guard::make_hidden(handle);     // → NA
 *
 * Platform: Windows x64/x86 (uses indirect syscalls for NtProtectVirtualMemory).
 * POSIX: mprotect() based, no indirect syscall needed.
 */

#include <vanhooks/vanhooks.vh>
#include <cstdint>

namespace vh::mem_guard {

/// Opaque handle to a guarded region.
using RegionId = std::uint64_t;

/// Memory state enum.
enum class State : std::uint8_t {
    Writable   = 0,   ///< PAGE_READWRITE — safe to write
    Executable = 1,   ///< PAGE_EXECUTE_READ — safe to execute
    Hidden     = 2,   ///< PAGE_NOACCESS — invisible to scanners
};

/// Register a memory region for permission rotation.
/// Returns a handle for subsequent state transitions.
[[nodiscard]] RegionId protect(void* base, std::size_t size) noexcept;

/// Unregister a guarded region (restores to RW).
void unprotect(RegionId id) noexcept;

/// Transition to writable (RW).
[[nodiscard]] bool make_writable(RegionId id) noexcept;

/// Transition to executable (RX).
[[nodiscard]] bool make_executable(RegionId id) noexcept;

/// Transition to hidden (PAGE_NOACCESS).
[[nodiscard]] bool make_hidden(RegionId id) noexcept;

/// Query current state.
[[nodiscard]] State current_state(RegionId id) noexcept;

/// How many regions are currently guarded.
[[nodiscard]] std::size_t guarded_count() noexcept;

/// Hide ALL guarded regions (bulk transition to NA).
/// Useful before sleep obfuscation.
void hide_all() noexcept;

/// Reveal ALL guarded regions (bulk transition to RX).
/// Useful after sleep obfuscation wakeup.
void reveal_all() noexcept;

/// RAII guard: makes region writable for its lifetime, then flips to RX.
class WriteGuard {
public:
    explicit WriteGuard(RegionId id) noexcept : id_(id), ok_(make_writable(id)) {}
    ~WriteGuard() noexcept { if (ok_) (void)make_executable(id_); }

    WriteGuard(const WriteGuard&)            = delete;
    WriteGuard& operator=(const WriteGuard&) = delete;
    WriteGuard(WriteGuard&& o) noexcept : id_(o.id_), ok_(o.ok_) { o.ok_ = false; }
    WriteGuard& operator=(WriteGuard&&)      = delete;

    [[nodiscard]] bool ok() const noexcept { return ok_; }

private:
    RegionId id_;
    bool     ok_;
};

/// RAII guard: makes region executable for its lifetime, then flips to NA.
class ExecGuard {
public:
    explicit ExecGuard(RegionId id) noexcept : id_(id), ok_(make_executable(id)) {}
    ~ExecGuard() noexcept { if (ok_) (void)make_hidden(id_); }

    ExecGuard(const ExecGuard&)            = delete;
    ExecGuard& operator=(const ExecGuard&) = delete;
    ExecGuard(ExecGuard&& o) noexcept : id_(o.id_), ok_(o.ok_) { o.ok_ = false; }
    ExecGuard& operator=(ExecGuard&&)      = delete;

    [[nodiscard]] bool ok() const noexcept { return ok_; }

private:
    RegionId id_;
    bool     ok_;
};

} // namespace vh::mem_guard

