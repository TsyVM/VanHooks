#pragma once

/**
 * vh/syscalls.vh — Direct + indirect syscall gate.
 *
 * Resolves Nt* system service numbers (SSNs) from the loaded ntdll image and
 * emits per-SSN stubs that invoke the corresponding syscall without going
 * through the user-mode ntdll dispatch trampoline.  Two flavours:
 *
 *   Direct  — the ``syscall`` instruction executes inside a VanHooks-allocated
 *             executable page.  Bypasses inline hooks on ntdll's Nt* stubs
 *             but leaves the ``syscall`` RIP outside ntdll, which some
 *             ETW-TI stack walks flag.
 *
 *   Indirect — the stub ends with a ``jmp`` to a ``syscall; ret`` gadget
 *              located inside ntdll's own ``.text``.  The ``syscall``
 *              instruction therefore executes at an ntdll address, matching
 *              what a legitimate ntdll dispatch would look like to a kernel
 *              stack walk.  Recommended for anything a real EDR watches.
 *
 * SSN resolution chain (``resolve_ssn`` in ``ResolveMode::Auto``):
 *
 *   1. **Hell's Gate** — parse the first bytes of the Nt* stub for the
 *      canonical ``mov r10, rcx / mov eax, <ssn> / syscall`` prologue and
 *      read the immediate.  Fast, exact.  Fails if the stub was hooked.
 *
 *   2. **Halo's Gate** — sort all Nt* exports by address, find the two
 *      neighbours of the target, extract SSNs from whichever neighbour is
 *      still clean, and derive the target SSN from the ordinal distance.
 *      Works even if the target is inline-hooked.
 *
 *   3. **Tartarus Gate** — if a target's neighbours are all hooked, expand
 *      the search radius until a clean stub is found and count from there.
 *
 * Every resolved SSN is cached process-wide; the second call for the same
 * name or hash is a hash-table hit.
 *
 * Platform: Windows x64 (primary) and Windows x86 (native, not WoW64).
 * Every entry point returns :cpp:enum:`vanhooks::Error::Unsupported` on
 * POSIX and on ARM64.  Under WoW64 (32-bit process on 64-bit Windows),
 * ``direct_stub`` works but ``indirect_stub`` requires the wow64cpu gadget
 * — see the note on ``wow64_indirect_stub`` below.
 *
 * Quick start
 * -----------
 *
 *   #include <vh/vh.vh>
 *
 *   using PFN_NtProtect = NTSTATUS (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
 *
 *   auto stub = vh::syscalls::stub_for("NtProtectVirtualMemory");
 *   if (!stub) return -1;
 *   auto NtProtect = reinterpret_cast<PFN_NtProtect>(*stub);
 *
 *   ULONG old = 0;
 *   NtProtect(GetCurrentProcess(), &page, &size, PAGE_READWRITE, &old);
 *
 *   // Direct instead of indirect (rare — indirect is the default and preferred):
 *   auto d = vh::syscalls::stub_for("NtProtectVirtualMemory",
 *                                    vh::syscalls::StubKind::Direct);
 */

#include "result.vh"
#include <vanhooks/vanhooks.vh>

#include <cstdint>
#include <string_view>

namespace vh::syscalls {

// ─────────────────────────────────────────────
//  Enums
// ─────────────────────────────────────────────

/// Which resolution technique the SSN resolver should attempt.
enum class ResolveMode : std::uint8_t {
    Auto,       ///< Hell → Halo → Tartarus fallback (default).
    Hell,       ///< Only read SSN from the stub prologue.  Fails on hooked stubs.
    Halo,       ///< Only derive SSN from neighbours.  Works past hooks.
    Tartarus,   ///< Halo with an unbounded expansion radius.
    /// Load a private clean copy of ntdll.dll from disk into a MEM_PRIVATE
    /// mapping and resolve the SSN directly from that image's stub bytes.
    /// Immune to all in-process hook forms (inline, IAT, trampoline) because
    /// the copy is never registered with the loader and is never executed —
    /// it is read-only for SSN extraction only.  Slower than the other modes
    /// (file I/O + PE parsing on first call) but the result is cached
    /// process-wide so subsequent calls are hash-table hits.
    /// Falls back to Tartarus if the file mapping fails.
    FreshNtdll,
};

/// Which kind of stub :cpp:func:`stub_for` / :cpp:func:`build_stub` emits.
enum class StubKind : std::uint8_t {
    Indirect,   ///< ``syscall`` executes inside ntdll's own gadget (default).
    Direct,     ///< ``syscall`` executes inside the allocated stub itself.
};

/// Rich result from :cpp:func:`resolve_ssn` — includes provenance for logging.
struct SsnResult {
    std::uint32_t ssn        = 0;
    ResolveMode   source     = ResolveMode::Auto;   ///< Which path actually succeeded.
    void*         stub_addr  = nullptr;             ///< The Nt* export address it came from (nullptr for hash path).
};

// ─────────────────────────────────────────────
//  Resolution
// ─────────────────────────────────────────────

/// Compile-time djb2 hash used by :cpp:func:`resolve_ssn_by_hash` for string-free lookup.
[[nodiscard]] constexpr std::uint32_t djb2(std::string_view s) noexcept {
    std::uint32_t h = 5381;
    for (unsigned char c : s) h = ((h << 5) + h) + c;
    return h;
}

/// Resolve an Nt* SSN by name.  Returns cached value on repeat calls.
[[nodiscard]]
vh::Result<SsnResult> resolve_ssn(std::string_view nt_name,
                                  ResolveMode      mode = ResolveMode::Auto) noexcept;

/// Resolve an Nt* SSN by djb2 hash of the export name.  Useful when you want
/// no plaintext of the API name in .rdata.
[[nodiscard]]
vh::Result<SsnResult> resolve_ssn_by_hash(std::uint32_t djb2_hash,
                                          ResolveMode   mode = ResolveMode::Auto) noexcept;

// ─────────────────────────────────────────────
//  Gadget discovery
// ─────────────────────────────────────────────

/**
 * Locate a ``syscall; ret`` (or ``sysenter; ret`` on x86) gadget inside
 * ntdll's ``.text``.  The result is cached.
 */
[[nodiscard]]
vh::Result<void*> get_syscall_gadget() noexcept;

// ─────────────────────────────────────────────
//  Stub emission
// ─────────────────────────────────────────────

/**
 * Emit (or return the cached) executable stub for ``ssn``.  Cast the result
 * to the target Nt* function's real pointer type and call it — argument
 * marshalling matches the Windows x64 fastcall / stdcall ABI exactly, so no
 * shuffling is required at the call site.
 */
[[nodiscard]]
vh::Result<void*> build_stub(std::uint32_t ssn,
                             StubKind      kind = StubKind::Indirect) noexcept;

/**
 * One-call: resolve ``nt_name`` and return the stub in ``kind``.
 * The resolved SSN and the returned stub are both cached.
 */
[[nodiscard]]
vh::Result<void*> stub_for(std::string_view nt_name,
                           StubKind         kind = StubKind::Indirect,
                           ResolveMode      mode = ResolveMode::Auto) noexcept;

/// Hash-form of :cpp:func:`stub_for`.
[[nodiscard]]
vh::Result<void*> stub_for_hash(std::uint32_t djb2_hash,
                                StubKind      kind = StubKind::Indirect,
                                ResolveMode   mode = ResolveMode::Auto) noexcept;

// ─────────────────────────────────────────────
//  Lifetime / diagnostics
// ─────────────────────────────────────────────

/// Free all cached stub pages and forget every resolved SSN.  Idempotent.
/// Safe to call once at DLL detach.
void shutdown() noexcept;

/// How many SSNs are currently cached (name-hash entries counted once).
[[nodiscard]] std::size_t cached_ssn_count() noexcept;

/// How many stub pages have been emitted (across both StubKind values).
[[nodiscard]] std::size_t emitted_stub_count() noexcept;

} // namespace vh::syscalls
