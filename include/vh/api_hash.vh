#pragma once

/**
 * vh/api_hash.vh — String-free module + export resolution.
 *
 * Replaces ``GetModuleHandleW`` / ``LoadLibraryW`` / ``GetProcAddress`` with
 * a PEB-walking resolver that takes 32-bit hashes instead of names.  No
 * plaintext of any looked-up API ends up in ``.rdata``.
 *
 * Hash functions
 * --------------
 *
 * Two constexpr hashers are provided; both fit in 32 bits.
 *
 *   * :cpp:func:`vh::api_hash::djb2` — Bernstein djb2.  Fast, well-known;
 *     used by the syscall gate for Nt* export lookup.
 *   * :cpp:func:`vh::api_hash::fnv1a` — FNV-1a 32-bit.  Slightly better
 *     avalanche if you're worried about naive collisions.
 *
 * Both are ASCII-case-insensitive when the string is a module name (Windows
 * treats module names case-insensitively) and case-sensitive for export
 * names (Windows' export table is case-sensitive).  The wide-character
 * overload lowercases per-character before hashing so
 * ``djb2_module(L"NTDLL.DLL") == djb2_module("ntdll.dll")``.
 *
 * Usage
 * -----
 *
 *   using namespace vh::api_hash;
 *
 *   constexpr auto H_KERNEL32 = module_djb2("kernel32.dll");
 *   constexpr auto H_VPROT    = export_djb2("VirtualProtect");
 *
 *   using PFN_VP = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
 *   auto VirtualProtect_ = reinterpret_cast<PFN_VP>(
 *       resolve(H_KERNEL32, H_VPROT));
 *   if (!VirtualProtect_) return -1;
 *
 * Resolutions are cached in a small hash table so repeated calls are O(1).
 *
 * Platform: Windows only.  POSIX entry points return ``nullptr`` /
 * :cpp:enum:`vanhooks::Error::Unsupported`.
 */

#include "result.vh"
#include <vanhooks/vanhooks.vh>

#include <cstdint>
#include <string_view>

namespace vh::api_hash {

// ─────────────────────────────────────────────
//  Hashers (constexpr, ASCII)
// ─────────────────────────────────────────────

[[nodiscard]] constexpr std::uint32_t djb2(std::string_view s) noexcept {
    std::uint32_t h = 5381;
    for (unsigned char c : s) h = ((h << 5) + h) + c;
    return h;
}

[[nodiscard]] constexpr std::uint32_t fnv1a(std::string_view s) noexcept {
    std::uint32_t h = 2166136261u;
    for (unsigned char c : s) { h ^= c; h *= 16777619u; }
    return h;
}

/// djb2 with per-character ASCII lower-case; use for module names.
[[nodiscard]] constexpr std::uint32_t module_djb2(std::string_view s) noexcept {
    std::uint32_t h = 5381;
    for (unsigned char c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
        h = ((h << 5) + h) + c;
    }
    return h;
}

/// djb2 without normalisation; use for export names.
[[nodiscard]] constexpr std::uint32_t export_djb2(std::string_view s) noexcept {
    return djb2(s);
}

/// Wide-character module hash — matches ``module_djb2`` byte-for-byte for
/// pure-ASCII module names.  Non-ASCII code units are truncated to their
/// low byte (Windows module names are ASCII in practice).
[[nodiscard]] constexpr std::uint32_t module_djb2(std::wstring_view s) noexcept {
    std::uint32_t h = 5381;
    for (wchar_t wc : s) {
        auto c = static_cast<unsigned char>(wc);
        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
        h = ((h << 5) + h) + c;
    }
    return h;
}

// ─────────────────────────────────────────────
//  PEB-walking resolution
// ─────────────────────────────────────────────

/**
 * Locate a loaded module by its lower-cased ASCII djb2 hash.  Walks the
 * PEB Ldr ``InLoadOrderModuleList``.  Returns ``nullptr`` if not present
 * — this function does **not** call ``LoadLibrary``.
 */
[[nodiscard]] void* find_module_by_hash(std::uint32_t module_hash) noexcept;

/**
 * Locate an export in ``module_base`` by djb2 hash of the export name.
 * Also handles forwarders (``xxx.dll.YyyFunc``) by chaining through
 * ``find_module_by_hash`` recursively.  Returns ``nullptr`` if not found.
 */
[[nodiscard]] void* find_export_by_hash(void*         module_base,
                                        std::uint32_t export_hash) noexcept;

/**
 * One-shot: ``find_module_by_hash`` then ``find_export_by_hash``.
 * Cached — the second call for the same hash pair returns from a hash
 * table without re-walking the PEB.  Thread-safe.
 */
[[nodiscard]] void* resolve(std::uint32_t module_hash,
                            std::uint32_t export_hash) noexcept;

/// Number of cached (module, export) → address entries.
[[nodiscard]] std::size_t cache_size() noexcept;

/// Drop the resolution cache.  Idempotent.  Rarely needed; useful in
/// long-running processes that unload modules.
void clear_cache() noexcept;

// ─────────────────────────────────────────────
//  Compile-time resolver template
// ─────────────────────────────────────────────

/**
 * Zero-runtime-cost holder that memoises a single (module, export) lookup
 * per template instantiation.
 *
 *   using VP = vh::api_hash::Resolver<
 *       vh::api_hash::module_djb2("kernel32.dll"),
 *       vh::api_hash::export_djb2("VirtualProtect")>;
 *
 *   auto fn = reinterpret_cast<PFN_VirtualProtect>(VP::get());
 */
template<std::uint32_t ModuleHash, std::uint32_t ExportHash>
struct Resolver {
    [[nodiscard]] static void* get() noexcept {
        static void* const cached = resolve(ModuleHash, ExportHash);
        return cached;
    }
};

} // namespace vh::api_hash
