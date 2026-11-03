#pragma once
/**
 * VanHooks — Encrypted engine state
 *
 * Hook metadata, trampoline addresses, tag strings and the internal
 * hook list are held encrypted in memory.  Decrypted on access,
 * re-encrypted after.  Defeats memory scanners that pattern-match
 * on VanHooks data structures.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace vh::crypt {

struct CryptConfig {
    bool     encrypt_metadata   = true;
    bool     encrypt_trampolines = false;
    bool     rotate_keys        = true;
    uint32_t rotation_interval_ms = 5000;
};

VH_API Status init(const CryptConfig& cfg = {}) noexcept;

VH_API Status shutdown() noexcept;

VH_API void encrypt_region(void* base, size_t size) noexcept;
VH_API void decrypt_region(void* base, size_t size) noexcept;

VH_API void rotate_key() noexcept;

class VH_API ScopedDecrypt {
public:
    explicit ScopedDecrypt(void* base, size_t size) noexcept;
    ~ScopedDecrypt() noexcept;
    ScopedDecrypt(const ScopedDecrypt&) = delete;
    ScopedDecrypt& operator=(const ScopedDecrypt&) = delete;

private:
    void*  base_;
    size_t size_;
};

VH_API bool is_active() noexcept;

} // namespace vh::crypt
