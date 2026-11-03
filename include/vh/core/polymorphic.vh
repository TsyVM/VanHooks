#pragma once
/**
 * VanHooks — Polymorphic trampoline generation
 *
 * Every trampoline is unique: randomised register selection, junk
 * instruction insertion, and instruction-order shuffling so no two
 * hook installations share the same byte pattern.  Defeats static
 * signature scanning across processes.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>
#include <span>

namespace vh::poly {

struct PolyConfig {
    uint8_t  junk_density    = 3;
    bool     randomise_regs  = true;
    bool     shuffle_order   = true;
    bool     insert_nop_sled = false;
    uint32_t seed            = 0;
};

struct PolyTrampoline {
    void*    code       = nullptr;
    size_t   code_size  = 0;
    void*    original   = nullptr;
    uint64_t signature  = 0;
};

VH_API Result<PolyTrampoline> generate(void* target, void* detour,
                                       const PolyConfig& cfg = {}) noexcept;

VH_API void destroy(PolyTrampoline& tramp) noexcept;

VH_API void reseed(uint32_t new_seed) noexcept;

VH_API size_t estimate_size(size_t stolen_bytes, const PolyConfig& cfg) noexcept;

} // namespace vh::poly
