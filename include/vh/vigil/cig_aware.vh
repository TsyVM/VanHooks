#pragma once
/**
 * VanHooks — CIG / ACG awareness
 *
 * Detects Code Integrity Guard and Arbitrary Code Guard policies.
 * When CIG is active, dynamic code generation (trampolines) is
 * blocked.  The engine falls back to signed-code-reuse paths:
 * module-stomp or ROP-chain trampolines.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::cig {

enum class Policy : uint8_t {
    None           = 0,
    CIG            = 1,
    ACG            = 2,
    CIG_and_ACG    = 3,
    CIG_Strict     = 4,
};

VH_API Policy query_policy() noexcept;

VH_API bool is_cig_active() noexcept;
VH_API bool is_acg_active() noexcept;
VH_API bool is_dynamic_code_blocked() noexcept;

enum class FallbackStrategy : uint8_t {
    ModuleStomp,
    RopChain,
    SignedCave,
    Fail,
};

VH_API FallbackStrategy recommended_strategy() noexcept;

} // namespace vh::cig
