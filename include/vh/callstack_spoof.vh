#pragma once

/**
 * vh/callstack_spoof.vh — Return-address spoofing.
 *
 * When another thread (an EDR sensor, an ETW-TI stack walker,
 * ``RtlCaptureStackBackTrace`` in a peer callback) walks the current
 * thread's stack, it treats each saved return address as evidence of who
 * called what.  If a foreign detour is on the stack, that shows up.
 *
 * ``callstack_spoof`` swaps the caller-side saved return address on the
 * stack for a "clean" gadget address — typically ``RtlUserThreadStart+0x21``
 * inside ntdll — for the duration of a scope.  A stack walker sampling
 * mid-scope sees the thread apparently returning to a legitimate
 * thread-entry site.
 *
 * This is a scoped RAII helper.  It does **not** rewrite deeper frames
 * (that is SilentMoonwalk-scale work); it defends the immediate frame,
 * which is the frame every "shallow" scanner actually reads.
 *
 * Usage
 * -----
 *
 *   NTSTATUS __stdcall DoSensitive(...) {
 *       VH_CALLSTACK_SPOOF();          // frame's return addr → ntdll gadget
 *       return NtProtectVirtualMemory(...);
 *   }                                  // return addr restored, real ret follows
 *
 * You can also fetch the pool of gadgets manually and construct a
 * ``ScopedSpoof`` in place if you want to control which gadget is used:
 *
 *   auto gadget = vh::callstack_spoof::pick_gadget();
 *   {
 *       vh::callstack_spoof::detail::ScopedSpoof s{
 *           static_cast<void**>(_AddressOfReturnAddress()),
 *           gadget.value_or(nullptr)};
 *       DoWork();
 *   }
 *
 * Platform: Windows x64 primary; Windows x86 supported.  POSIX returns
 * ``Unsupported`` from :cpp:func:`pick_gadget`, and the macro is a no-op.
 */

#include "result.vh"
#include <vanhooks/vanhooks.hpp>

#include <cstdint>

#if defined(_MSC_VER)
#  include <intrin.h>
#endif

namespace vh::callstack_spoof {

/**
 * Return one of several curated gadget addresses located inside ntdll or
 * kernel32 that look like plausible thread-entry return sites.  Round-robin
 * across gadgets to avoid a single detectable constant.
 */
[[nodiscard]] vh::Result<void*> pick_gadget() noexcept;

/**
 * Force-refresh the gadget pool.  Called automatically on first
 * ``pick_gadget()``.  Safe to invoke after a runtime module reload.
 */
vh::Result<void> refresh_gadgets() noexcept;

/// How many gadgets are currently in the pool.
[[nodiscard]] std::size_t gadget_count() noexcept;

namespace detail {

/// Swap ``*slot`` for ``fake`` on construction; restore on destruction.
/// ``slot`` must point to a real return-address stack slot — get one with
/// ``_AddressOfReturnAddress()`` INSIDE the function whose frame you are
/// spoofing.  A ``nullptr`` ``fake`` is a no-op (safe fallback when the
/// gadget pool is empty).
class ScopedSpoof {
public:
    ScopedSpoof(void** slot, void* fake) noexcept
        : slot_(slot), saved_(nullptr), active_(false)
    {
        if (slot_ && fake) {
            saved_  = *slot_;
            *slot_  = fake;
            active_ = true;
        }
    }

    ~ScopedSpoof() noexcept {
        if (active_) *slot_ = saved_;
    }

    ScopedSpoof(const ScopedSpoof&)            = delete;
    ScopedSpoof& operator=(const ScopedSpoof&) = delete;
    ScopedSpoof(ScopedSpoof&&)                 = delete;
    ScopedSpoof& operator=(ScopedSpoof&&)      = delete;

private:
    void** slot_;
    void*  saved_;
    bool   active_;
};

} // namespace detail
} // namespace vh::callstack_spoof

// ─────────────────────────────────────────────
//  Convenience macro
// ─────────────────────────────────────────────
//
// Must be expanded INSIDE the function whose frame you want to spoof — the
// intrinsic ``_AddressOfReturnAddress()`` returns the enclosing function's
// slot.

#if defined(_MSC_VER) && defined(_WIN32) && (defined(_M_X64) || defined(_M_IX86))

#  define VH_CALLSTACK_SPOOF()                                                     \
    auto _vh_gadget_ = ::vh::callstack_spoof::pick_gadget();                       \
    ::vh::callstack_spoof::detail::ScopedSpoof _vh_scoped_spoof_{                  \
        static_cast<void**>(_AddressOfReturnAddress()),                            \
        _vh_gadget_ ? *_vh_gadget_ : nullptr }

#else
#  define VH_CALLSTACK_SPOOF() ((void)0)
#endif
