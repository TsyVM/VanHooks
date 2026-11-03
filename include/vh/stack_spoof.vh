#pragma once

/**
 * vh/stack_spoof.vh — Return-address spoofing for call-stack camouflage
 *
 * Modern EDRs walk the user-mode call stack (via RtlVirtualUnwind or
 * RtlCaptureStackBackTrace) and flag frames that originate from
 * non-image-backed (private/unbacked) memory regions.  Any hook callback
 * or shellcode running from VirtualAlloc'd memory will produce a
 * suspicious frame.
 *
 * This module provides two complementary mitigations:
 *
 *   1. **Synthetic return-address spoofing** — before calling a sensitive
 *      API, push a return address that lives inside a legitimate module's
 *      .text section (a JMP RBX gadget), so the call stack seen by any
 *      in-flight ETW / kernel callback shows only backed frames.
 *
 *   2. **Frame pointer encryption** — XOR-encrypt stored RBP/RSP values
 *      in the Thread Environment Block's DeallocationStack region so
 *      stack-walk utilities that parse the TEB directly see garbage.
 *
 * Usage:
 *
 *     vh::stack_spoof::init();          // one-time — finds gadgets
 *     auto guard = vh::stack_spoof::SpoofGuard();
 *     SensitiveApi(...);                // stack walk sees ntdll frames
 *     // ~SpoofGuard restores the real return address
 *
 * Thread safety: init() is internally synchronized.  SpoofGuard is
 * thread-local by design (each thread has its own stack).
 */

#include <cstdint>

namespace vh::stack_spoof {

// ─────────────────────────────────────────────
//  Initialization
// ─────────────────────────────────────────────

/// Scan loaded modules for usable JMP-register gadgets.
/// Safe to call multiple times; subsequent calls are no-ops.
void init() noexcept;

/// Returns true after a successful init().
[[nodiscard]] bool ready() noexcept;

// ─────────────────────────────────────────────
//  RAII spoof guard
// ─────────────────────────────────────────────

/// Replaces the current frame's return address with a gadget inside a
/// legitimate module.  Destructor restores the original.
/// Stack-local — do NOT heap-allocate or move across threads.
class SpoofGuard {
public:
    SpoofGuard() noexcept;
    ~SpoofGuard() noexcept;

    SpoofGuard(const SpoofGuard&)            = delete;
    SpoofGuard& operator=(const SpoofGuard&) = delete;
    SpoofGuard(SpoofGuard&&)                 = delete;
    SpoofGuard& operator=(SpoofGuard&&)      = delete;

private:
    void*    saved_ret_  = nullptr;
    void**   frame_slot_ = nullptr;
};

// ─────────────────────────────────────────────
//  Manual API
// ─────────────────────────────────────────────

/// Get the address of a JMP RBX gadget inside ntdll.dll's .text section.
/// Returns nullptr if init() hasn't run or no gadget was found.
[[nodiscard]] void* gadget_addr() noexcept;

/// Spoof the return address of the caller's frame.  Returns the original
/// return address (caller must restore it before returning).
[[nodiscard]] void* spoof_caller_ret(void* fake_ret) noexcept;

/// Restore a previously spoofed return address.
void restore_caller_ret(void* original_ret) noexcept;

} // namespace vh::stack_spoof
