#pragma once

/**
 * vh/config.hpp
 * Simplified, discoverable configuration structs under vh::config::.
 *
 * These replace the verbose TrampolineOptions / IATOptions / PLTOptions /
 * VTableOptions from vanhooks::. The old names are kept as deprecated aliases
 * so all existing code continues to compile unchanged.
 */

#include <string>
#include <string_view>
#include <cstddef>

#include <vanhooks/vanhooks.hpp>

namespace vh::config {

// ─────────────────────────────────────────────
//  Trampoline (inline patch) options
// ─────────────────────────────────────────────

struct Trampoline {
    bool        thread_safe = true;  // suspend threads during patch (recommended)
    std::string tag;
};

// ─────────────────────────────────────────────
//  API hook options  (hook_api / api_hook)
//  Resolves target via GetModuleHandle + GetProcAddress (Windows) or dlsym (POSIX).
// ─────────────────────────────────────────────

struct API {
    std::string_view module_name;    // e.g. "user32" or "user32.dll"
    std::string_view function_name;  // e.g. "MessageBoxW"
    bool             thread_safe = true;
    std::string      tag;
};

// ─────────────────────────────────────────────
//  IAT hook options  (Windows import table)
// ─────────────────────────────────────────────

struct IAT {
    std::string_view module_name;    // module containing the IAT (empty = all loaded)
    std::string_view import_name;    // symbol name to redirect
    std::string      tag;
};

// ─────────────────────────────────────────────
//  PLT / GOT hook options  (Linux / macOS)
// ─────────────────────────────────────────────

struct PLT {
    std::string_view library_name;   // shared object name, e.g. "libc"
    std::string_view symbol_name;    // symbol to redirect, e.g. "malloc"
    std::string      tag;
};

// ─────────────────────────────────────────────
//  VTable hook options
// ─────────────────────────────────────────────

struct VTable {
    void**      vtable     = nullptr;
    size_t      slot       = 0;      // which slot to patch (was slot_index)
    std::string tag;
};

// ─────────────────────────────────────────────
//  Mid-function hook options
// ─────────────────────────────────────────────

struct Mid {
    size_t      offset      = 0;     // byte offset into target function
    bool        thread_safe = true;
    std::string tag;
};

// ─────────────────────────────────────────────
//  HwBp hook options  (Hardware Breakpoint via DR0-DR3 + VEH)
//  Windows x64 only; returns Error::Unsupported elsewhere.
// ─────────────────────────────────────────────

struct HwBp {
    uint8_t     dr_slot = 0xFF;  // 0-3 or 0xFF (auto-pick first free slot)
    std::string tag;
};

// ─────────────────────────────────────────────
//  PageGuard hook options  (PAGE_GUARD VEH trap)
//  Windows only; returns Error::Unsupported on POSIX.
// ─────────────────────────────────────────────

struct PageGuard {
    vanhooks::PageGuardCondition condition   = vanhooks::PageGuardCondition::Execute;
    bool                         auto_rearm  = true;
    std::string                  tag;
};

// ─────────────────────────────────────────────
//  Instrumentation Callback options  (Nirvana IC)
//  Windows x64 only; process-wide singleton.
// ─────────────────────────────────────────────

struct IC {
    std::string tag;
};

} // namespace vh::config

// ─────────────────────────────────────────────
//  Compatibility guard
//  Verify that vh::config::Trampoline and vanhooks::TrampolineOptions remain
//  size-compatible. If you add a field to one, add it to the other too.
// ─────────────────────────────────────────────
static_assert(sizeof(vh::config::Trampoline) == sizeof(vanhooks::TrampolineOptions),
    "vh::config::Trampoline and vanhooks::TrampolineOptions have diverged — "
    "keep them in sync or remove the deprecated TrampolineOptions.");
static_assert(alignof(vh::config::Trampoline) == alignof(vanhooks::TrampolineOptions),
    "vh::config::Trampoline and vanhooks::TrampolineOptions alignment mismatch.");
static_assert(offsetof(vh::config::Trampoline, thread_safe) ==
              offsetof(vanhooks::TrampolineOptions, thread_safe),
    "vh::config::Trampoline::thread_safe and vanhooks::TrampolineOptions::thread_safe "
    "have different offsets — structs have diverged.");

// Layout guards for new option structs (check dr_slot / condition fields exist at offset 0).
static_assert(offsetof(vh::config::HwBp,     dr_slot)   == 0);
static_assert(offsetof(vh::config::PageGuard, condition) == 0);
