#pragma once

/**
 * vh/config.vh
 * Simplified, discoverable configuration structs under vh::config::.
 *
 * These replace the verbose TrampolineOptions / IATOptions / PLTOptions /
 * VTableOptions from vanhooks::. The old names are kept as deprecated aliases
 * so all existing code continues to compile unchanged.
 */

#include <string>
#include <string_view>
#include <cstddef>

#include <vanhooks/vanhooks.vh>

namespace vh::config {

// ─────────────────────────────────────────────
//  Trampoline (inline patch) options
// ─────────────────────────────────────────────

struct Trampoline {
    bool        thread_safe = true;  // suspend threads during patch (recommended)
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
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

    [[nodiscard]] constexpr bool valid() const noexcept {
        return dr_slot == 0xFF || dr_slot <= 3;
    }
};

// ─────────────────────────────────────────────
//  PageGuard hook options  (PAGE_GUARD VEH trap)
//  Windows only; returns Error::Unsupported on POSIX.
// ─────────────────────────────────────────────

struct PageGuard {
    vanhooks::PageGuardCondition condition   = vanhooks::PageGuardCondition::Execute;
    bool                         auto_rearm  = true;
    std::string                  tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Instrumentation Callback options  (Nirvana IC)
//  Windows x64 only; process-wide singleton.
// ─────────────────────────────────────────────

struct IC {
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  EAT hook options
// ─────────────────────────────────────────────

struct EAT {
    std::string_view module_name;
    std::string_view export_name;
    std::string      tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return !module_name.empty() && !export_name.empty();
    }
};

// ─────────────────────────────────────────────
//  GOT hook options  (Linux/macOS)
// ─────────────────────────────────────────────

struct GOT {
    std::string_view library_name;
    std::string_view symbol_name;
    std::string      tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return !library_name.empty() && !symbol_name.empty();
    }
};

// ─────────────────────────────────────────────
//  Syscall gate hook options  (Windows x64 only)
// ─────────────────────────────────────────────

struct Syscall {
    std::string_view function_name;  // e.g. "NtProtectVirtualMemory"
    std::string      tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return !function_name.empty();
    }
};

// ─────────────────────────────────────────────
//  TLS callback hook options  (Windows only)
// ─────────────────────────────────────────────

struct TlsCallback {
    void*       module_base = nullptr;  // null = self
    size_t      slot        = 0;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Exception hook options
// ─────────────────────────────────────────────

struct Exception {
    uint32_t    exc_code  = 0;
    uintptr_t   addr_low  = 0;
    uintptr_t   addr_high = 0;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return exc_code != 0;
    }
};

// ─────────────────────────────────────────────
//  Thread-local hook options
// ─────────────────────────────────────────────

struct ThreadLocal {
    bool        thread_safe = true;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  SoftBp / VEH hook options
// ─────────────────────────────────────────────

struct SoftBp {
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Conditional hook options  (Phase 21)
// ─────────────────────────────────────────────

struct Conditional {
    vanhooks::ConditionFn condition  = nullptr;
    void*                 user_data  = nullptr;
    int32_t               priority   = 0;
    bool                  thread_safe = true;
    bool                  stats      = false;
    std::string           tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return condition != nullptr; }
};

// ─────────────────────────────────────────────
//  Lazy hook options  (Phase 21)
// ─────────────────────────────────────────────

struct Lazy {
    int32_t     priority    = 0;
    bool        thread_safe = true;
    bool        stats       = false;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Exit hook options  (Phase 21)
// ─────────────────────────────────────────────

struct ExitHook {
    size_t      max_scan_bytes = 4096;
    int32_t     priority       = 0;
    bool        thread_safe    = true;
    bool        stats          = false;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return max_scan_bytes > 0; }
};

// ─────────────────────────────────────────────
//  macOS dyld interpose options  (Phase 22)
// ─────────────────────────────────────────────

struct DyldInterpose {
    std::string original_symbol;
    std::string tag;

    [[nodiscard]] bool valid() const noexcept { return !original_symbol.empty(); }
};

// ─────────────────────────────────────────────
//  macOS Mach-O import hook options  (Phase 22)
// ─────────────────────────────────────────────

struct MachOImport {
    std::string library_name;
    std::string symbol_name;
    std::string tag;

    [[nodiscard]] bool valid() const noexcept {
        return !library_name.empty() && !symbol_name.empty();
    }
};

// ─────────────────────────────────────────────
//  ARM64 veneer stub options  (Phase 22)
// ─────────────────────────────────────────────

struct Veneer {
    bool        prefer_adrp_ldr = true;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Relay hook options  (Phase 24)
// ─────────────────────────────────────────────

struct Relay {
    size_t      pool_size   = 64;
    bool        thread_safe = true;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return pool_size > 0; }
};

// ─────────────────────────────────────────────
//  Copy-on-write hook options  (Phase 24)
// ─────────────────────────────────────────────

struct Cow {
    bool        thread_safe = true;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Signal-based hook options  (Phase 24, Linux)
// ─────────────────────────────────────────────

struct Signal {
    int         signal_num  = 5;  // SIGTRAP
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return signal_num > 0; }
};

// ─────────────────────────────────────────────
//  JIT hook options  (Phase 24)
// ─────────────────────────────────────────────

struct Jit {
    size_t      monitor_interval_ms = 100;
    bool        auto_repatch        = true;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
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
