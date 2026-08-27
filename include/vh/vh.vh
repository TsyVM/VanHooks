#pragma once

/**
 * vh/vh.hpp — VanHooks public API mega-include.
 *
 * Three-level progressive API:
 *
 *   Level 1 — vh::hook(target, detour)
 *   Level 2 — vh::inline_hook / api_hook / vtable_hook / iat_hook / plt_hook / mid_hook
 *   Level 3 — vh::group("Name")  →  Group;  vh::HookRegistry::global()
 *
 * #include <vh/vh.vh>  is the only include end users need.
 */

#include "fwd.vh"
#include "result.vh"
#include "mid.vh"
#include "config.vh"
#include "hook.vh"
#include "group.vh"
#include "detail/callsite_bridge.vh"
#include "advanced.vh"

// ── Disassembler (always available — Zydis is always linked) ────────────────
#include "disasm.vh"

// ── VanTrace instrumentation layer (opt-out via VH_ENABLE_TRACE=OFF) ─────────
#if defined(VH_TRACE_ENABLED)
#  include "trace.vh"
#endif

// ── Optional network layer ───────────────────────────────────────────────────
#ifdef VH_NET_ENABLED
#  include "net.vh"
#endif

// ── Optional injection layer ─────────────────────────────────────────────────
#ifdef VH_INJECT_ENABLED
#  include "inject.vh"
#endif

// ── Optional symbol resolution layer ─────────────────────────────────────────
#ifdef VH_SYMBOLS_ENABLED
#  include "symbols.vh"
#endif

// ── Optional PE introspection layer ──────────────────────────────────────────
#ifdef VH_PE_ENABLED
#  include "pe.vh"
#endif

// ── Optional breakpoint layer ─────────────────────────────────────────────────
#ifdef VH_BREAKPOINT_ENABLED
#  include "breakpoint.vh"
#endif

// ── Optional callstack capture layer ─────────────────────────────────────────
#ifdef VH_CALLSTACK_ENABLED
#  include "callstack.vh"
#endif

#include <vanhooks/vanhooks.hpp>

#include <string_view>
#include <vector>

namespace vh {

using vanhooks::HookHandle;
using vanhooks::HookKind;
using vanhooks::HookDesc;
using vanhooks::Engine;

// ── Internal bridge declarations (compiled into the library) ──────────────────

namespace detail {
    // Trampoline
    Result<HookHandle> eng_hook_trampoline(Engine*, void* target, void* detour,
                                           void** orig, bool thread_safe, std::string tag);
    // API (by name)
    Result<HookHandle> eng_hook_api(Engine*, std::string_view module, std::string_view symbol,
                                    void* detour, void** orig, bool thread_safe, std::string tag);
    // IAT
    Result<HookHandle> eng_hook_iat(Engine*, std::string_view module, std::string_view import_name,
                                    void* detour, std::string tag);
    Result<std::vector<HookHandle>> eng_hook_iat_all(Engine*, std::string_view module,
                                                      std::string_view import_name,
                                                      void* detour, std::string tag);
    // PLT
    Result<HookHandle> eng_hook_plt(Engine*, std::string_view library, std::string_view symbol,
                                    void* detour, std::string tag);
    // VTable
    Result<HookHandle> eng_hook_vtable(Engine*, void** vtable, size_t slot,
                                       void* detour, std::string tag);
    // Mid
    Result<HookHandle> eng_hook_mid(Engine*, void* target, size_t offset,
                                    vanhooks::MidCallback cb, bool thread_safe, std::string tag);
    // eng_hook_callsite is declared in detail/callsite_bridge.vh (included above).
    // HwBp
    Result<HookHandle> eng_hook_hwbp(Engine*, void* target,
                                     vanhooks::MidCallback cb,
                                     vanhooks::HwBpOptions opts);
    // PageGuard
    Result<HookHandle> eng_hook_page_guard(Engine*, void* target,
                                           vanhooks::MidCallback cb,
                                           vanhooks::PageGuardOptions opts);
    // Instrumentation Callback
    Result<HookHandle> eng_hook_ic(Engine*,
                                   vanhooks::ICCallback cb,
                                   vanhooks::ICOptions  opts);
} // namespace detail

// ═════════════════════════════════════════════
//  Level 1 — Beginner API
// ═════════════════════════════════════════════

template<typename Fn>
[[nodiscard]] Result<Hook> hook(Fn* target, Fn* detour) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        nullptr, true, {})
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

template<typename Fn>
[[nodiscard]] Result<Hook> hook(Fn* target, Fn* detour, Fn** original_out) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out), true, {})
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

template<typename Fn>
[[nodiscard]] Result<Hook> hook(std::string_view module, std::string_view symbol,
                                Fn* detour, Fn** original_out = nullptr) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_api(&eng, module, symbol,
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out), true, {})
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// Address-based overloads — accept a raw uintptr_t target so callers working
// with runtime-resolved addresses do not need a reinterpret_cast at every site.
//
//   vh::hook(0x5D5DB0, &MyFunc);
//   vh::hook(0x5E7859, &MyDetour, &orgFunc);
template<typename Fn>
[[nodiscard]] Result<Hook> hook(uintptr_t target, Fn* detour) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        nullptr, true, {})
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

template<typename Fn>
[[nodiscard]] Result<Hook> hook(uintptr_t target, Fn* detour, Fn** original_out) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out), true, {})
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ═════════════════════════════════════════════
//  Level 2 — Explicit Hook Type API
// ═════════════════════════════════════════════

template<typename Fn>
[[nodiscard]] Result<Hook> inline_hook(Fn* target, Fn* detour,
                                       Fn** original_out = nullptr,
                                       config::Trampoline opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out),
        opts.thread_safe, opts.tag)
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// Address-based overload for inline_hook.
template<typename Fn>
[[nodiscard]] Result<Hook> inline_hook(uintptr_t target, Fn* detour,
                                       Fn** original_out = nullptr,
                                       config::Trampoline opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out),
        opts.thread_safe, opts.tag)
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

template<typename Fn>
[[nodiscard]] Result<Hook> api_hook(std::string_view module, std::string_view symbol,
                                    Fn* detour, Fn** original_out = nullptr,
                                    config::Trampoline opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_api(&eng, module, symbol,
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out),
        opts.thread_safe, opts.tag)
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

[[nodiscard]] inline Result<Hook> vtable_hook(void** vtable, size_t slot,
                                              void* detour,
                                              void** /*original_out*/ = nullptr,
                                              config::VTable opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_vtable(&eng, vtable, slot, detour, opts.tag)
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

[[nodiscard]] inline Result<Hook> iat_hook(std::string_view import_name,
                                           void* detour,
                                           config::IAT opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_iat(&eng, opts.module_name, import_name, detour, opts.tag)
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

[[nodiscard]] inline Result<std::vector<Hook>> iat_hook_all(std::string_view import_name,
                                                             void* detour,
                                                             config::IAT opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_iat_all(&eng, opts.module_name, import_name, detour, opts.tag)
        .transform([&eng](std::vector<HookHandle> handles) {
            std::vector<Hook> hooks;
            hooks.reserve(handles.size());
            for (auto& h : handles) hooks.emplace_back(eng, h);
            return hooks;
        });
}

[[nodiscard]] inline Result<Hook> plt_hook(std::string_view library,
                                           std::string_view symbol,
                                           void* detour,
                                           config::PLT opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_plt(&eng, library, symbol, detour, opts.tag)
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

[[nodiscard]] inline Result<Hook> mid_hook(void* target,
                                           vanhooks::MidCallback callback,
                                           config::Mid opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_mid(&eng, target, opts.offset, callback,
                                opts.thread_safe, opts.tag)
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ── CallSite hooks ─────────────────────────────────────────────────────────
//
// Patches the 32-bit relative displacement of a single CALL (E8) or JMP (E9)
// instruction, redirecting only that one call site to detour.  The resolved
// original absolute target is written to *orig.
//
// Primary target: x86 (32-bit Windows) — NFS:MW, GTA:SA, etc.
// x64: returns Error::TrampolineNoSpace if &detour is outside ±2 GB.
// ARM64: returns Error::Unsupported.
//
//   using PFN = void(__cdecl*)(int);
//   PFN g_orig = nullptr;
//   auto h = vh::callsite_hook(0x12AB34, &MyDetour, &g_orig);

// Address-based overload — primary API for game modding with pattern-scanned addresses.
template<typename Detour>
[[nodiscard]] Result<Hook> callsite_hook(uintptr_t site_addr,
                                         Detour*   detour,
                                         auto*     orig,
                                         vanhooks::CallSiteOptions opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_callsite(&eng, site_addr,
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(orig),
        opts.thread_safe, std::move(opts.tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// Function-pointer overload — for typed call sites where the address is known at compile time.
template<typename Fn>
[[nodiscard]] Result<Hook> callsite_hook(Fn*  site_addr,
                                         Fn*  detour,
                                         Fn** orig = nullptr,
                                         vanhooks::CallSiteOptions opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_callsite(&eng,
        reinterpret_cast<uintptr_t>(site_addr),
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(orig),
        opts.thread_safe, std::move(opts.tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ── HwBp hooks ────────────────────────────────────────────────────────────
//
// No bytes written to .text.  Fires via DR0-DR3 + VEH on execution of target.
// Windows x64 only; returns Error::Unsupported elsewhere.
// Up to 4 active hooks simultaneously (DR0-DR3 limit).
//
//   auto h = vh::hwbp_hook(0xDEADBEEF, &MyCallback);
//   auto h = vh::hwbp_hook(fn_ptr, &MyCallback, { .dr_slot = 2, .tag = "x" });

[[nodiscard]] inline Result<Hook> hwbp_hook(void*                    target,
                                             vanhooks::MidCallback    callback,
                                             vanhooks::HwBpOptions    opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_hwbp(&eng, target, callback, std::move(opts))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

template<typename Fn>
[[nodiscard]] Result<Hook> hwbp_hook(Fn* target,
                                      vanhooks::MidCallback   callback,
                                      vanhooks::HwBpOptions   opts = {}) {
    return hwbp_hook(reinterpret_cast<void*>(target), callback, std::move(opts));
}

// ── PageGuard hooks ───────────────────────────────────────────────────────
//
// Sets PAGE_GUARD on the target's page and fires via VEH on each access.
// Windows only; returns Error::Unsupported on POSIX.
//
//   auto h = vh::page_guard_hook(addr, &MyCallback);
//   auto h = vh::page_guard_hook(addr, &MyCallback,
//       { .condition = PageGuardCondition::Write, .auto_rearm = true });

[[nodiscard]] inline Result<Hook> page_guard_hook(
    void*                         target,
    vanhooks::MidCallback         callback,
    vanhooks::PageGuardOptions    opts = {})
{
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_page_guard(&eng, target, callback, std::move(opts))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ── Instrumentation Callback (Nirvana IC) ─────────────────────────────────
//
// Installs a process-wide hook on every kernel-to-user-mode transition.
// Windows x64 only; singleton — second install returns HookAlreadyExists.
//
//   auto h = vh::ic_hook(&MyNakedStub);

[[nodiscard]] inline Result<Hook> ic_hook(vanhooks::ICCallback   callback,
                                           vanhooks::ICOptions    opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_ic(&eng, callback, std::move(opts))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ═════════════════════════════════════════════
//  Level 3 — Group factory
// ═════════════════════════════════════════════

[[nodiscard]] inline Group group(std::string_view name = "") {
    return Group(std::string(name));
}

// ── Explicit shutdown ──────────────────────────────────────────────────────
//
// Call vh::shutdown() (or vanhooks::global_engine().remove_all()) before
// returning from DllMain(DLL_PROCESS_DETACH) or before unloading the library.
//
// The global engine is a function-local static; its destructor calls
// remove_all() automatically, but static-destruction order across translation
// units is unspecified. Explicit shutdown guarantees all hooks are removed
// while your own module objects are still live.
//
// Idempotent: safe to call multiple times.
inline void shutdown() {
    vanhooks::global_engine().remove_all();
}

} // namespace vh
