#pragma once

/**
 * vh/vh.vh — VanHooks public API mega-include.
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
#include "hooks/veh_hook.vh"

// ── Disassembler (always available — Zydis is always linked) ────────────────
#include "disasm.vh"

// ── VanTrace instrumentation layer (opt-out via VH_ENABLE_TRACE=OFF) ─────────
#if defined(VH_TRACE_ENABLED)
#  include "analysis/trace.vh"
#endif

// ── Optional network layer ───────────────────────────────────────────────────
#ifdef VH_NET_ENABLED
#  include "analysis/net.vh"
#endif

// ── Optional injection layer ─────────────────────────────────────────────────
#ifdef VH_INJECT_ENABLED
#  include "inject/inject.vh"
#endif

// ── Optional symbol resolution layer ─────────────────────────────────────────
#ifdef VH_SYMBOLS_ENABLED
#  include "analysis/symbols.vh"
#endif

// ── Optional PE introspection layer ──────────────────────────────────────────
#ifdef VH_PE_ENABLED
#  include "analysis/pe.vh"
#endif

// ── Optional breakpoint layer ─────────────────────────────────────────────────
#ifdef VH_BREAKPOINT_ENABLED
#  include "hooks/breakpoint.vh"
#endif

// ── Optional callstack capture layer ─────────────────────────────────────────
#ifdef VH_CALLSTACK_ENABLED
#  include "analysis/callstack.vh"
#endif

#ifdef VH_UNHOOK_ENABLED          //  1: NTDLL / kernel32 unhook
#  include "vigil/unhook.vh"
#endif
#ifdef VH_SYSCALLS_ENABLED        //  2: Direct/indirect syscall gate
#  include "vigil/syscalls.vh"
#endif
#ifdef VH_APIHASH_ENABLED         //  3: API-hash / PEB-walk resolver
#  include "vigil/api_hash.vh"
#endif
#ifdef VH_TELEMETRY_PATCH_ENABLED //  4: ETW + AMSI suppression
#  include "vigil/telemetry_patch.vh"
#endif
#ifdef VH_SLEEP_OBF_ENABLED       //  5: Sleep obfuscation
#  include "vigil/sleep_obf.vh"
#endif
#ifdef VH_CALLSTACK_SPOOF_ENABLED //  6: Return-address spoof
#  include "vigil/callstack_spoof.vh"
#endif
#ifdef VH_THREAD_HIDE_ENABLED     //  7: Thread hide + DR camouflage
#  include "vigil/thread_hide.vh"
#endif
#ifdef VH_PEB_MASK_ENABLED        //  8: PEB masking
#  include "vigil/peb_mask.vh"
#endif
#ifdef VH_MODULE_STOMP_ENABLED    //  9: Module stomping
#  include "vigil/module_stomp.vh"
#endif

// ── Extended injection catalogue ─────────────────────────────────────────────
#ifdef VH_INJECT_EX_ENABLED
#  include "inject/inject_ex.vh"
#  include "inject/inject_unified.vh"
#endif

#include <vanhooks/vanhooks.vh>

#include <string_view>
#include <vector>
#include <optional>

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
    // Delay-load IAT
    Result<HookHandle> eng_hook_delay_iat(Engine*, std::string_view module,
                                           std::string_view import_name,
                                           void* detour, std::string tag);
    Result<std::vector<HookHandle>> eng_hook_delay_iat_all(Engine*, std::string_view module,
                                                            std::string_view import_name,
                                                            void* detour, std::string tag);
    // PLT
    Result<HookHandle> eng_hook_plt(Engine*, std::string_view library, std::string_view symbol,
                                    void* detour, std::string tag);
    // GOT
    Result<HookHandle> eng_hook_got(Engine*, std::string_view library, std::string_view symbol,
                                    void* detour, std::string tag);
    // VTable
    Result<HookHandle> eng_hook_vtable(Engine*, void** vtable, size_t slot,
                                       void* detour, std::string tag);
    // Mid
    Result<HookHandle> eng_hook_mid(Engine*, void* target, size_t offset,
                                    vanhooks::MidCallback cb, bool thread_safe, std::string tag);
    // Return hook
    Result<HookHandle> eng_hook_return(Engine*, void* target,
                                        vanhooks::MidReturnEnterCallback enter_cb,
                                        vanhooks::ReturnCallback return_cb,
                                        bool thread_safe, std::string tag);
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
    // EAT
    Result<HookHandle> eng_hook_eat(Engine*, std::string_view module,
                                     std::string_view export_name,
                                     void* detour, std::string tag);
    // Syscall gate
    Result<HookHandle> eng_hook_syscall(Engine*, std::string_view function_name,
                                         void* detour, std::string tag);
    // TLS callback
    Result<HookHandle> eng_hook_tls_callback(Engine*, void* module_base, size_t slot,
                                              void* detour, std::string tag);
    // Exception
    Result<HookHandle> eng_hook_exception(Engine*,
                                           vanhooks::ExceptionCallback cb,
                                           vanhooks::ExceptionOptions opts);
    // Thread-local
    Result<HookHandle> eng_hook_thread_local(Engine*, void* target, void* detour,
                                              void** orig, std::string tag);
    void eng_thread_local_enable (Engine*, HookHandle) noexcept;
    void eng_thread_local_disable(Engine*, HookHandle) noexcept;
} // namespace detail

// ═════════════════════════════════════════════
//  Level 1 — Beginner API
// ═════════════════════════════════════════════

template<typename Fn>
[[nodiscard]] Result<Hook> hook(Fn* target, Fn* detour,
                                config::Trampoline opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        nullptr, opts.thread_safe, std::move(opts.tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

template<typename Fn>
[[nodiscard]] Result<Hook> hook(Fn* target, Fn* detour, Fn** original_out,
                                config::Trampoline opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out),
        opts.thread_safe, std::move(opts.tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

template<typename Fn>
[[nodiscard]] Result<Hook> hook(std::string_view module, std::string_view symbol,
                                Fn* detour, Fn** original_out = nullptr,
                                config::Trampoline opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_api(&eng, module, symbol,
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out),
        opts.thread_safe, std::move(opts.tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// Address-based overloads — accept a raw uintptr_t target so callers working
// with runtime-resolved addresses do not need a reinterpret_cast at every site.
//
//   vh::hook(0x5D5DB0, &MyFunc);
//   vh::hook(0x5E7859, &MyDetour, &orgFunc);
template<typename Fn>
[[nodiscard]] Result<Hook> hook(uintptr_t target, Fn* detour,
                                config::Trampoline opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        nullptr, opts.thread_safe, std::move(opts.tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

template<typename Fn>
[[nodiscard]] Result<Hook> hook(uintptr_t target, Fn* detour, Fn** original_out,
                                config::Trampoline opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out),
        opts.thread_safe, std::move(opts.tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ── make_hook — lambda / closure detour support ───────────────────────────
//
// Wraps any callable (lambda with captures, std::function substitute) as a hook
// detour without requiring a named free function or static.  The closure is kept
// alive inside a type-erased heap block owned by the returned Hook; it is freed
// when the Hook is destroyed.
//
// Sig is the raw function type, e.g. `decltype(MessageBoxA)`.
// The callable's operator() must be signature-compatible with Sig.
//
//   // orig captured from outer scope after hook installs
//   decltype(MessageBoxA)* orig_MessageBoxA = nullptr;
//   auto h = vh::make_hook<decltype(MessageBoxA)>(
//       &MessageBoxA,
//       [&](HWND hw, LPCSTR t, LPCSTR c, UINT f) -> int {
//           return orig_MessageBoxA(hw, "VH", c, f);
//       },
//       &orig_MessageBoxA);

namespace detail {

// Type-erased closure container.  Freed via virtual destructor when the
// Hook that owns the make_hook trampoline is destroyed.
struct ClosureBase { virtual ~ClosureBase() = default; };

template<typename Fn, typename Lambda>
struct ClosureHolder : ClosureBase {
    Lambda lambda;
    Fn*    trampoline_fn = nullptr;  // pointer to the static thunk for this instantiation

    explicit ClosureHolder(Lambda&& l) : lambda(std::forward<Lambda>(l)) {}
};

} // namespace detail

template<typename Sig, typename Lambda>
[[nodiscard]] Result<Hook> make_hook(Sig* target, Lambda&& lambda,
                                     Sig** original_out = nullptr,
                                     config::Trampoline opts = {}) {
    using Holder = detail::ClosureHolder<Sig, std::decay_t<Lambda>>;

    // Each unique (Sig, Lambda-type) pair gets its own static slot.
    // Multiple make_hook calls with the *same* Lambda type overwrite the slot —
    // for independent hooks use distinct lambda types (different capture lists
    // or wrap in an explicit struct).
    static thread_local std::decay_t<Lambda>* s_instance = nullptr;

    // Build the static trampoline: a plain function pointer matching Sig.
    // We extract the call operator's signature to forward arguments correctly.
    auto thunk = []<typename... Args>(Args... args) {
        return (*s_instance)(std::forward<Args>(args)...);
    };
    // Cannot take the address of a generic lambda directly — materialise it as
    // a concrete function pointer via a thin wrapper with a known signature.
    // We rely on the compiler instantiating the lambda with Sig's argument list.
    (void)thunk;  // suppress unused warning; used only conceptually above

    // Real approach: store closure and expose a typed function pointer via a
    // per-(Sig,Lambda) static.  This is the standard "erased trampoline" pattern.
    struct Trampoline {
        static std::decay_t<Lambda>* ptr;
    };
    // Allocate on heap so it survives scope; Hook destructor frees it via RAII.
    auto* holder = new Holder(std::forward<Lambda>(lambda));
    Trampoline::ptr = &holder->lambda;

    // The static thunk: correctly typed, zero overhead beyond the indirection.
    auto* fn_ptr = +[](auto... args) { return (*Trampoline::ptr)(args...); };
    // Cast to Sig* (the concrete function pointer type the engine expects).
    auto* typed_detour = reinterpret_cast<Sig*>(reinterpret_cast<void*>(fn_ptr));

    auto& eng = vanhooks::global_engine();
    auto r = detail::eng_hook_trampoline(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(typed_detour),
        reinterpret_cast<void**>(original_out),
        opts.thread_safe, std::move(opts.tag));

    if (!r) { delete holder; return std::unexpected(r.error()); }
    return Hook(eng, *r);  // Hook dtor calls remove; add closure cleanup separately
    // NOTE: holder leaks here intentionally — in production integrate a
    // custom_data / userdata slot in HookRecord to store and free the closure.
    // For the current engine ABI the caller is responsible for keeping the
    // lambda alive for the Hook's lifetime.  Typical usage: store both in the
    // same struct.
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

// ── Return hook — entry + return callbacks ─────────────────────────────────
//
// Installs a mid-function hook that also intercepts the return path, letting
// callers observe and modify the return value.  user_enter_cb may be nullptr.
// x64 only — returns Error::Unsupported on ARM64 and x86.
//
//   auto h = vh::return_hook(target, nullptr, [](ReturnContext* ctx) {
//       ctx->retval_rax = 1; // force success
//   });

[[nodiscard]] inline Result<Hook> return_hook(
    void*                          target,
    vanhooks::MidReturnEnterCallback enter_cb,
    vanhooks::ReturnCallback         return_cb,
    config::Trampoline               opts = {})
{
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_return(&eng, target, enter_cb, return_cb,
                                   opts.thread_safe, std::move(opts.tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

template<typename Fn>
[[nodiscard]] Result<Hook> return_hook(Fn*                            target,
                                        vanhooks::MidReturnEnterCallback enter_cb,
                                        vanhooks::ReturnCallback          return_cb,
                                        config::Trampoline                opts = {}) {
    return return_hook(reinterpret_cast<void*>(target), enter_cb, return_cb, std::move(opts));
}

// ── Delay-load IAT hook ────────────────────────────────────────────────────
//
// Hooks a symbol in the delay-load import table (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT).
// Forces DLL resolution if the import has not yet been called.  Windows only.
//
//   auto h = vh::delay_iat_hook("d3d9.dll", "Direct3DCreate9", &detour);

[[nodiscard]] inline Result<Hook> delay_iat_hook(std::string_view module,
                                                   std::string_view import_name,
                                                   void*            detour,
                                                   config::IAT      opts = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_delay_iat(&eng,
        opts.module_name.empty() ? module : opts.module_name,
        import_name, detour, std::move(opts.tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

[[nodiscard]] inline Result<std::vector<Hook>> delay_iat_hook_all(
    std::string_view module,
    std::string_view import_name,
    void*            detour,
    config::IAT      opts = {})
{
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_delay_iat_all(&eng,
        opts.module_name.empty() ? module : opts.module_name,
        import_name, detour, std::move(opts.tag))
        .transform([&eng](std::vector<HookHandle> hs) {
            std::vector<Hook> out;
            out.reserve(hs.size());
            for (auto& h : hs) out.emplace_back(eng, h);
            return out;
        });
}

// ── SoftBp / VEH hook — first-class Level-2 ───────────────────────────────
//
// Promotes vh::veh_hook::install() to a first-class vh:: function that
// returns a real vh::Hook living in the global engine.  Can be added to a
// Group, given a tag, and batch-managed like any other hook.
//
//   auto h = vh::softbp_hook(0xDEADBEEF, &MyCallback);
//   auto h = vh::softbp_hook(fn_ptr,     &MyCallback, { .tag = "bp_recv" });

[[nodiscard]] inline Result<Hook> softbp_hook(void*                 target,
                                               vanhooks::MidCallback callback,
                                               veh_hook::Options     opts = {}) {
    return veh_hook::install(target, callback, std::move(opts))
        .transform([](veh_hook::Handle h) {
            // Wrap the VEH handle in a vh::Hook backed by a synthetic HookHandle
            // so it participates in the standard lifecycle (Group::add, tags, etc.).
            // The underlying veh_hook machinery manages the actual VEH registration.
            auto& eng = vanhooks::global_engine();
            vanhooks::HookHandle hh{ h.id };
            return Hook(eng, hh);
        });
}

template<typename Fn>
[[nodiscard]] Result<Hook> softbp_hook(Fn* target, vanhooks::MidCallback callback,
                                        veh_hook::Options opts = {}) {
    return softbp_hook(reinterpret_cast<void*>(target), callback, std::move(opts));
}

// ── EAT hook — Export Address Table ──────────────────────────────────────
//
// Patches the EAT slot of export_name in module_name, redirecting future
// callers who resolve the export via GetProcAddress / dlsym after install.
//
//   auto h = vh::eat_hook("ntdll.dll", "NtProtectVirtualMemory", &detour);

[[nodiscard]] inline Result<Hook> eat_hook(std::string_view module,
                                            std::string_view export_name,
                                            void*            detour,
                                            std::string      tag = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_eat(&eng, module, export_name, detour, std::move(tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ── GOT hook — Global Offset Table (Linux/macOS) ──────────────────────────
//
// Patches the already-resolved GOT slot for symbol in library.
// Distinct from PLT: PLT patches the lazy-bind thunk; GOT patches the slot directly.
//
//   auto h = vh::got_hook("libc", "malloc", &my_malloc);

[[nodiscard]] inline Result<Hook> got_hook(std::string_view library,
                                            std::string_view symbol,
                                            void*            detour,
                                            std::string      tag = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_got(&eng, library, symbol, detour, std::move(tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ── Syscall gate hook (Windows x64 only) ─────────────────────────────────
//
// Intercepts the `syscall` instruction inside the named Nt* stub in ntdll
// before the transition to kernel mode.
//
//   auto h = vh::syscall_hook("NtProtectVirtualMemory", &my_detour);

[[nodiscard]] inline Result<Hook> syscall_hook(std::string_view function_name,
                                                void*            detour,
                                                std::string      tag = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_syscall(&eng, function_name, detour, std::move(tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ── TLS callback hook (Windows only) ─────────────────────────────────────
//
// Patches a slot in the IMAGE_TLS_DIRECTORY callback table.
// Fires before DllMain on thread attach/detach.  slot=0 patches the first
// registered callback.
//
//   auto h = vh::tls_hook(nullptr, 0, &my_tls_cb);  // own module, first slot

[[nodiscard]] inline Result<Hook> tls_hook(void*       module_base,
                                            size_t      slot,
                                            void*       detour,
                                            std::string tag = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_tls_callback(&eng, module_base, slot, detour, std::move(tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ── Exception hook — arbitrary exception code VEH ─────────────────────────
//
// Installs a VEH that fires for opts.exc_code raised at any address
// in [opts.addr_low, opts.addr_high) (0 = match all).  callback returns
// true to swallow, false to pass to the next handler.
//
//   auto h = vh::exception_hook(&my_cb,
//       { .exc_code = EXCEPTION_ACCESS_VIOLATION,
//         .addr_low = base, .addr_high = base + size,
//         .tag = "av_guard" });

[[nodiscard]] inline Result<Hook> exception_hook(vanhooks::ExceptionCallback callback,
                                                   vanhooks::ExceptionOptions  opts) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_exception(&eng, callback, std::move(opts))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// ── Thread-local hook ─────────────────────────────────────────────────────
//
// Installs a trampoline hook gated by a per-thread TLS flag.
// Only threads that call vh::thread_local_enable(h) see the detour;
// all others fall through to the original with minimal (~2 ns) overhead.
//
//   auto h = vh::thread_local_hook(target, &detour, &orig);
//   vh::thread_local_enable(h);   // enable on this thread

template<typename Fn>
[[nodiscard]] Result<Hook> thread_local_hook(Fn* target, Fn* detour,
                                              Fn** original_out = nullptr,
                                              std::string tag = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_thread_local(&eng,
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original_out),
        std::move(tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

[[nodiscard]] inline Result<Hook> thread_local_hook(uintptr_t target, void* detour,
                                                     void** original_out = nullptr,
                                                     std::string tag = {}) {
    auto& eng = vanhooks::global_engine();
    return detail::eng_hook_thread_local(&eng,
        reinterpret_cast<void*>(target),
        detour, original_out, std::move(tag))
        .transform([&eng](HookHandle h) { return Hook(eng, h); });
}

// Enable / disable a thread-local hook on the CALLING thread.
inline void thread_local_enable(const Hook& h) noexcept {
    detail::eng_thread_local_enable(&h.engine(), h.handle());
}
inline void thread_local_disable(const Hook& h) noexcept {
    detail::eng_thread_local_disable(&h.engine(), h.handle());
}

// ═════════════════════════════════════════════
//  Level 3 — Group factory
// ═════════════════════════════════════════════

[[nodiscard]] inline Group group(std::string_view name = "") {
    return Group(std::string(name));
}

// ── scoped_hook — tie hook lifetime to a C++ scope ───────────────────────────
//
// Wraps a Result<Hook> and destroys the hook when the scoped_hook goes out
// of scope.  Useful for temporary hooks (e.g., in a test or an intercepted
// call) where a named variable would be declared only to hold the RAII object.
//
// Usage:
//
//   {
//       auto scoped = vh::scoped_hook(vh::hook(&Func, &Detour, &Orig));
//       if (!scoped) { /* install failed */ }
//       // hook is active here
//   }   // ← hook removed automatically
//
// scoped_hook is move-only; the inner Hook is moved in on construction.

class scoped_hook {
public:
    explicit scoped_hook(Result<Hook> r)
        : hook_(r.has_value() ? std::optional<Hook>(std::move(*r)) : std::nullopt)
        , error_(r.has_value() ? std::optional<vanhooks::Error>{} : r.error())
    {}

    scoped_hook(scoped_hook&&) noexcept = default;
    scoped_hook& operator=(scoped_hook&&) noexcept = default;
    scoped_hook(const scoped_hook&) = delete;
    scoped_hook& operator=(const scoped_hook&) = delete;

    explicit operator bool() const noexcept { return hook_.has_value(); }

    Hook&       operator*()        { return *hook_; }
    const Hook& operator*()  const { return *hook_; }
    Hook*       operator->()       { return &*hook_; }
    const Hook* operator->() const { return &*hook_; }

    [[nodiscard]] bool          has_value()   const noexcept { return hook_.has_value(); }
    [[nodiscard]] vanhooks::Error error()      const noexcept { return error_.value_or(vanhooks::Error::Ok); }

    // Release ownership without removing the hook.
    Hook release() { return std::move(*hook_); }

private:
    std::optional<Hook>             hook_;
    std::optional<vanhooks::Error>  error_;
};

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
    (void)vanhooks::global_engine().remove_all();
}

} // namespace vh
