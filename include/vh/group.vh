#pragma once

/**
 * vh/group.vh
 * vh::Group  — RAII container owning Hook objects with batch lifecycle management.
 * vh::HookRegistry — Process-wide singleton for named group lookup across modules.
 */

#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <optional>
#include <cassert>

#include <vanhooks/vanhooks.vh>
#include <vanhooks/memory.vh>
#include <vanhooks/trampoline.vh>
#include <vanhooks/scanner.vh>
#include "result.vh"
#include "hook.vh"
#include "detail/callsite_bridge.vh"
#include "config.vh"
#include "hooks/veh_hook.vh"

namespace vh {

// Bridge declarations (implemented in vh_bridge.cpp, compiled into the library).
namespace detail {
    void   engine_queue_enable (vanhooks::Engine*, vanhooks::HookHandle) ;
    void   engine_queue_disable(vanhooks::Engine*, vanhooks::HookHandle);
    void   engine_queue_remove (vanhooks::Engine*, vanhooks::HookHandle);
    Status engine_apply_queued (vanhooks::Engine*);

    // Trampoline (needed by hook_at)
    Result<vanhooks::HookHandle> eng_hook_trampoline(vanhooks::Engine*, void* target,
                                                      void* detour, void** orig,
                                                      bool thread_safe, std::string tag);

    // eng_hook_callsite is declared in detail/callsite_bridge.vh (included above).
    // HwBp
    Result<vanhooks::HookHandle> eng_hook_hwbp(vanhooks::Engine*, void* target,
                                                vanhooks::MidCallback cb,
                                                vanhooks::HwBpOptions opts);
    // Delay-load IAT
    Result<vanhooks::HookHandle> eng_hook_delay_iat(vanhooks::Engine*,
                                                     std::string_view module,
                                                     std::string_view import_name,
                                                     void* detour, std::string tag);
    // EAT
    Result<vanhooks::HookHandle> eng_hook_eat(vanhooks::Engine*, std::string_view module,
                                               std::string_view export_name,
                                               void* detour, std::string tag);
    // GOT
    Result<vanhooks::HookHandle> eng_hook_got(vanhooks::Engine*, std::string_view library,
                                               std::string_view symbol,
                                               void* detour, std::string tag);
    // Syscall
    Result<vanhooks::HookHandle> eng_hook_syscall(vanhooks::Engine*,
                                                   std::string_view function_name,
                                                   void* detour, std::string tag);
    // TLS callback
    Result<vanhooks::HookHandle> eng_hook_tls_callback(vanhooks::Engine*, void* module_base,
                                                        size_t slot,
                                                        void* detour, std::string tag);
    // Exception
    Result<vanhooks::HookHandle> eng_hook_exception(vanhooks::Engine*,
                                                     vanhooks::ExceptionCallback cb,
                                                     vanhooks::ExceptionOptions opts);
    // Thread-local
    Result<vanhooks::HookHandle> eng_hook_thread_local(vanhooks::Engine*, void* target,
                                                        void* detour, void** orig,
                                                        std::string tag);
    void eng_thread_local_enable (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    void eng_thread_local_disable(vanhooks::Engine*, vanhooks::HookHandle) noexcept;
} // namespace detail

// ─────────────────────────────────────────────
//  Group
// ─────────────────────────────────────────────

class Group {
public:
    // Construct with an optional name and an optional engine (defaults to global).
    explicit Group(std::string name = {},
                   vanhooks::Engine* engine = nullptr)
        : name_(std::move(name))
        , engine_(engine ? engine : &vanhooks::global_engine())
    {}

    // ── Error visibility ──────────────────────────────────────────────────────
    //
    // on_error(cb) registers a callback invoked whenever a hook installation fails.
    // Returns *this for chaining.  cb is called with the Error before the failed
    // hook is silently dropped.
    //
    //   group.on_error([](vh::Error e) {
    //       log("hook failed: {}", vh::error_to_string(e));
    //   }).hook_at(addr, &det);

    using ErrorCallback = std::function<void(vanhooks::Error)>;

    Group& on_error(ErrorCallback cb) {
        error_cb_ = std::move(cb);
        return *this;
    }

    // Returns a snapshot of all errors that occurred since the last call to
    // clear_errors() (or construction).
    [[nodiscard]] const std::vector<vanhooks::Error>& errors() const noexcept {
        return errors_;
    }

    void clear_errors() { errors_.clear(); }

    Group(Group&&) noexcept = default;
    Group& operator=(Group&&) noexcept = default;
    Group(const Group&)  = delete;
    Group& operator=(const Group&) = delete;

    ~Group() { remove_all(); }

    // ── Add hooks ─────────────────────────────────────────────────────────────

    Group& add(Hook hook) {
        hooks_.push_back(std::move(hook));
        return *this;
    }

    Group& add(Result<Hook> r) {
        if (r.has_value()) hooks_.push_back(std::move(*r));
        return *this;
    }

    // ── Address-based hook installation ──────────────────────────────────────
    //
    // hook_at() installs a trampoline hook at a raw runtime address. This is the
    // primary entry point for callers working with pattern-scanned or version-table
    // addresses where writing reinterpret_cast at every call site is impractical.
    //
    // The hook is stored in this Group and removed when the Group is destroyed.
    // Failed hooks are silently dropped and do not invalidate the chain — callers
    // that need failure visibility should use add(vh::inline_hook(...)) directly.
    //
    //   group.hook_at(0x5D5DB0, &MyFunc);
    //   group.hook_at(0x5E7859, &MyDetour, &orgFunc);
    //   group.hook_at(addr, &MyFunc, nullptr, { .tag = "my_hook" });

    template<typename Fn>
    Group& hook_at(uintptr_t target, Fn* detour, Fn** original = nullptr,
                   config::Trampoline opts = {})
    {
        auto r = detail::eng_hook_trampoline(
            engine_,
            reinterpret_cast<void*>(target),
            reinterpret_cast<void*>(detour),
            reinterpret_cast<void**>(original),
            opts.thread_safe, std::move(opts.tag));
        if (r) hooks_.push_back(Hook(*engine_, *r));
        else    report_error(r.error());
        return *this;
    }

    // ── CallSite hook installation ────────────────────────────────────────────
    //
    // hook_callsite() patches the 32-bit relative displacement of a single
    // CALL (E8) or JMP (E9) instruction at site_addr, redirecting only that
    // one call site to detour.  The original absolute target is written to *orig.
    //
    // hook_callsite_pattern() scans for the first match of `pattern`, advances
    // by `byte_offset` bytes, and treats that address as the E8/E9 site.  If
    // the pattern is not found the call is a no-op (not an error), mirroring
    // hook_pattern() behaviour.
    //
    //   group.hook_callsite(0x12AB34, &MyDetour, &g_orig);
    //   group.hook_callsite_pattern("E8 ? ? ? ? 83 C4 04", 0, &MyDetour, &g_orig);

    template<typename Detour>
    Group& hook_callsite(uintptr_t site_addr, Detour* detour, auto* orig,
                         vanhooks::CallSiteOptions opts = {})
    {
        auto r = detail::eng_hook_callsite(
            engine_, site_addr,
            reinterpret_cast<void*>(detour),
            reinterpret_cast<void**>(orig),
            opts.thread_safe, std::move(opts.tag));
        if (r) hooks_.push_back(Hook(*engine_, *r));
        else    report_error(r.error());
        return *this;
    }

    template<typename Detour>
    Group& hook_callsite_pattern(std::string_view pattern, ptrdiff_t byte_offset,
                                  Detour* detour, auto* orig,
                                  vanhooks::CallSiteOptions opts = {})
    {
        auto results = vanhooks::scanner::scan_process(pattern);
        if (results && !results->empty())
            hook_callsite((*results)[0] + static_cast<uintptr_t>(byte_offset),
                          detour, orig, std::move(opts));
        return *this;
    }

    // match_index overload — hook the Nth match instead of the first.
    // If results has fewer than match_index+1 entries the call is a no-op.
    template<typename Detour>
    Group& hook_callsite_pattern(std::string_view pattern,
                                  ptrdiff_t byte_offset,
                                  size_t match_index,
                                  Detour* detour, auto* orig,
                                  vanhooks::CallSiteOptions opts = {})
    {
        auto results = vanhooks::scanner::scan_process(pattern);
        if (results && results->size() > match_index)
            hook_callsite((*results)[match_index] + static_cast<uintptr_t>(byte_offset),
                          detour, orig, std::move(opts));
        return *this;
    }

    // ── Hardware Breakpoint hooks ─────────────────────────────────────────────
    //
    // hook_hwbp() installs a HookKind::HwBp hook at the given address.  No bytes
    // are written to the target function; the hook fires via DR0-DR3 + VEH.
    // Windows x64 only — silently a no-op on other platforms (same behaviour as
    // hook_at / hook_callsite when the install returns an error).
    //
    //   group.hook_hwbp(0xDEADBEEF, &MyMidCallback);
    //   group.hook_hwbp(fn_ptr,     &MyMidCallback, { .dr_slot = 1 });

    Group& hook_hwbp(uintptr_t target,
                     vanhooks::MidCallback          callback,
                     vanhooks::HwBpOptions          opts = {})
    {
        auto r = detail::eng_hook_hwbp(
            engine_,
            reinterpret_cast<void*>(target),
            callback,
            std::move(opts));
        if (r) hooks_.push_back(Hook(*engine_, *r));
        else    report_error(r.error());
        return *this;
    }

    template<typename Fn>
    Group& hook_hwbp(Fn*                            target,
                     vanhooks::MidCallback          callback,
                     vanhooks::HwBpOptions          opts = {})
    {
        return hook_hwbp(reinterpret_cast<uintptr_t>(target), callback, std::move(opts));
    }

    // ── Delay-load IAT hook ───────────────────────────────────────────────────
    //
    //   group.hook_delay_iat("d3d9.dll", "Direct3DCreate9", &detour);

    Group& hook_delay_iat(std::string_view module, std::string_view import_name,
                           void* detour, std::string tag = {})
    {
        auto r = detail::eng_hook_delay_iat(engine_, module, import_name,
                                             detour, std::move(tag));
        if (r) hooks_.push_back(Hook(*engine_, *r));
        else    report_error(r.error());
        return *this;
    }

    // ── EAT hook ──────────────────────────────────────────────────────────────
    //
    //   group.hook_eat("ntdll.dll", "NtProtectVirtualMemory", &detour);

    Group& hook_eat(std::string_view module, std::string_view export_name,
                    void* detour, std::string tag = {})
    {
        auto r = detail::eng_hook_eat(engine_, module, export_name, detour, std::move(tag));
        if (r) hooks_.push_back(Hook(*engine_, *r));
        else    report_error(r.error());
        return *this;
    }

    // ── GOT hook (Linux/macOS) ────────────────────────────────────────────────

    Group& hook_got(std::string_view library, std::string_view symbol,
                    void* detour, std::string tag = {})
    {
        auto r = detail::eng_hook_got(engine_, library, symbol, detour, std::move(tag));
        if (r) hooks_.push_back(Hook(*engine_, *r));
        else    report_error(r.error());
        return *this;
    }

    // ── Syscall gate hook (Windows x64) ──────────────────────────────────────

    Group& hook_syscall(std::string_view function_name, void* detour, std::string tag = {})
    {
        auto r = detail::eng_hook_syscall(engine_, function_name, detour, std::move(tag));
        if (r) hooks_.push_back(Hook(*engine_, *r));
        else    report_error(r.error());
        return *this;
    }

    // ── TLS callback hook (Windows) ───────────────────────────────────────────

    Group& hook_tls(void* module_base, size_t slot, void* detour, std::string tag = {})
    {
        auto r = detail::eng_hook_tls_callback(engine_, module_base, slot,
                                                detour, std::move(tag));
        if (r) hooks_.push_back(Hook(*engine_, *r));
        else    report_error(r.error());
        return *this;
    }

    // ── Exception hook ────────────────────────────────────────────────────────

    Group& hook_exception(vanhooks::ExceptionCallback cb, vanhooks::ExceptionOptions opts)
    {
        auto r = detail::eng_hook_exception(engine_, cb, std::move(opts));
        if (r) hooks_.push_back(Hook(*engine_, *r));
        else    report_error(r.error());
        return *this;
    }

    // ── SoftBp (VEH) hook ─────────────────────────────────────────────────────

    Group& hook_softbp(uintptr_t target, vanhooks::MidCallback callback,
                        veh_hook::Options opts = {})
    {
        auto vr = veh_hook::install(reinterpret_cast<void*>(target), callback,
                                    std::move(opts));
        if (vr) hooks_.push_back(Hook(*engine_, vanhooks::HookHandle{ vr->id }));
        else    report_error(vr.error());
        return *this;
    }

    template<typename Fn>
    Group& hook_softbp(Fn* target, vanhooks::MidCallback callback,
                        veh_hook::Options opts = {})
    {
        return hook_softbp(reinterpret_cast<uintptr_t>(target), callback, std::move(opts));
    }

    // ── Memory patch helpers ──────────────────────────────────────────────────
    //
    // patch() writes a typed value to a runtime address, temporarily lifting
    // page protection as needed. Equivalent to ModUtils' Patch<T>() or a
    // manually scoped VirtualProtect/mprotect pair.
    //
    // Returns *this for call chaining. Errors from write_bytes are silently
    // discarded to keep the fluent interface unconditional; callers that need
    // failure visibility should call vanhooks::memory::write_bytes() directly.
    //
    //   group.patch<uint8_t>(0x581E72, 32);
    //   group.patch<float>(0x5D88D1 + 6, 0.25f);
    //   group.patch<const char*>(0x581EA8, myString);

    template<typename T>
    Group& patch(uintptr_t addr, const T& value)
    {
        vanhooks::memory::write_bytes(
            reinterpret_cast<void*>(addr),
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(&value), sizeof(T)));
        return *this;
    }

    // nop() fills [addr, addr+count) with Intel-recommended multi-byte NOP
    // sequences, matching the padding strategy used by the trampoline builder.
    // Single-byte 0x90 sleds are a detectable fingerprint; multi-byte NOPs are not.
    //
    //   group.nop(0x14E738B, 2);

    Group& nop(uintptr_t addr, size_t count)
    {
        std::vector<uint8_t> nops;
        nops.reserve(count);
#if defined(VH_ARCH_ARM64)
        // ARM64 NOP is 0xD503201F (4 bytes).  Fill aligned slots; truncated
        // tail is padded with the standard 1-byte hint NOP (0xD503201F >> 24 == 0xD5).
        const uint32_t arm_nop = 0xD503201Fu;
        for (size_t i = 0; i + 4 <= count; i += 4) {
            const auto* b = reinterpret_cast<const uint8_t*>(&arm_nop);
            nops.insert(nops.end(), b, b + 4);
        }
        // Fill remaining bytes with the first byte of the NOP encoding.
        while (nops.size() < count) nops.push_back(0xD5u);
#else
        vanhooks::trampoline::emit_x64_nops(nops, count);
#endif
        (void)vanhooks::memory::write_bytes(
            reinterpret_cast<void*>(addr),
            std::span<const uint8_t>(nops));
        return *this;
    }

    // ── Pattern-scan hook ─────────────────────────────────────────────────────
    //
    // hook_pattern() scans the process for an IDA-style byte pattern, applies
    // an optional byte offset to reach the exact instruction to hook, then
    // installs a trampoline hook — all in one call.
    //
    // Only the first match is hooked. If the pattern is not found the call is a
    // no-op; use vanhooks::scanner::scan_process() directly when you need to
    // distinguish not-found from other errors.
    //
    //   group.hook_pattern("E8 ? ? ? ? 83 C4 04", -5, &MyFunc);
    //   group.hook_pattern("48 8B 05 ? ? ? ?", 0, &MyDetour, &orgFunc);

    template<typename Fn>
    Group& hook_pattern(std::string_view pattern, ptrdiff_t offset,
                        Fn* detour, Fn** original = nullptr,
                        config::Trampoline opts = {})
    {
        auto results = vanhooks::scanner::scan_process(pattern);
        if (results && !results->empty())
            hook_at((*results)[0] + static_cast<uintptr_t>(offset),
                    detour, original, std::move(opts));
        return *this;
    }

    // match_index overload — hook the Nth match instead of the first.
    // If results has fewer than match_index+1 entries the call is a no-op.
    template<typename Fn>
    Group& hook_pattern(std::string_view pattern, ptrdiff_t offset,
                        size_t match_index,
                        Fn* detour, Fn** original = nullptr,
                        config::Trampoline opts = {})
    {
        auto results = vanhooks::scanner::scan_process(pattern);
        if (results && results->size() > match_index)
            hook_at((*results)[match_index] + static_cast<uintptr_t>(offset),
                    detour, original, std::move(opts));
        return *this;
    }

    // ── Batch lifecycle ───────────────────────────────────────────────────────

    Group& enable() {
        if (hooks_.empty()) return *this;
        for (auto& h : hooks_) if (h.valid()) detail::engine_queue_enable(engine_, h.handle());
        (void)detail::engine_apply_queued(engine_);
        return *this;
    }

    Group& disable() {
        if (hooks_.empty()) return *this;
        for (auto& h : hooks_) if (h.valid()) detail::engine_queue_disable(engine_, h.handle());
        (void)detail::engine_apply_queued(engine_);
        return *this;
    }

    void remove_all() {
        if (hooks_.empty()) return;
        for (auto it = hooks_.rbegin(); it != hooks_.rend(); ++it) {
            if (it->valid()) detail::engine_queue_remove(engine_, it->handle());
        }
        (void)detail::engine_apply_queued(engine_);
        hooks_.clear();
    }

    void clear() { remove_all(); }

    // ── Queued batch ──────────────────────────────────────────────────────────

    Group& queue_enable() {
        for (auto& h : hooks_) if (h.valid()) detail::engine_queue_enable(engine_, h.handle());
        return *this;
    }

    Group& queue_disable() {
        for (auto& h : hooks_) if (h.valid()) detail::engine_queue_disable(engine_, h.handle());
        return *this;
    }

    Status apply() {
        if (hooks_.empty()) return {};
        return detail::engine_apply_queued(engine_);
    }

    // ── Introspection ─────────────────────────────────────────────────────────

    size_t      size()  const noexcept { return hooks_.size(); }
    bool        empty() const noexcept { return hooks_.empty(); }
    std::string name()  const          { return name_; }

    Hook& operator[](size_t i)          { return hooks_.at(i); }
    const Hook& operator[](size_t i) const { return hooks_.at(i); }

    Result<std::reference_wrapper<Hook>> at(std::string_view tag) {
        for (auto& h : hooks_)
            if (h.tag() == tag) return std::ref(h);
        return std::unexpected(vanhooks::Error::HookNotFound);
    }

    Result<std::reference_wrapper<const Hook>> at(std::string_view tag) const {
        for (const auto& h : hooks_)
            if (h.tag() == tag) return std::cref(h);
        return std::unexpected(vanhooks::Error::HookNotFound);
    }

    // ── Iterator support ──────────────────────────────────────────────────────

    auto begin()        { return hooks_.begin(); }
    auto end()          { return hooks_.end(); }
    auto begin()  const { return hooks_.begin(); }
    auto end()    const { return hooks_.end(); }

private:
    std::string              name_;
    std::vector<Hook>        hooks_;
    vanhooks::Engine*        engine_;
    ErrorCallback            error_cb_;
    std::vector<vanhooks::Error> errors_;

    void report_error(vanhooks::Error e) {
        errors_.push_back(e);
        if (error_cb_) error_cb_(e);
    }
};

// ─────────────────────────────────────────────
//  HookRegistry
// ─────────────────────────────────────────────

class HookRegistry {
public:
    static HookRegistry& global() {
        static HookRegistry instance;
        return instance;
    }

    void register_group(Group group) {
        std::unique_lock lock(mutex_);
        std::string key = group.name();
        groups_.emplace(std::move(key), std::move(group));
    }

    // Raw pointer overload kept for internal / legacy use.
    Group* find_group(std::string_view name) {
        std::shared_lock lock(mutex_);
        auto it = groups_.find(name);
        return it != groups_.end() ? &it->second : nullptr;
    }

    // Safer optional-reference overload for external use.
    [[nodiscard]]
    std::optional<std::reference_wrapper<Group>> get(std::string_view name) {
        std::shared_lock lock(mutex_);
        auto it = groups_.find(name);
        if (it == groups_.end()) return std::nullopt;
        return std::ref(it->second);
    }

    [[nodiscard]]
    std::optional<std::reference_wrapper<const Group>> get(std::string_view name) const {
        std::shared_lock lock(mutex_);
        auto it = groups_.find(name);
        if (it == groups_.end()) return std::nullopt;
        return std::cref(it->second);
    }

    // operator[] — same as get() but asserts on miss (debug builds only).
    Group& operator[](std::string_view name) {
        auto opt = get(name);
        assert(opt.has_value() && "HookRegistry::operator[]: group not found");
        return opt->get();
    }

    // Thread suspension (inside enable/disable/remove_all) must not happen
    // while we hold the registry mutex — hence the copy-under-lock pattern.
    void enable_all() {
        std::vector<Group*> ptrs;
        {
            std::shared_lock lock(mutex_);
            ptrs.reserve(groups_.size());
            for (auto& [k,g] : groups_) ptrs.push_back(&g);
        }
        for (auto* g : ptrs) g->enable();
    }
    void disable_all() {
        std::vector<Group*> ptrs;
        {
            std::shared_lock lock(mutex_);
            ptrs.reserve(groups_.size());
            for (auto& [k,g] : groups_) ptrs.push_back(&g);
        }
        for (auto* g : ptrs) g->disable();
    }
    void remove_all() {
        // Move the map out under an exclusive lock so groups are destroyed outside it.
        // ~Group() calls remove_all() → engine_apply_queued() → thread suspension;
        // that must not happen while holding the registry mutex.
        std::unordered_map<std::string, Group, StringHash, std::equal_to<>> local;
        {
            std::unique_lock lock(mutex_);
            local = std::move(groups_);
        }
        // local goes out of scope here — each ~Group() fires exactly once,
        // with no registry lock held and no double-destroy.
    }

    size_t total_hook_count() const {
        std::shared_lock lock(mutex_);
        size_t n = 0;
        for (const auto& [k,g] : groups_) n += g.size();
        return n;
    }

    ~HookRegistry() { remove_all(); }

private:
    HookRegistry() = default;

    // Transparent hasher: allows find(string_view) without allocating a std::string.
    struct StringHash {
        using is_transparent = void;
        size_t operator()(std::string_view sv) const noexcept { return std::hash<std::string_view>{}(sv); }
        size_t operator()(const std::string& s)  const noexcept { return std::hash<std::string>{}(s); }
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, Group, StringHash, std::equal_to<>> groups_;
};

} // namespace vh
