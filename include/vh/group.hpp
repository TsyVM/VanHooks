#pragma once

/**
 * vh/group.hpp
 * vh::Group  — RAII container owning Hook objects with batch lifecycle management.
 * vh::HookRegistry — Process-wide singleton for named group lookup across modules.
 */

#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>
#include <mutex>
#include <unordered_map>

#include <vanhooks/vanhooks.hpp>
#include <vanhooks/memory.hpp>
#include <vanhooks/scanner.hpp>
#include "result.hpp"
#include "hook.hpp"
#include "config.hpp"

namespace vh {

// Bridge declarations (implemented in vh_bridge.cpp, compiled into the library).
namespace detail {
    void   engine_queue_enable (vanhooks::Engine*, vanhooks::HookHandle) ;
    void   engine_queue_disable(vanhooks::Engine*, vanhooks::HookHandle);
    void   engine_queue_remove (vanhooks::Engine*, vanhooks::HookHandle);
    Status engine_apply_queued (vanhooks::Engine*);
} // namespace detail

// ─────────────────────────────────────────────
//  Group
// ─────────────────────────────────────────────

class Group {
public:
    explicit Group(std::string name = {}) : name_(std::move(name)) {}

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
        auto* e = &vanhooks::global_engine();
        auto r = detail::eng_hook_trampoline(
            e,
            reinterpret_cast<void*>(target),
            reinterpret_cast<void*>(detour),
            reinterpret_cast<void**>(original),
            opts.thread_safe, std::move(opts.tag));
        if (r) hooks_.push_back(Hook(*e, *r));
        return *this;
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

    // nop() fills [addr, addr+count) with 0x90 (x86 NOP) bytes.
    //
    //   group.nop(0x14E738B, 2);

    Group& nop(uintptr_t addr, size_t count)
    {
        std::vector<uint8_t> nops(count, 0x90);
        vanhooks::memory::write_bytes(
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

    // ── Batch lifecycle ───────────────────────────────────────────────────────

    Group& enable() {
        if (hooks_.empty()) return *this;
        auto* e = engine_ptr();
        for (auto& h : hooks_) if (h.valid()) detail::engine_queue_enable(e, h.handle());
        detail::engine_apply_queued(e);
        return *this;
    }

    Group& disable() {
        if (hooks_.empty()) return *this;
        auto* e = engine_ptr();
        for (auto& h : hooks_) if (h.valid()) detail::engine_queue_disable(e, h.handle());
        detail::engine_apply_queued(e);
        return *this;
    }

    void remove_all() {
        if (hooks_.empty()) return;
        auto* e = engine_ptr();
        for (auto& h : hooks_) if (h.valid()) detail::engine_queue_remove(e, h.handle());
        detail::engine_apply_queued(e);
        hooks_.clear();
    }

    void clear() { remove_all(); }

    // ── Queued batch ──────────────────────────────────────────────────────────

    Group& queue_enable() {
        auto* e = engine_ptr();
        for (auto& h : hooks_) if (h.valid()) detail::engine_queue_enable(e, h.handle());
        return *this;
    }

    Group& queue_disable() {
        auto* e = engine_ptr();
        for (auto& h : hooks_) if (h.valid()) detail::engine_queue_disable(e, h.handle());
        return *this;
    }

    Status apply() {
        if (hooks_.empty()) return {};
        return detail::engine_apply_queued(engine_ptr());
    }

    // ── Introspection ─────────────────────────────────────────────────────────

    size_t      size()  const noexcept { return hooks_.size(); }
    bool        empty() const noexcept { return hooks_.empty(); }
    std::string name()  const          { return name_; }

    Hook& operator[](size_t i)          { return hooks_.at(i); }
    const Hook& operator[](size_t i) const { return hooks_.at(i); }

    Hook& at(std::string_view tag) {
        for (auto& h : hooks_)
            if (h.tag() == tag) return h;
        throw std::out_of_range(std::string("vh::Group::at: tag not found: ") + std::string(tag));
    }

    // ── Iterator support ──────────────────────────────────────────────────────

    auto begin()        { return hooks_.begin(); }
    auto end()          { return hooks_.end(); }
    auto begin()  const { return hooks_.begin(); }
    auto end()    const { return hooks_.end(); }

private:
    std::string       name_;
    std::vector<Hook> hooks_;

    vanhooks::Engine* engine_ptr() {
        for (auto& h : hooks_)
            if (h.valid()) return &h.engine();
        return &vanhooks::global_engine();
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
        std::lock_guard lock(mutex_);
        std::string key = group.name();
        groups_.emplace(std::move(key), std::move(group));
    }

    Group* find_group(std::string_view name) {
        std::lock_guard lock(mutex_);
        auto it = groups_.find(std::string(name));
        return it != groups_.end() ? &it->second : nullptr;
    }

    void enable_all()  { std::lock_guard lock(mutex_); for (auto& [k,g] : groups_) g.enable();     }
    void disable_all() { std::lock_guard lock(mutex_); for (auto& [k,g] : groups_) g.disable();    }
    void remove_all()  { std::lock_guard lock(mutex_); for (auto& [k,g] : groups_) g.remove_all(); groups_.clear(); }

    size_t total_hook_count() const {
        std::lock_guard lock(mutex_);
        size_t n = 0;
        for (const auto& [k,g] : groups_) n += g.size();
        return n;
    }

    ~HookRegistry() { remove_all(); }

private:
    HookRegistry() = default;
    mutable std::mutex                     mutex_;
    std::unordered_map<std::string, Group> groups_;
};

} // namespace vh
