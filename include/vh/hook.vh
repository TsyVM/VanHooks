#pragma once

/**
 * vh/hook.vh
 * vh::Hook — Universal RAII hook object returned by every hook creation function.
 *
 * Move-only. Destructor calls remove(). Works with the opaque Engine type —
 * all Engine method calls are routed through the internal bridge (hook_impl.vh)
 * which is compiled into the library and not shipped in the SDK.
 */

#include <string>
#include <cstddef>
#include <functional>
#include <optional>

#include <vanhooks/vanhooks.vh>
#include "result.vh"

namespace vh {

// Internal bridge — implemented in the library, not visible in the SDK headers.
// These free functions accept a raw HookHandle + Engine* and forward to the
// real Engine methods, keeping Hook independent of the complete Engine type.
namespace detail {
    Status      hook_enable  (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    Status      hook_disable (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    Status      hook_remove  (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    bool        hook_enabled (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    std::string hook_tag     (vanhooks::Engine*, vanhooks::HookHandle);
    vanhooks::HookKind hook_kind   (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    void*       hook_target  (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    void*       hook_detour  (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    void*       hook_trampoline(vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    vanhooks::Result<vanhooks::HookHandle> hook_chain(
        vanhooks::Engine*, vanhooks::HookHandle,
        void* next_detour, void** next_original_out, std::string tag);

    // Phase 21 bridges
    Status      hook_swap_detour  (vanhooks::Engine*, vanhooks::HookHandle, void* new_detour, void** old_out) noexcept;
    int32_t     hook_priority     (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    Status      hook_set_priority (vanhooks::Engine*, vanhooks::HookHandle, int32_t) noexcept;
    std::optional<vanhooks::HookStatsSnapshot> hook_stats(vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    Status      hook_enable_stats (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    Status      hook_disable_stats(vanhooks::Engine*, vanhooks::HookHandle) noexcept;
    Status      hook_reset_stats  (vanhooks::Engine*, vanhooks::HookHandle) noexcept;
} // namespace detail

class Hook {
public:
    // ── Construction (internal — users call vh::hook() etc.) ──────────────────

    Hook(vanhooks::Engine& engine, vanhooks::HookHandle handle) noexcept
        : engine_(&engine), handle_(handle) {}

    // ── Move-only ─────────────────────────────────────────────────────────────

    Hook(Hook&& other) noexcept
        : engine_(other.engine_), handle_(other.handle_)
    {
        other.handle_ = {};
    }

    Hook& operator=(Hook&& other) noexcept {
        if (this != &other) {
            do_remove();
            engine_ = other.engine_;
            handle_ = other.handle_;
            other.handle_ = {};
        }
        return *this;
    }

    Hook(const Hook&)            = delete;
    Hook& operator=(const Hook&) = delete;

    ~Hook() { do_remove(); }

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    //
    // enable() / disable() return Hook& for fluent chaining.
    // Use valid() as the pre-check; operating on an invalid handle is a no-op.
    // If you need to distinguish the error (e.g. HookAlreadyEnabled), call
    // advanced::engine().enable(handle()) directly.

    Hook& enable() noexcept {
        if (handle_.valid()) (void)detail::hook_enable(engine_, handle_);
        return *this;
    }

    Hook& disable() noexcept {
        if (handle_.valid()) (void)detail::hook_disable(engine_, handle_);
        return *this;
    }

    // enable_checked / disable_checked preserve the old Result<> contract for
    // callers that need to distinguish HookAlreadyEnabled / HookAlreadyDisabled.
    [[nodiscard]] Status enable_checked() {
        if (!handle_.valid()) return std::unexpected(vanhooks::Error::HookNotFound);
        return detail::hook_enable(engine_, handle_);
    }

    [[nodiscard]] Status disable_checked() {
        if (!handle_.valid()) return std::unexpected(vanhooks::Error::HookNotFound);
        return detail::hook_disable(engine_, handle_);
    }

    void remove() { do_remove(); }

    // ── Chaining ──────────────────────────────────────────────────────────────

    Result<Hook> chain(void* next_detour, void** next_original_out = nullptr,
                       std::string tag = {}) {
        if (!handle_.valid())
            return std::unexpected(vanhooks::Error::HookNotFound);
        return detail::hook_chain(engine_, handle_, next_detour, next_original_out,
                                  std::move(tag))
            .transform([this](vanhooks::HookHandle h) { return Hook(*engine_, h); });
    }

    template<typename Fn>
    Result<Hook> chain(Fn* next_detour, Fn** next_original_out = nullptr,
                       std::string tag = {}) {
        return chain(reinterpret_cast<void*>(next_detour),
                     reinterpret_cast<void**>(next_original_out),
                     std::move(tag));
    }

    // ── Introspection ─────────────────────────────────────────────────────────

    bool valid()              const noexcept { return handle_.valid(); }
    explicit operator bool()  const noexcept { return valid(); }

    bool        enabled()    const noexcept { return handle_.valid() && detail::hook_enabled(engine_, handle_); }
    std::string tag()        const          { return handle_.valid() ? detail::hook_tag(engine_, handle_) : std::string{}; }
    vanhooks::HookKind kind() const noexcept { return detail::hook_kind(engine_, handle_); }
    void*       target()     const noexcept { return handle_.valid() ? detail::hook_target(engine_, handle_)     : nullptr; }
    void*       detour()     const noexcept { return handle_.valid() ? detail::hook_detour(engine_, handle_)     : nullptr; }
    void*       trampoline() const noexcept { return handle_.valid() ? detail::hook_trampoline(engine_, handle_) : nullptr; }

    // ── Phase 21 — Hook Engine v2 ───────────────────────────────────────────

    [[nodiscard]]
    Status swap_detour(void* new_detour, void** old_detour_out = nullptr) {
        if (!handle_.valid()) return std::unexpected(vanhooks::Error::HookNotFound);
        return detail::hook_swap_detour(engine_, handle_, new_detour, old_detour_out);
    }

    template<typename Fn>
    [[nodiscard]]
    Status swap_detour(Fn* new_detour, Fn** old_detour_out = nullptr) {
        return swap_detour(reinterpret_cast<void*>(new_detour),
                           reinterpret_cast<void**>(old_detour_out));
    }

    [[nodiscard]]
    int32_t priority() const noexcept {
        return handle_.valid() ? detail::hook_priority(engine_, handle_) : 0;
    }

    [[nodiscard]]
    Status set_priority(int32_t p) {
        if (!handle_.valid()) return std::unexpected(vanhooks::Error::HookNotFound);
        return detail::hook_set_priority(engine_, handle_, p);
    }

    [[nodiscard]]
    std::optional<vanhooks::HookStatsSnapshot> stats() const noexcept {
        return handle_.valid() ? detail::hook_stats(engine_, handle_) : std::nullopt;
    }

    [[nodiscard]] Status enable_stats() {
        if (!handle_.valid()) return std::unexpected(vanhooks::Error::HookNotFound);
        return detail::hook_enable_stats(engine_, handle_);
    }

    [[nodiscard]] Status disable_stats() {
        if (!handle_.valid()) return std::unexpected(vanhooks::Error::HookNotFound);
        return detail::hook_disable_stats(engine_, handle_);
    }

    [[nodiscard]] Status reset_stats() {
        if (!handle_.valid()) return std::unexpected(vanhooks::Error::HookNotFound);
        return detail::hook_reset_stats(engine_, handle_);
    }

    // Escape hatches for Engine interop (power users only).
    vanhooks::HookHandle  handle() const noexcept { return handle_; }
    vanhooks::Engine&     engine() const noexcept { return *engine_; }

private:
    vanhooks::Engine*    engine_ = nullptr;
    vanhooks::HookHandle handle_ = {};

    void do_remove() noexcept {
        if (handle_.valid() && engine_) {
            (void)detail::hook_remove(engine_, handle_);
            handle_ = {};
        }
    }
};

} // namespace vh
