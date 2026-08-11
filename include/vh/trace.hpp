#pragma once

/**
 * vh/trace.hpp
 * VanTrace public API — vh:: namespace surface.
 *
 * This header re-exports the vanhooks::trace:: types under simpler aliases
 * and provides the vh::Tracer convenience wrapper that works naturally with
 * vh::Hook and vh::Group, mirroring the rest of the vh:: layer.
 *
 * #include <vh/vh.hpp>  pulls this in automatically when VH_TRACE_ENABLED.
 * Include it directly only if you need tracing without the full vh:: API.
 *
 * Quick-start example:
 *
 *   // Setup (once, e.g. in DllMain / module init):
 *   static vh::Tracer tracer;
 *
 *   auto sink = std::make_shared<vanhooks::trace::CallbackSink>(
 *       [](const vh::TraceEvent& ev, const vh::TraceMeta* meta) {
 *           if (meta && ev.kind == vh::TraceEventKind::HookEnter)
 *               // log ev, meta->tag, ev.thread_id, ev.call_depth …
 *               ;
 *       });
 *   tracer.set_sink(sink);
 *   tracer.start();
 *
 *   // Hook creation:
 *   static vh::AttachedHook g_EndScene_hook;
 *
 *   auto h = vh::hook("d3d9.dll", "Direct3DCreate9", &MyDetour);
 *   g_EndScene_hook = tracer.attach(*h);
 *
 *   // Inside the detour:
 *   HRESULT __stdcall MyEndScene(IDirect3DDevice9* dev) {
 *       vh::CallScope scope(g_EndScene_hook);   // enter + exit recorded
 *       return g_orig(dev);
 *   }
 */

#include <vanhooks/trace.hpp>
#include <vh/hook.hpp>
#include <vh/result.hpp>

namespace vh {

// ─────────────────────────────────────────────
//  Type aliases — bring core types into vh::
// ─────────────────────────────────────────────

using TraceEvent       = vanhooks::trace::Event;
using TraceEventKind   = vanhooks::trace::EventKind;
using TraceMeta        = vanhooks::trace::HookMeta;
using TraceFilter      = vanhooks::trace::Filter;
using TraceConfig      = vanhooks::trace::TracerConfig;
using TraceStats       = vanhooks::trace::TracerStats;
using AttachedHook     = vanhooks::trace::AttachedHook;
using CallScope        = vanhooks::trace::CallScope;
using ISink            = vanhooks::trace::ISink;
using NullSink         = vanhooks::trace::NullSink;
using CallbackSink     = vanhooks::trace::CallbackSink;
using OverflowPolicy   = vanhooks::trace::OverflowPolicy;

// ─────────────────────────────────────────────
//  vh::Tracer
//  Thin wrapper around vanhooks::trace::Tracer that accepts vh::Hook
//  directly in attach(), so users never touch the raw Engine or HookHandle.
// ─────────────────────────────────────────────

class Tracer {
public:
    explicit Tracer(TraceConfig cfg = {})
        : inner_(std::move(cfg)) {}

    // ── Forwarded configuration ───────────────────────────────────────────────

    void set_sink(std::shared_ptr<ISink> sink) {
        inner_.set_sink(std::move(sink));
    }

    void set_filter(TraceFilter filter) {
        inner_.set_filter(std::move(filter));
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    [[nodiscard]] Status start()  { return inner_.start(); }
    void                 stop()   { inner_.stop(); }

    // ── Attach from vh::Hook ──────────────────────────────────────────────────

    // Most common form: attach a hook by its vh::Hook RAII wrapper.
    [[nodiscard]] Result<AttachedHook> attach(const vh::Hook& hook,
                                               std::string_view tag_override = {})
    {
        if (!hook.valid())
            return std::unexpected(vanhooks::Error::HookNotFound);
        return inner_.attach(hook.engine(), hook.handle(), tag_override);
    }

    // Attach directly from a raw HookHandle + Engine (power-user path).
    [[nodiscard]] Result<AttachedHook> attach(vanhooks::Engine& engine,
                                               vanhooks::HookHandle handle,
                                               std::string_view tag_override = {})
    {
        return inner_.attach(engine, handle, tag_override);
    }

    // Detach by handle.
    void detach(vanhooks::HookHandle handle) noexcept {
        inner_.detach(handle);
    }

    // Detach by vh::Hook.
    void detach(const vh::Hook& hook) noexcept {
        if (hook.valid()) inner_.detach(hook.handle());
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    TraceStats stats() const noexcept { return inner_.stats(); }

    // ── Escape hatch ──────────────────────────────────────────────────────────
    // Access the underlying Tracer if you need vanhooks::trace:: APIs directly.
    vanhooks::trace::Tracer& inner() noexcept { return inner_; }

private:
    vanhooks::trace::Tracer inner_;
};

} // namespace vh
