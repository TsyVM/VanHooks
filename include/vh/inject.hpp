#pragma once

/**
 * vh/inject.hpp — Process Injection public API
 *
 * Inject DLLs into remote processes using four methods. All functions
 * return a move-only Injection RAII object that ejects automatically on
 * scope exit.
 *
 * Quick start — LoadLibrary (simplest):
 * ─────────────────────────────────────
 *   auto inj = vh::inject(pid, "C:\\payloads\\research.dll");
 *   if (!inj) {
 *       fprintf(stderr, "inject failed: %d\n", (int)inj.error());
 *       return;
 *   }
 *   // DLL is running in pid; ejects when inj goes out of scope
 *
 * Manual-map from memory (no module-list entry):
 * ───────────────────────────────────────────────
 *   std::vector<uint8_t> pe = load_from_resource();
 *   auto inj = vh::inject_from_memory(pid, pe,
 *       { .method = vh::InjectMethod::ManualMap, .tag = "research" });
 *
 * Thread-hijack (no remote thread spawned):
 * ──────────────────────────────────────────
 *   auto inj = vh::inject(pid, dll_path,
 *       { .method = vh::InjectMethod::ThreadHijack });
 *
 * APC queue (fires on next alertable wait):
 * ──────────────────────────────────────────
 *   auto inj = vh::inject(pid, dll_path,
 *       { .method = vh::InjectMethod::ApcQueue });
 *
 * Explicit early eject:
 * ─────────────────────
 *   auto result = inj.eject();
 *   // or move out of scope naturally
 *
 * Method trade-offs:
 *   LoadLibrary  — trivially detected by module list scan / LoadLibrary hook;
 *                  simplest, most compatible.
 *   ManualMap    — no module-list entry; PE header withheld from remote
 *                  allocation; suitable for research into targets that check
 *                  the PEB loader list.
 *   ThreadHijack — no CreateRemoteThread syscall; harder to detect via
 *                  thread-creation callbacks; disturbs the hijacked thread
 *                  briefly; fails if no alertable thread exists.
 *   ApcQueue     — no new thread; stealthy but timing is non-deterministic
 *                  (fires only when a thread calls an alertable wait).
 *
 * Windows-only. All functions return Error::Unsupported on other platforms.
 */

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <vanhooks/vanhooks.hpp>
#include <vanhooks/inject.hpp>
#include "result.hpp"
#include "config.hpp"

namespace vh {

// ─────────────────────────────────────────────
//  InjectMethod
// ─────────────────────────────────────────────

enum class InjectMethod : uint8_t {
    LoadLibrary,   ///< CreateRemoteThread + LoadLibraryA — simple, detected
    ManualMap,     ///< Manual PE mapping — no module-list entry by default
    ThreadHijack,  ///< Context-redirect an existing thread — no remote thread
    ApcQueue,      ///< Queue APC to alertable threads — timing non-deterministic
};

} // namespace vh

namespace vh::config {

// ─────────────────────────────────────────────
//  Extends the config:: namespace established
//  by config.hpp with injection options.
// ─────────────────────────────────────────────

struct Inject {
    InjectMethod method = InjectMethod::LoadLibrary;
    std::string  tag;
};

} // namespace vh::config

namespace vh {

// ─────────────────────────────────────────────
//  Internal bridge (implemented in src/inject.cpp)
// ─────────────────────────────────────────────

namespace detail {
    [[nodiscard]] Result<vanhooks::inject::InjHandle>
    eng_inject(uint32_t pid, std::string_view dll_path,
               vanhooks::inject::Method method, std::string tag);

    [[nodiscard]] Result<vanhooks::inject::InjHandle>
    eng_inject_from_memory(uint32_t pid, std::span<const uint8_t> pe_bytes,
                           vanhooks::inject::Method method, std::string tag);

    [[nodiscard]] Result<void>
    eng_eject(vanhooks::inject::InjHandle handle);

    [[nodiscard]] std::optional<vanhooks::inject::InjRecord>
    eng_inj_find(vanhooks::inject::InjHandle handle);

    [[nodiscard]] vanhooks::inject::Method
    to_inj_method(InjectMethod m) noexcept;
} // namespace detail

// ─────────────────────────────────────────────
//  Injection — RAII handle returned by inject()
// ─────────────────────────────────────────────
//
//  Move-only. Destructor calls eject(). Follows the same ownership model
//  as vh::Hook: the object manages lifetime; explicit eject() is optional.

class Injection {
public:
    // Internal — users call vh::inject() / vh::inject_from_memory()
    explicit Injection(vanhooks::inject::InjHandle handle) noexcept
        : handle_(handle) {}

    // ── Move-only ────────────────────────────────────────────────────────────

    Injection(Injection&& other) noexcept
        : handle_(other.handle_) { other.handle_ = {}; }

    Injection& operator=(Injection&& other) noexcept {
        if (this != &other) {
            do_eject();
            handle_       = other.handle_;
            other.handle_ = {};
        }
        return *this;
    }

    Injection(const Injection&)            = delete;
    Injection& operator=(const Injection&) = delete;

    ~Injection() { do_eject(); }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /// Explicitly eject and invalidate this handle. Idempotent.
    [[nodiscard]] Result<void> eject() {
        if (!handle_.valid()) return {};
        auto r  = detail::eng_eject(handle_);
        handle_ = {};
        return r;
    }

    // ── Validity ──────────────────────────────────────────────────────────────

    [[nodiscard]] bool valid()           const noexcept { return handle_.valid(); }
    [[nodiscard]] explicit operator bool()const noexcept { return valid(); }

    // ── Introspection ─────────────────────────────────────────────────────────

    [[nodiscard]] uint32_t pid() const noexcept {
        if (!handle_.valid()) return 0;
        auto rec = detail::eng_inj_find(handle_);
        return rec ? rec->pid : 0;
    }

    [[nodiscard]] InjectMethod method() const noexcept {
        if (!handle_.valid()) return InjectMethod::LoadLibrary;
        auto rec = detail::eng_inj_find(handle_);
        if (!rec) return InjectMethod::LoadLibrary;
        return static_cast<InjectMethod>(static_cast<uint8_t>(rec->method));
    }

    [[nodiscard]] std::string tag() const {
        if (!handle_.valid()) return {};
        auto rec = detail::eng_inj_find(handle_);
        return rec ? rec->tag : std::string{};
    }

    // Escape hatch — power users only.
    [[nodiscard]] vanhooks::inject::InjHandle handle() const noexcept { return handle_; }

private:
    vanhooks::inject::InjHandle handle_{};

    void do_eject() noexcept {
        if (handle_.valid()) {
            (void)detail::eng_eject(handle_);
            handle_ = {};
        }
    }
};

// ─────────────────────────────────────────────
//  Free functions
// ─────────────────────────────────────────────

/**
 * Inject a DLL by path into process @pid.
 *
 * @param pid      Target process ID.
 * @param dll_path Fully-qualified DLL path (accessible from the target process).
 * @param opts     Method and optional tag.
 * @returns        RAII Injection on success; error code on failure.
 */
[[nodiscard]]
inline Result<Injection> inject(uint32_t pid, std::string_view dll_path,
                                 config::Inject opts = {}) {
    return detail::eng_inject(pid, dll_path,
                              detail::to_inj_method(opts.method),
                              std::move(opts.tag))
        .transform([](vanhooks::inject::InjHandle h) { return Injection(h); });
}

/**
 * Inject from an in-memory PE image.
 *
 * If @opts.method is not ManualMap, the image is written to a temp file
 * and loaded via the chosen method; the file is deleted immediately after.
 *
 * @param pid      Target process ID.
 * @param pe_bytes Raw PE bytes (must be a valid x64 DLL for ManualMap).
 * @param opts     Method and optional tag.
 */
[[nodiscard]]
inline Result<Injection> inject_from_memory(uint32_t pid,
                                             std::span<const uint8_t> pe_bytes,
                                             config::Inject opts = {}) {
    return detail::eng_inject_from_memory(pid, pe_bytes,
                                          detail::to_inj_method(opts.method),
                                          std::move(opts.tag))
        .transform([](vanhooks::inject::InjHandle h) { return Injection(h); });
}

/**
 * Explicitly eject an injection. Equivalent to calling inj.eject().
 * Provided for API symmetry with other vh:: free functions.
 */
[[nodiscard]]
inline Result<void> eject(Injection& inj) {
    return inj.eject();
}

} // namespace vh
