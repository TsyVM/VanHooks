#pragma once

/**
 * vh/callstack.hpp — Call Stack Capture (public API)
 *
 * Re-exports vanhooks::callstack under vh::callstack, matching the
 * style of vh/pe.hpp and vh/symbols.hpp.
 *
 * Quick start — raw addresses:
 * ────────────────────────────
 *   #include <vh/vh.hpp>   // or just <vh/callstack.hpp>
 *
 *   auto frames = vh::callstack::capture();
 *   if (frames) {
 *       for (auto addr : *frames)
 *           printf("  0x%016llx\n", (unsigned long long)addr);
 *   }
 *
 * Quick start — annotated (requires VH_SYMBOLS_ENABLED):
 * ───────────────────────────────────────────────────────
 *   auto frames = vh::callstack::capture_annotated();
 *   if (frames)
 *       printf("%s", vh::callstack::format(*frames).c_str());
 *
 * Inside a hook detour — skip VanHooks frames:
 *   auto frames = vh::callstack::capture(/* skip= *\/ 2, /* max_depth= *\/ 32);
 *
 * Platform:
 *   Windows: RtlCaptureStackBackTrace (kernel32 — always linked, no extra dep)
 *   Linux / macOS: backtrace() (libc — always linked, no extra dep)
 */

#include <vanhooks/callstack.hpp>
#include "result.hpp"

namespace vh::callstack {

// ── Re-export core types ──────────────────────────────────────────────────────

using Frame = vanhooks::callstack::Frame;

static constexpr size_t kMaxDepth = vanhooks::callstack::kMaxDepth;

// ── Convenience wrappers ──────────────────────────────────────────────────────

/**
 * Capture the raw call stack of the current thread.
 * @param skip       Frames to omit from the top (1 = skip capture() itself).
 * @param max_depth  Upper bound on returned frames (capped at kMaxDepth = 64).
 */
[[nodiscard]]
inline Result<std::vector<uintptr_t>> capture(size_t skip      = 1,
                                               size_t max_depth = kMaxDepth) {
    return vanhooks::callstack::capture(skip + 1, max_depth);
}

#ifdef VH_SYMBOLS_ENABLED

/**
 * Capture and annotate the call stack using the symbols layer.
 * Frames without symbol info are still included; their name/file/line are empty.
 */
[[nodiscard]]
inline Result<std::vector<Frame>> capture_annotated(size_t skip      = 1,
                                                     size_t max_depth = kMaxDepth) {
    return vanhooks::callstack::capture_annotated(skip + 1, max_depth);
}

/**
 * Format an annotated stack trace as a multi-line human-readable string.
 *
 *   #0  0x00007ffe12345678  MyFunc  src/foo.cpp:42
 *   #1  0x00007ffe12344000  Caller  src/bar.cpp:17
 */
[[nodiscard]]
inline std::string format(const std::vector<Frame>& frames) {
    return vanhooks::callstack::format(frames);
}

#endif // VH_SYMBOLS_ENABLED

} // namespace vh::callstack
