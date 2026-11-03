#pragma once
/**
 * VanHooks — ptrace hardening
 *
 * Prevents debugger attachment and ptrace-based inspection by:
 *   1. Self-tracing (PTRACE_TRACEME) to block external attachments
 *   2. Monitoring /proc/self/status for TracerPid changes
 *   3. Detecting breakpoint instructions (INT3 / BRK)
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::ptrace_harden {

VH_API Status init() noexcept;
VH_API Status shutdown() noexcept;

VH_API bool is_traced() noexcept;

VH_API Status self_trace() noexcept;

VH_API Status enable_monitor() noexcept;
VH_API Status disable_monitor() noexcept;

using DebugCallback = void(*)(int tracer_pid) noexcept;
VH_API Status set_callback(DebugCallback cb) noexcept;

VH_API bool scan_breakpoints(void* addr, size_t size) noexcept;

} // namespace vh::ptrace_harden
