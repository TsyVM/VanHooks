#pragma once
/**
 * VanHooks — Thread pool injection (TP_WORK)
 *
 * Injects code by submitting a TP_WORK callback to the target
 * process's default thread pool.  The callback executes in a
 * worker thread managed by the system, avoiding CreateRemoteThread
 * which is heavily monitored by ACs.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::inject_tp {

struct TpConfig {
    uint32_t process_id     = 0;
    void*    shellcode      = nullptr;
    size_t   shellcode_size = 0;
    void*    parameter      = nullptr;
    bool     wait_complete  = false;
    uint32_t timeout_ms     = 5000;
};

VH_API Result<void*> inject(const TpConfig& cfg) noexcept;

} // namespace vh::inject_tp
