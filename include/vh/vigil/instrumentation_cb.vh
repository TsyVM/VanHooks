#pragma once
/**
 * VanHooks — Instrumentation callback detection + neutralisation
 *
 * Detects NtSetInformationProcess(ProcessInstrumentationCallback)
 * used by EAC and other ACs as a usermode telemetry vector.
 * Can clear the callback pointer or redirect it to a no-op stub.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>

namespace vh::instrumentation {

struct CallbackInfo {
    void*    callback_address = nullptr;
    bool     is_active        = false;
    uint64_t version          = 0;
};

VH_API CallbackInfo query() noexcept;

VH_API Status neutralise() noexcept;

VH_API Status redirect(void* replacement_callback) noexcept;

VH_API Status restore() noexcept;

VH_API bool is_monitored() noexcept;

} // namespace vh::instrumentation
