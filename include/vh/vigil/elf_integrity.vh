#pragma once
/**
 * VanHooks — ELF .text integrity
 *
 * Maintains a CRC snapshot of a module's .text section from the
 * on-disk ELF binary.  Background thread periodically verifies
 * that the in-memory .text matches the snapshot (minus our known
 * hook patches), detecting external tampering.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>

namespace vh::elf_integrity {

struct IntegrityConfig {
    uint32_t check_interval_ms = 1000;
    bool     auto_repair       = false;
    bool     alert_on_tamper   = true;
};

using TamperCallback = void(*)(void* module_base, size_t offset, size_t size) noexcept;

VH_API Status init(const IntegrityConfig& cfg = {}) noexcept;
VH_API Status shutdown() noexcept;

VH_API Status watch_module(void* module_base) noexcept;
VH_API Status watch_module(const char* module_name) noexcept;
VH_API Status unwatch_module(void* module_base) noexcept;

VH_API Status register_known_patch(void* addr, size_t size) noexcept;
VH_API Status unregister_known_patch(void* addr) noexcept;

VH_API Status set_callback(TamperCallback cb) noexcept;

VH_API bool verify_now(void* module_base) noexcept;

VH_API uint32_t tamper_count() noexcept;

} // namespace vh::elf_integrity
