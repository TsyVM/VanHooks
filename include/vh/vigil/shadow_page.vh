#pragma once
/**
 * VanHooks — Shadow-page .text integrity
 *
 * Maps a second SEC_IMAGE view of a module so hash-scan checks
 * read the original bytes while the executable view runs hooked code.
 * On Linux uses a clean mmap from disk for the same effect.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace vh::shadow {

struct ShadowMapping {
    void*           module_base    = nullptr;
    void*           shadow_base    = nullptr;
    size_t          text_offset    = 0;
    size_t          text_size      = 0;
    std::string_view module_name;
};

VH_API Result<ShadowMapping> create(std::string_view module_name) noexcept;
VH_API Result<ShadowMapping> create(void* module_base) noexcept;

VH_API Status destroy(ShadowMapping& mapping) noexcept;

VH_API bool verify_integrity(const ShadowMapping& mapping) noexcept;

VH_API Status redirect_reads(const ShadowMapping& mapping) noexcept;
VH_API Status restore_reads(const ShadowMapping& mapping) noexcept;

} // namespace vh::shadow
