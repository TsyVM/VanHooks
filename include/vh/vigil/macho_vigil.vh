#pragma once
/**
 * VanHooks — Mach-O vigil modules
 *
 * Port of key vigil modules to macOS, replacing POSIX stubs with
 * real implementations backed by Mach and dyld APIs.
 * Provides dyld image enumeration, Mach-O section inspection,
 * and kext-aware module fingerprinting.
 */

#include <vh/fwd.vh>
#include <vh/result.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::macho_vigil {

struct DyldImageInfo {
    std::string   path;
    std::uint64_t load_address = 0;
    std::uint64_t slide        = 0;
    bool          is_system    = false;
};

struct MachOSectionInfo {
    std::string   segment;
    std::string   section;
    std::uint64_t address = 0;
    std::uint64_t size    = 0;
    std::uint32_t flags   = 0;
};

VH_API std::vector<DyldImageInfo> enumerate_dyld_images() noexcept;

VH_API std::vector<MachOSectionInfo> get_sections(const char* image_path) noexcept;

VH_API bool is_code_signed(const char* image_path) noexcept;

VH_API std::uint32_t get_image_flags(const char* image_path) noexcept;

VH_API bool has_restrict_segment(const char* image_path) noexcept;

VH_API std::vector<std::string> find_kext_loaded_images() noexcept;

} // namespace vh::macho_vigil
