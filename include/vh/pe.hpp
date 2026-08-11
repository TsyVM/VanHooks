#pragma once

/**
 * vh/pe.hpp — PE Module Introspection public API
 *
 * Exposes vanhooks::pe to end users under the vh::pe namespace.
 * Provides structured access to sections, exports, imports, and code caves
 * of any module currently loaded in the process — no file I/O, no extra
 * dependencies.
 *
 * Quick start:
 * ────────────
 *   #include <vh/vh.hpp>
 *
 *   // Open any loaded module by name
 *   auto view = vh::pe::open("ntdll.dll");
 *   if (!view) { ... }
 *
 *   // Walk exports — find a function without GetProcAddress
 *   for (auto& e : view->exports().value_or({}))
 *       if (e.name == "NtQuerySystemInformation")
 *           printf("found @ 0x%llx\n", (ull)e.address);
 *
 *   // Read the IAT slot for a specific import
 *   auto imp = view->find_import("kernel32.dll", "VirtualProtect");
 *   if (imp) {
 *       auto* slot = reinterpret_cast<void**>(imp->iat_address);
 *       printf("IAT slot → %p\n", *slot);
 *   }
 *
 *   // Locate code caves large enough for a short stub
 *   for (auto& cave : view->find_caves(32))
 *       printf("[%s] 0x%llx  %zu bytes\n",
 *              cave.section_name, (ull)cave.address, cave.size);
 *
 *   // List all loaded modules
 *   for (auto& m : vh::pe::modules().value_or({}))
 *       printf("%s  base=0x%llx  size=0x%zx\n",
 *              m.name().data(), (ull)m.base(), m.image_size());
 *
 * Error handling:
 *   All factory/query functions return vh::Result<T>.
 *   find_caves() never fails — it returns an empty vector on error.
 *
 * Platform:
 *   Full support on Windows (PE32 / PE32+, x86 / x64).
 *   Error::Unsupported on Linux and macOS.
 */

#include <vanhooks/pe.hpp>
#include "result.hpp"

namespace vh::pe {

// ── Re-export core types ─────────────────────────────────────────────────────

using Section  = vanhooks::pe::Section;
using Export   = vanhooks::pe::Export;
using Import   = vanhooks::pe::Import;
using CodeCave = vanhooks::pe::CodeCave;
using PeView   = vanhooks::pe::PeView;

// ── Convenience factories ────────────────────────────────────────────────────

/**
 * Open a module that is already loaded in the current process by name.
 *
 * @param name  Base name or full path (e.g. "ntdll.dll", "ntdll", "C:\\Windows\\System32\\ntdll.dll").
 *              Pass an empty string to open the main executable.
 * @returns     PeView on success; Error::ModuleNotFound / Error::PeInvalidHeader on failure.
 */
[[nodiscard]]
inline Result<PeView> open(std::string_view name = {}) {
    return PeView::from_name(name);
}

/**
 * Open a PE image at a known base address.
 *
 * @param base        Load base (VA) of the image.
 * @param image_size  Optional — derived from PE headers if 0.
 * @param name        Optional display name for the view.
 */
[[nodiscard]]
inline Result<PeView> open_at(uintptr_t        base,
                               size_t           image_size = 0,
                               std::string_view name       = {}) {
    return PeView::from_base(base, image_size, name);
}

#ifdef VH_PLATFORM_WINDOWS
/**
 * Open a module by its HMODULE handle.
 */
[[nodiscard]]
inline Result<PeView> open_handle(HMODULE hmod) {
    return PeView::from_handle(hmod);
}

/**
 * Enumerate all modules currently loaded in the process.
 * Returns one PeView per loaded module, in load order.
 */
[[nodiscard]]
inline Result<std::vector<PeView>> modules() {
    return vanhooks::pe::loaded_modules();
}
#endif // VH_PLATFORM_WINDOWS

} // namespace vh::pe
