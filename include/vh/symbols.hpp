#pragma once

/**
 * vh/symbols.hpp — Symbol resolution public API
 *
 * Resolve virtual addresses to human-readable names and source locations using
 * the platform's native debug-info backend (DbgHelp on Windows, dladdr/libbacktrace
 * on Linux and macOS).
 *
 * Quick start:
 * ────────────
 *   #include <vh/symbols.hpp>
 *
 *   // Resolve any address to its symbol:
 *   if (auto sym = vh::symbols::resolve(some_address)) {
 *       printf("%s + 0x%zx  [%s]\n",
 *              sym->name.c_str(),
 *              some_address - sym->address,
 *              sym->module.c_str());
 *   }
 *
 *   // Look up a symbol by name:
 *   if (auto addr = vh::symbols::find("CreateFileW", "KernelBase")) {
 *       printf("CreateFileW is at 0x%llx\n", (unsigned long long)*addr);
 *   }
 *
 *   // Print a stack trace:
 *   void* frames[32];
 *   int   n = vh::symbols::capture_stack(frames, 32);
 *   for (auto& line : vh::symbols::format_stack({frames, frames + n}))
 *       puts(line.c_str());
 *
 * Notes:
 *   - initialize() is called automatically on first use; call it explicitly
 *     at startup if you want to control when the backend warms up.
 *   - Windows: add the _NT_SYMBOL_PATH environment variable or call
 *     load_module() before resolving addresses from a module with a PDB.
 *   - Linux/macOS: compile with -g / -rdynamic; for DWARF line info, also
 *     link libbacktrace and build with -DVH_ENABLE_SYMBOLS_BACKTRACE=ON.
 */

#include <cstdint>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include <vanhooks/symbols.hpp>
#include "result.hpp"

namespace vh::symbols {

// ─────────────────────────────────────────────
//  Re-export core types
// ─────────────────────────────────────────────

using Symbol         = vanhooks::symbols::Symbol;
using SourceLocation = vanhooks::symbols::SourceLocation;

// ─────────────────────────────────────────────
//  Primary API
// ─────────────────────────────────────────────

/**
 * Initialize the symbol resolution backend.
 * Idempotent — safe to call multiple times. Called automatically by all
 * other functions, but calling it early avoids latency on the first query.
 */
[[nodiscard]]
inline Result<void> initialize() {
    return vanhooks::symbols::SymbolManager::global().initialize();
}

/**
 * Resolve @address to its nearest symbol.
 *
 * The returned Symbol::address is the symbol's base (not @address); compute
 * the offset yourself: `address - sym.address`.
 *
 * @returns Error::SymbolNotFound if no debug info covers @address.
 */
[[nodiscard]]
inline Result<Symbol> resolve(uintptr_t address) {
    return vanhooks::symbols::SymbolManager::global().resolve(address);
}

/**
 * Resolve a function pointer to its nearest symbol.
 * Convenience overload — avoids the reinterpret_cast at the call site.
 */
template<typename Fn>
[[nodiscard]]
Result<Symbol> resolve(Fn* fn_ptr) {
    return resolve(reinterpret_cast<uintptr_t>(fn_ptr));
}

/**
 * Find the virtual address of a symbol by name.
 *
 * @param name    Symbol name (demangled or mangled; tries both on Windows).
 * @param module  Optional module name to narrow the search (e.g. "ntdll.dll").
 *                Empty string (default) searches all loaded modules.
 * @returns Address on success, Error::SymbolNotFound if not found.
 */
[[nodiscard]]
inline Result<uintptr_t> find(std::string_view name, std::string_view module = {}) {
    return vanhooks::symbols::SymbolManager::global().find(name, module);
}

/**
 * Return the source file and line that correspond to @address.
 * Requires PDB information (Windows) or DWARF debug sections (Linux/macOS).
 *
 * @returns Error::Unsupported if no line information is available.
 */
[[nodiscard]]
inline Result<SourceLocation> source_location(uintptr_t address) {
    return vanhooks::symbols::SymbolManager::global().source_location(address);
}

/**
 * Pre-load symbols for a specific module path.
 * Normally symbols are loaded lazily; call this to warm a module's symbol
 * table before entering a hot path or before spawning worker threads.
 */
[[nodiscard]]
inline Result<void> load_module(std::string_view module_path) {
    return vanhooks::symbols::SymbolManager::global().load_module(module_path);
}

// ─────────────────────────────────────────────
//  Stack capture and formatting
// ─────────────────────────────────────────────

/**
 * Capture the current call stack into @frames.
 *
 * @param frames  Output buffer.
 * @param count   Maximum number of frames to capture.
 * @param skip    Number of frames to skip from the top (0 = include this call).
 * @returns Number of frames written (≤ count).
 *
 * Windows: uses RtlCaptureStackBackTrace.
 * POSIX:   uses backtrace(3).
 */
[[nodiscard]]
int capture_stack(void** frames, int count, int skip = 1) noexcept;

/**
 * Format a list of return addresses into human-readable lines.
 *
 * Each line has the form:
 *   #N  0xADDRESS  symbol_name + 0xOFFSET  [module.dll]
 *
 * Frames that cannot be resolved fall back to their raw address.
 */
[[nodiscard]]
std::vector<std::string> format_stack(std::span<void* const> frames);

/**
 * Convenience wrapper: capture and immediately format the current stack.
 *
 * @param depth  Maximum number of frames to include (default 32).
 * @param skip   Frames to skip from the top (default 2: this fn + caller).
 */
[[nodiscard]]
inline std::vector<std::string> current_stack(int depth = 32, int skip = 2) {
    std::vector<void*> frames(static_cast<size_t>(depth));
    int n = capture_stack(frames.data(), depth, skip);
    frames.resize(static_cast<size_t>(n));
    return format_stack(frames);
}

/**
 * Demangle a C++ symbol name.
 * On MSVC: undecorate using UnDecorateSymbolName (dbghelp).
 * On GCC/Clang: demangle using __cxa_demangle (cxxabi.h).
 * Falls back to @mangled unchanged if demangling fails.
 */
[[nodiscard]]
std::string demangle(std::string_view mangled);

} // namespace vh::symbols
