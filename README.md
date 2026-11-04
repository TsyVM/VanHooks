<div align="center">

<img src="vh-logo.png" width="600" alt="VanHooks"/>

<p><em>Modern C++23 Cross-Platform Function Hooking &amp; Process Injection Library</em></p>

<a href="#">
<img src="https://readme-typing-svg.demolab.com/?lines=Five+hook+types.+One+unified+API.;24+injection+techniques.+Indirect+syscalls.;Trampoline+%C2%B7+IAT+%C2%B7+PLT+%C2%B7+VTable+%C2%B7+Mid.;std%3A%3Aexpected+errors.+RAII+lifetimes.;Windows+%C2%B7+Linux+%C2%B7+macOS+%C2%B7+ARM64.;Groups+batch+hooks+in+one+suspension.;No+PAGE_EXECUTE_READWRITE.+Ever.&font=Fira%20Code&center=true&width=700&height=45&color=DC2626&vCenter=true&size=20&pause=1800"/>
</a>

<br/>

[![License: MIT](https://img.shields.io/badge/License-MIT-DC2626?style=for-the-badge&labelColor=0D0D0D)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-DC2626?style=for-the-badge&labelColor=0D0D0D&logo=cplusplus&logoColor=DC2626)](https://en.cppreference.com/w/cpp/23)
[![Windows](https://img.shields.io/badge/Windows-x86%20%7C%20x64-DC2626?style=for-the-badge&labelColor=0D0D0D&logo=windows&logoColor=DC2626)](lib/)
[![Linux](https://img.shields.io/badge/Linux-x64%20%7C%20ARM64-DC2626?style=for-the-badge&labelColor=0D0D0D&logo=linux&logoColor=DC2626)](lib/)
[![macOS](https://img.shields.io/badge/macOS-x64%20%7C%20ARM64-DC2626?style=for-the-badge&labelColor=0D0D0D&logo=apple&logoColor=DC2626)](lib/)
[![TeamVanilla](https://img.shields.io/badge/Team-TeamVanilla-DC2626?style=for-the-badge&labelColor=0D0D0D)](https://www.teamvanilla.org/)

<br/>

[![Stars](https://img.shields.io/github/stars/tsyvm/vanhooks?style=for-the-badge&color=DC2626&labelColor=0D0D0D)](../../stargazers)
[![Issues](https://img.shields.io/github/issues/tsyvm/vanhooks?style=for-the-badge&color=DC2626&labelColor=0D0D0D)](../../issues)
[![Last Commit](https://img.shields.io/github/last-commit/tsyvm/vanhooks?style=for-the-badge&color=DC2626&labelColor=0D0D0D)](../../commits)
[![Downloads](https://img.shields.io/github/downloads/tsyvm/vanhooks/total?style=for-the-badge&color=DC2626&labelColor=0D0D0D)](../../releases)

<br/>

[![Hook types](https://img.shields.io/badge/Hooks-5%20types-DC2626?style=flat-square&labelColor=0D0D0D)](#-hook-types)
[![Injection](https://img.shields.io/badge/Injection-24%20techniques-DC2626?style=flat-square&labelColor=0D0D0D)](#-process-injection)
[![Syscalls](https://img.shields.io/badge/Syscalls-indirect%20mode-DC2626?style=flat-square&labelColor=0D0D0D)](#stealth-hardening)
[![Error handling](https://img.shields.io/badge/Errors-std%3A%3Aexpected-DC2626?style=flat-square&labelColor=0D0D0D)](#-error-handling)
[![RAII](https://img.shields.io/badge/Lifetime-RAII%20hooks-DC2626?style=flat-square&labelColor=0D0D0D)](#-hook-lifetime-and-raii)
[![Zero deps](https://img.shields.io/badge/Runtime-zero%20dependencies-DC2626?style=flat-square&labelColor=0D0D0D)](#%EF%B8%8F-requirements)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

VanHooks is a production-grade, cross-platform function hooking and process injection library for C++23. It provides inline trampoline hooks, import table hooks, procedure linkage table hooks, virtual function table hooks, mid-function register-context hooks, and a 24-technique injection catalogue — all through a single unified API backed by `std::expected` error handling and RAII lifetime management.

All injection paths use indirect syscalls (executing at ntdll gadget addresses) so kernel stack walks see a legitimate origin. No `PAGE_EXECUTE_READWRITE` memory is ever allocated — all code pages follow the RW → RX lifecycle.

VanHooks is distributed as **precompiled static libraries with public API headers**. Drop the headers and the matching `.lib` files into your project and link — no build system integration or source compilation required.

<div align="center">

### 📑 Contents

[Why VanHooks](#-why-vanhooks) · [Requirements](#%EF%B8%8F-requirements) · [Installation](#-installation) · [Quick Start](#-quick-start)

[Hook Types](#-hook-types) · [Hook Lifetime](#-hook-lifetime-and-raii) · [Groups](#-groups--batch-lifecycle-management) · [Hook Chaining](#-hook-chaining)

[Examples & Tutorials](#-examples--tutorials) · [Performance Pass](#-performance-pass) · [Process Injection](#-process-injection) · [Error Handling](#-error-handling) · [HookRegistry](#-multi-module-projects--hookregistry) · [Platform Support](#-platform-support)

[Stealth & Hardening](#-stealth--hardening) · [Shared Library](#-shared-library-abi) · [Package Layout](#-package-layout)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🧭 Why VanHooks

| | MinHook | EasyHook | SafetyHook | PolyHook2 | **VanHooks** |
|---|---|---|---|---|---|
| **Platforms** | Win | Win | Win / Lin | Win | **Win / Lin / macOS** |
| **ARM64** | ✗ | ✗ | ✗ | ✗ | **✓** |
| **Hook types** | Trampoline | Trampoline + IAT | Trampoline | Trampoline + IAT + VTable | **Trampoline + IAT + PLT + VTable + Mid** |
| **Process injection** | ✗ | ✗ | ✗ | ✗ | **24 techniques** |
| **Indirect syscalls** | ✗ | ✗ | ✗ | ✗ | **✓ (all injection)** |
| **Error handling** | C enum | C enum | exceptions | exceptions | **`std::expected`** |
| **C++ standard** | C89 API | .NET | C++23 | C++20 | **C++23** |
| **macOS lazy pointers** | ✗ | ✗ | ✗ | ✗ | **✓** |
| **RAII hook lifetime** | ✗ | ✗ | ✓ | ✓ | **✓** |
| **Batch group operations** | ✗ | ✗ | ✗ | ✗ | **✓** |
| **Hook chaining** | ✗ | ✓ | ✗ | ✓ | **✓** |
| **Mid-function hooks** | ✗ | ✗ | ✓ | ✗ | **✓** |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🛠️ Requirements

| | |
|---|---|
| **C++ standard** | C++23 |
| **MSVC** | 19.38+ (Visual Studio 2022 17.8+) |
| **GCC** | 13+ |
| **Clang** | 17+ |
| **CMake** | 3.25+ — optional; drop-in use needs no build system |
| **Windows target** | Windows 10 1903 / Windows Server 2019 |
| **Runtime dependencies** | None — Halo is compiled into the library |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📦 Installation

### Option A — Drop-in (precompiled, no build system required)

Copy `include/` into your project and link against the precompiled `.lib` for your target.

| Target | Configuration | Path |
|---|---|---|
| Windows x64 | Release | `lib/win-x64/Release/vanhooks.lib` |
| Windows x64 | Debug | `lib/win-x64/Debug/vanhooks.lib` |
| Windows x86 | Release | `lib/win-x86/Release/vanhooks.lib` |
| Windows x86 | Debug | `lib/win-x86/Debug/vanhooks.lib` |

All precompiled libs use a static CRT (`/MT` Release, `/MTd` Debug). No Visual C++ Redistributable is required. See [`lib/README.md`](lib/README.md) for MSVC project settings and ARM64 / Linux / macOS build-from-source instructions.

### Option B — CMake (drop-in)

```cmake
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(VH_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/win-x64")
else()
    set(VH_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/win-x86")
endif()

add_library(VanHooks::vanhooks STATIC IMPORTED)
set_target_properties(VanHooks::vanhooks PROPERTIES
    IMPORTED_LOCATION_RELEASE "${VH_LIB_DIR}/Release/vanhooks.lib"
    IMPORTED_LOCATION_DEBUG   "${VH_LIB_DIR}/Debug/vanhooks.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_link_libraries(my_target PRIVATE VanHooks::vanhooks)
```

### Option C — MSVC project (manual)

1. **Additional Include Directories** → add `include\`
2. **Additional Library Directories** → add `lib\win-x64\Release\` (adjust for arch/config)
3. **Additional Dependencies** → add `vanhooks.lib`
4. **Runtime Library** → `Multi-threaded (/MT)` for Release, `Multi-threaded Debug (/MTd)` for Debug

### Single include

```cpp
#include <vh/vh.vh>
```

Everything lives in the `vh::` namespace.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚡ Quick Start

### Intercept a function (no call-through needed)

```cpp
#include <vh/vh.vh>

int my_detour(int a, int b) {
    printf("intercepted!\n");
    return a + b;
}

auto r = vh::hook(&target_fn, &my_detour);
if (!r) {
    printf("failed: %s\n", vh::error_to_string(r.error()).data());
}
// Hook is live. r->valid() == true.
// Hook removes itself when r goes out of scope.
```

### Intercept a function and call the original

```cpp
static int (*orig_fn)(int, int) = nullptr;

int my_detour(int a, int b) {
    printf("add(%d, %d)\n", a, b);
    return orig_fn(a, b);   // call through to real function
}

auto r = vh::hook(&target_fn, &my_detour, &orig_fn);
```

### Hook a system function by name

```cpp
static decltype(&MessageBoxW) orig_mbw = nullptr;

BOOL WINAPI hk_mbw(HWND h, LPCWSTR text, LPCWSTR cap, UINT type) {
    return orig_mbw(h, L"[Intercepted]", cap, type);
}

auto r = vh::hook("user32", "MessageBoxW", &hk_mbw, &orig_mbw);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🪝 Hook Types

VanHooks provides five hook types, all returning the same `Result<Hook>` type.

### Inline (trampoline) hook

Patches the first bytes of the target function with a jump. Works on any function whose prologue is large enough — 5 bytes on x86/x64, 16 bytes on ARM64.

```cpp
auto r = vh::inline_hook(&target, &detour, &orig, { .tag = "Module.Function" });
```

### IAT hook — Windows

Patches an Import Address Table entry. Intercepts calls from a specific module without modifying the target function itself. Useful for short functions that cannot be safely inline-hooked.

```cpp
// Patch the IAT entry in a specific module
auto r = vh::iat_hook("MessageBoxW", (void*)&hk_mbw,
                      { .module_name = "my_app.exe", .tag = "IAT.MessageBoxW" });

// Patch every loaded module's IAT entry at once
auto hooks = vh::iat_hook_all("malloc", (void*)&hk_malloc);
```

### PLT hook — Linux / macOS

Patches the Procedure Linkage Table (Linux) or lazy pointer (macOS) used by the dynamic linker. The POSIX equivalent of an IAT hook.

```cpp
auto r = vh::plt_hook("libc", "malloc", (void*)&hk_malloc, { .tag = "libc.malloc" });
```

### VTable hook

Patches a single slot in a C++ virtual function table.

```cpp
// Hook IDXGISwapChain::Present (slot 8)
void** vtbl = *reinterpret_cast<void***>(swap_chain_ptr);

static HRESULT (STDMETHODCALLTYPE *orig_Present)(IDXGISwapChain*, UINT, UINT) = nullptr;

HRESULT STDMETHODCALLTYPE hk_Present(IDXGISwapChain* sc, UINT sync, UINT flags) {
    // render overlay
    return orig_Present(sc, sync, flags);
}

auto r = vh::vtable_hook(vtbl, 8,
                         (void*)&hk_Present,
                         (void**)&orig_Present,
                         { .tag = "DXGI.Present" });
```

### Mid-function hook

Installs a hook at a byte offset inside a function. Does not redirect control flow — observes and optionally modifies CPU register state at that point, then continues original execution.

```cpp
auto r = vh::mid_hook(game_update_fn,
    [](vh::MidContext* ctx) noexcept {
        player_health = static_cast<int>(ctx->rax);
    },
    { .offset = 0x1C, .tag = "Game.HealthReadback" });
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔒 Hook Lifetime and RAII

Every hook creation function returns `Result<Hook>`. The `Hook` object removes the hook automatically when it is destroyed — you do not need to call remove manually in normal use.

```cpp
{
    auto r = vh::hook(&fn, &detour);
    // hook is live here
}
// hook automatically removed when r goes out of scope
```

To control hook state explicitly:

```cpp
auto r = vh::hook(&fn, &detour);
auto& h = *r;

h.disable();    // deactivate without removing
h.enable();     // reactivate
h.remove();     // permanently remove (destructor also does this)

h.valid();      // is the hook installed?
h.enabled();    // is it currently active?
h.tag();        // the tag string set at creation
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📦 Groups — Batch Lifecycle Management

A `Group` owns multiple hooks and enables, disables, or removes them all inside a single thread-suspension window — significantly cheaper than operating on each hook individually.

```cpp
auto grp = vh::group("RenderHooks");

grp.add(vh::vtable_hook(vtbl, 8,  (void*)&hk_Present))
   .add(vh::vtable_hook(vtbl, 16, (void*)&hk_Reset))
   .add(vh::iat_hook("CreateDevice", (void*)&hk_CreateDevice));

grp.enable();   // one suspension window for all three
grp.disable();  // same

// Find a specific hook by tag
grp.at("DXGI.Present").disable();

// Iterate
for (auto& h : grp) {
    printf("%s: %s\n", h.tag().c_str(), h.enabled() ? "on" : "off");
}

// Maximum performance — queue operations, flush once
grp.queue_enable().apply();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔗 Hook Chaining

A second detour can be inserted in front of an existing hook. Execution order after chaining:

```
new_detour → original_detour → real_function
```

Chain links must be removed in reverse order of creation.

```cpp
auto base = vh::inline_hook(&fn, &detour1, &orig1).value();

static decltype(&fn) chain_orig = nullptr;
auto link = base.chain(&detour2, &chain_orig).value();

// Later, in reverse order:
link.remove();
base.remove();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚡ Hook Engine v2

### Conditional hooks

A hook that fires only when a predicate returns true — zero-overhead skip when false.

```cpp
bool should_hook(void* target, void* user_data) noexcept {
    return game_state == GameState::InMatch;
}

auto h = engine.hook_conditional(&target, &detour, &orig,
    { .condition = should_hook, .priority = 10, .stats = true, .tag = "Conditional" });
```

### Atomic detour swap

Replace a hook's detour function in-place without a remove+add gap.

```cpp
auto h = vh::inline_hook(&fn, &detourV1, &orig).value();
// Later — hot-swap to a new detour, no window of exposure:
void* old = nullptr;
h.swap_detour(&detourV2, &old);
```

### Hook statistics

Per-hook call counter, cumulative/average/max call duration, and last-call timestamp — all lock-free atomics.

```cpp
h.enable_stats();
// ... some calls happen ...
if (auto s = h.stats()) {
    printf("calls: %llu  avg: %llu ns  max: %llu ns\n",
           s->call_count, s->average_duration_ns, s->max_duration_ns);
}
```

### Type-safe hooks

Compile-time signature matching prevents silent calling-convention mismatches.

```cpp
auto h = engine.hook_typed<int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT)>(
    MessageBoxA, MyMessageBoxA, &g_origMessageBoxA);
```

### Lazy hooks, function-exit hooks, hook priority

```cpp
// Lazy — trampoline installed on first call, not at hook time
auto h = engine.hook_lazy(&target, &detour, &orig, { .tag = "JIT" });

// Exit — fires on every ret/retn in the function body
auto h = engine.hook_exit(&target, my_return_cb, { .max_scan_bytes = 8192 });

// Priority — higher fires first when multiple hooks target the same function
engine.set_priority(h, 100);
```

## 🌍 Cross-Platform Hook Parity

| Hook | Platform | API |
|---|---|---|
| **dyld interpose** | macOS | `engine.hook_dyld_interpose(detour, { .original_symbol = "malloc" })` |
| **Mach-O import** | macOS | `engine.hook_macho_import(detour, { .library_name = "libSystem", .symbol_name = "open" })` |
| **HwBp (Linux)** | Linux | `engine.hook_hwbp_linux(target, callback)` |
| **HwBp (macOS)** | macOS | `engine.hook_hwbp_macos(target, callback)` |

ARM64 veneer stubs, RISC-V, and FreeBSD API surfaces are defined and return `Error::Unsupported` / `Error::RiscVUnsupported` until platform-specific backends are added.

## 💉 Injection Engine v2

### Platform Injection Catalogue

| Platform | Techniques | API |
|---|---|---|
| **Linux** | ptrace, process_vm_writev, LD_PRELOAD, /proc/mem | `inject_ex::inject_ptrace()`, `inject_process_vm_writev()`, `inject_ld_preload()`, `inject_proc_mem()` |
| **macOS** | task_for_pid + mach_vm_write, DYLD_INSERT_LIBRARIES | `inject_ex::inject_task_for_pid()`, `inject_dyld_insert()` |
| **Android** | ptrace + linker namespace dlopen | `inject_ex::inject_android_ptrace()` |
| **Windows** | Reflective DLL v2, Manual Map v2 | `inject_ex::inject_reflective_v2()`, `inject_manual_map_v2()` |

### Injection Recommend & Shellcode Gen

```cpp
// Survey a target and get ranked techniques
auto ranked = engine.inject_recommend(pid);
for (auto& r : ranked)
    printf("%s — stealth %d, reliability %d\n",
           r.technique_name.c_str(), r.stealth_score, r.reliability_score);

// Generate null-free PIC shellcode from a code buffer
auto sc = engine.shellcode_generate(code_bytes,
    { .arch = vanhooks::ShellcodeArch::X64, .null_free = true });
```

## ⚡ Advanced Hook Techniques

| Hook | Platform | Use Case |
|---|---|---|
| **Relay** | All | Shared trampoline pool — saves one indirection per call on hot hooks |
| **Copy-on-write** | Windows, Linux | CoW page split — hook invisible to integrity scans |
| **Signal** | Linux | SIGTRAP/SIGILL handler dispatch — VEH equivalent |
| **Exception port** | macOS | Mach exception port interception — breakpoint-free |
| **JIT** | All | Hook JIT'd code with auto-repatch on recompile |

```cpp
// Relay hook — shared trampoline pool
auto h = engine.hook_relay(target, detour, &original,
    { .pool_size = 128, .tag = "hot-path" });

// JIT hook — monitors for recompilation
auto h = engine.hook_jit(jit_code, detour, &original,
    { .auto_repatch = true, .monitor_interval_ms = 50 });
```

## 🔬 Analysis Subsystem v2

| Capability | Types | API |
|---|---|---|
| **ELF parser** | `ElfSection`, `ElfSymbol`, `ElfDynEntry`, `ElfRelocation` | `elf_sections()`, `elf_symbols()`, `elf_dynamic()`, `elf_relocations()` |
| **Mach-O parser** | `MachOFatSlice`, `MachOSection`, `MachOSymbol`, `MachOLoadCommand` | `macho_fat_slices()`, `macho_sections()`, `macho_load_commands()` |
| **Control flow graph** | `BasicBlock`, `CfgEdge`, `ControlFlowGraph` | `build_cfg()` |
| **Binary diffing** | `FunctionDiff`, `BinaryDiffResult` | `binary_diff()` |
| **Pattern scanner v2** | `PatternRule`, `PatternMatch` | `pattern_scan()` |
| **String scanner** | `ExtractedString`, `StringEncoding` | `string_scan()` |
| **RTTI recovery** | `RttiClassInfo` | `rtti_scan()` |
| **Function detection** | `FunctionBoundary` | `detect_functions()` |

```cpp
// Parse an ELF binary
auto sections = engine.elf_sections(elf_bytes);
auto symbols  = engine.elf_symbols(elf_bytes);

// Build a control flow graph
auto cfg = engine.build_cfg(function_ptr, { .max_instructions = 50000 });

// Scan memory for patterns with wildcards
PatternRule rule{ .name = "sig", .pattern = {0x48, 0x89, 0x5C},
                  .mask = {0xFF, 0xFF, 0xFF} };
auto matches = engine.pattern_scan(base, size, std::span(&rule, 1));

// Recover RTTI class hierarchy
auto classes = engine.rtti_scan(GetModuleHandle(nullptr));
```

## 🌐 Network Layer v2

| Capability | API |
|---|---|
| **Packet timing** — jitter to mask hook latency | `net_set_packet_timing()` |
| **DNS fingerprint** — detect AC canary domains | `net_dns_fingerprint()` |
| **TLS fingerprint** — JA3/JA4 client-hello hashes | `net_tls_fingerprint()` |
| **Traffic replay** — pcapng replay at original timing | `net_replay()` |
| **Packet interception** — WinDivert/nfqueue inline modification | `net_intercept_add()`, `net_intercept_remove()` |
| **Cert pin detection** — HPKP, embedded, dynamic pins | `net_cert_pin_scan()` |
| **Winsock hooks** — WSASend/Recv/connect/accept/DNS | `net_winsock_hook()`, `net_winsock_unhook()` |

```cpp
// Add jitter to mask hook latency
engine.net_set_packet_timing({ .jitter_ms_min = 1.0, .jitter_ms_max = 8.0 });

// Capture TLS fingerprints
auto fps = engine.net_tls_fingerprint("eth0", 10000);
for (auto& fp : *fps)
    printf("JA3: %s  SNI: %s\n", fp.ja3_hash.c_str(), fp.server_name.c_str());

// Hook all Winsock functions for traffic inspection
engine.net_winsock_hook({ .hook_send = true, .hook_recv = true, .hook_dns = true });
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📡 VanTrace v2

| Capability | API |
|---|---|
| **Structured trace** — JSON, binary, or collapsed-stack ring buffer | `trace_init()`, `trace_shutdown()` |
| **Trace filtering** — module/address/depth filters | `trace_set_filter()` |
| **Remote viewer** — TCP or named-pipe live streaming | `trace_remote_start()`, `trace_remote_stop()` |
| **ETW provider** — emit events for Windows Performance Analyzer | `trace_etw_register()`, `trace_etw_unregister()` |
| **Flame graph** — collapsed-stack export for visualisation | `trace_flame_export()` |
| **IDA/Ghidra export** — annotation scripts from runtime data | `trace_ida_export()` |

```cpp
// Start structured JSON tracing
engine.trace_init({ .format = vanhooks::TraceFormat::Json, .include_stacks = true });

// Filter to one module
engine.trace_set_filter({ .include_modules = {"game.dll"}, .max_depth = 8 });

// Export flame graph
auto flames = engine.trace_flame_export("trace_out.txt");
for (auto& f : *flames)
    printf("%s  %llu ns\n", f.stack.c_str(), f.duration_ns);

// Export IDA annotation script
engine.trace_ida_export({
    .format = vanhooks::IdaExportFormat::IdaPython,
    .output_path = "annotate.py"
});
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🧪 Test Suite

| Capability | API |
|---|---|
| **Full test suite** — all hook kinds + hardening self-tests | `test_run()` |
| **Stress tests** — concurrent hook/unhook, chain depth, batch saturation | `test_stress()` |
| **Single test** — run one named test case | `test_run_one()` |
| **Test listing** — enumerate all available tests | `test_list()` |

```cpp
// Run all tests
auto suite = engine.test_run({ .verbosity = vanhooks::TestVerbosity::Verbose });
printf("Passed: %zu / %zu\n", suite->passed, suite->total);

// Stress test: 8 threads, 10k iterations
auto stress = engine.test_stress({ .thread_count = 8, .iterations = 10000 });

// Run a single test by name
auto one = engine.test_run_one("hook_iat", 5000);
if (one && one->result == vanhooks::TestResult::Pass)
    printf("IAT hook test passed\n");
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔥 Fuzzing Infrastructure

| Capability | API |
|---|---|
| **Fuzz session** — start/stop fuzz runs per target | `fuzz_start()`, `fuzz_stop()` |
| **8 fuzz targets** — disasm, trampoline, PE/ELF/Mach-O, injection, scanner | `FuzzTarget` enum |
| **Corpus management** — stats and minimisation | `fuzz_corpus_stats()`, `fuzz_corpus_minimise()` |
| **Sanitizer check** — ASan/TSan/UBSan/MSan/LSan runtime detection | `fuzz_sanitizer_available()` |
| **Target listing** — enumerate all fuzz targets | `fuzz_list_targets()` |

```cpp
// Start fuzzing the disassembler
engine.fuzz_start({
    .engine     = vanhooks::FuzzEngine::LibFuzzer,
    .target     = vanhooks::FuzzTarget::Disasm,
    .corpus_dir = "corpus/disasm",
    .output_dir = "crashes/disasm",
});

// Later: collect results
auto crashes = engine.fuzz_stop();
if (crashes)
    printf("Found %zu unique crashes\n", crashes->size());

// Minimise corpus
auto stats = engine.fuzz_corpus_minimise("corpus/disasm");
printf("Minimised: %zu → %zu inputs\n", stats->total_inputs, stats->minimised_count);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚙️ CI/CD Pipeline

| Capability | API |
|---|---|
| **Workflow validation** — parse and check CI YAML | `ci_validate_workflow()` |
| **Local job execution** — run any CI platform config locally | `ci_run_job()` |
| **SDK sync check** — detect header drift between source and SDK | `ci_check_sdk_sync()` |
| **Release build** — tag-triggered archive generation | `ci_release_build()` |
| **Coverage report** — line/branch/function coverage | `ci_coverage_report()` |
| **Static analysis** — clang-tidy, cppcheck, PVS-Studio | `ci_static_analysis()` |
| **Binary size tracking** — per-target, per-platform .lib/.dll sizes | `ci_binary_sizes()` |

```cpp
// Check SDK sync
auto sync = engine.ci_check_sdk_sync();
if (sync && !sync->in_sync)
    for (auto& h : sync->mismatched_headers)
        printf("  out of sync: %s\n", h.c_str());

// Run coverage report
auto cov = engine.ci_coverage_report();
if (cov)
    printf("Coverage: %.1f%% lines, %.1f%% branches\n", cov->line_pct, cov->branch_pct);

// Run static analysis
auto sa = engine.ci_static_analysis("clang-tidy");
if (sa)
    printf("Issues: %zu errors, %zu warnings\n", sa->issues_error, sa->issues_warning);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📖 API Documentation

| Capability | API |
|---|---|
| **Generate docs** — Html/Markdown/Json from header comments | `doc_generate()` |
| **Module reference** — per-module info (category, detects, functions) | `doc_module_info()`, `doc_list_modules()` |
| **Hook kind guide** — 17 kinds with platform + performance data | `doc_hook_kinds()` |
| **Injection guide** — 25 techniques with stealth rankings | `doc_injection_techniques()` |
| **Error reference** — cause, troubleshooting, recovery examples | `doc_error_reference()` |

```cpp
// Get hook kind decision guide
auto kinds = engine.doc_hook_kinds();
for (auto& k : *kinds)
    printf("%s: %s (%s)\n", k.name.c_str(), k.when_to_use.c_str(), k.performance.c_str());

// Get injection techniques sorted by stealth
auto techs = engine.doc_injection_techniques();
std::sort(techs->begin(), techs->end(),
    [](auto& a, auto& b) { return a.stealth_rank < b.stealth_rank; });

// Query a specific module
auto info = engine.doc_module_info("vh::unhook");
// info->category == "vigil", info->description == "Restore .text of system DLLs..."
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔧 SDK Improvements

| Capability | API |
|---|---|
| **Automated sync** — copy changed headers + libs to SDK | `sdk_sync()` |
| **Version check** — header/lib version match verification | `sdk_version()` |
| **Changelog** — structured per-version change entries | `sdk_changelog()` |
| **Minimal builds** — 4 profiles: Full/Minimal/Analysis/Stealth | `sdk_build_minimal()` |
| **Binding generation** — C, Python, Rust, C# wrappers | `sdk_generate_bindings()` |

```cpp
// Sync SDK headers and libs
auto report = engine.sdk_sync();
printf("Synced %zu headers, %zu libs\n", report->headers_copied, report->libs_copied);

// Check version match
auto ver = engine.sdk_version();
printf("VanHooks %s (match: %s)\n", ver->full_string.c_str(),
       ver->header_matches_lib ? "yes" : "NO");

// Generate Python bindings
BindingGenConfig cfg;
cfg.language   = BindingLang::Python;
cfg.output_dir = "bindings/python";
auto result = engine.sdk_generate_bindings(cfg);
// result->generated_files == {"vanhooks.pyi", "vanhooks_bindings.cpp"}
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📚 Examples & Tutorials

VanHooks ships a built-in example registry with 7 comprehensive examples that cover every major subsystem. Query, inspect, and build examples programmatically.

| Capability | API |
|---|---|
| List all examples | `example_list()` |
| Get example metadata | `example_get(name)` |
| Build & run an example | `example_build(config)` |

### Built-in Examples

| Name | Category | Demonstrates |
|---|---|---|
| `quickstart` | core | `hook_trampoline`, `enable`, `remove` |
| `all_hook_kinds` | core | All 17 HookKind values |
| `stealth_pipeline` | stealth | `ac_profile`, `unhook`, `peb_mask`, `telemetry`, `callstack_spoof`, `sleep_obf` |
| `analysis_workflow` | analysis | `pe_exports`, `symbols`, `pattern_scan`, `callstack_capture` |
| `network_capture` | net | `net_aware`, `net_dns_fingerprint`, `net_tls_fingerprint` |
| `cross_platform` | cross-platform | `hook_trampoline`, `hook_plt`, `hook_iat`, platform macros |
| `game_integration` | game-integration | `hook_vtable`, `unhook`, `peb_mask`, `poly::generate`, `shadow::create` |

```cpp
auto examples = engine.example_list();
for (auto& ex : examples.value())
    printf("%s — %s\n", ex.name.c_str(), ex.title.c_str());

ExampleBuildConfig cfg;
cfg.example_name = "stealth_pipeline";
cfg.run_after     = true;
auto result = engine.example_build(cfg);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚡ Performance Pass

Micro-benchmark 8 core operations, track per-module memory footprints, and manage arena allocators for trampoline stubs.

| Capability | API |
|---|---|
| Benchmark one target | `perf_benchmark(config)` |
| Benchmark all 8 targets | `perf_benchmark_all()` |
| Memory footprint | `perf_memory_footprint()` |
| Arena allocator | `perf_arena_init` / `perf_arena_stats` / `perf_arena_destroy` |

### Benchmark Targets

`HookInstall` · `HookDispatch` · `HookRemove` · `BatchInstall` · `TrampolineAlloc` · `ArenaAlloc` · `LockContention` · `CachePressure`

```cpp
BenchmarkConfig cfg;
cfg.target     = BenchmarkTarget::HookDispatch;
cfg.iterations = 100000;
auto r = engine.perf_benchmark(cfg);
printf("avg %.1f ns, p99 %.1f ns\n", r->avg_ns, r->p99_ns);

// Or benchmark everything at once
auto all = engine.perf_benchmark_all();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 💉 Process Injection

VanHooks includes a full injection subsystem with 33 techniques, all hardened with indirect syscalls. Include `<vh/inject/inject.vh>` for the core 4 methods, or `<vh/inject/inject_unified.vh>` for the full 33-technique catalogue.

### Quick Start — LoadLibrary (simplest)

```cpp
#include <vh/inject/inject.vh>

auto inj = vh::inject(pid, "C:\\payloads\\research.dll");
if (!inj) {
    fprintf(stderr, "inject failed: %d\n", (int)inj.error());
    return;
}
// DLL is running in pid; ejects when inj goes out of scope
```

### Manual-Map (no module-list entry)

```cpp
std::vector<uint8_t> pe = load_from_resource();
auto inj = vh::inject_from_memory(pid, pe,
    { .method = vh::InjectMethod::ManualMap, .tag = "research" });
```

### Thread-Hijack (no remote thread spawned)

```cpp
auto inj = vh::inject(pid, dll_path,
    { .method = vh::InjectMethod::ThreadHijack });
```

### APC Queue (fires on next alertable wait)

```cpp
auto inj = vh::inject(pid, dll_path,
    { .method = vh::InjectMethod::ApcQueue });
```

### Method Trade-offs

| Method | Module list | Remote thread | Timing | Detection |
|---|---|---|---|---|
| **LoadLibrary** | Visible | Yes | Immediate | Trivially detected |
| **ManualMap** | Hidden | Yes (shellcode) | Immediate | No loader entry |
| **ThreadHijack** | Visible | No | Immediate | No thread-creation callback |
| **ApcQueue** | Visible | No | Non-deterministic | No thread-creation callback |

### Extended Catalogue (33 techniques)

The unified API (`<vh/inject/inject_unified.vh>`) adds 29 more techniques across eight groups:

- **Process-birth:** EarlyBird APC, Herpaderping, Ghosting, Doppelgänging
- **Remote-thread modern:** NtCreateThreadEx, RtlCreateUserThread, Reflective, SetWindowsHookEx
- **APC-modern:** QueueApcEx2, Waiting-thread hijack
- **Callback-hijack:** KernelCallbackTable, Threadless callback, Module-stomp
- **Window-message:** PROP_PROPAGATE, Extra Window Memory
- **Process manipulation:** Process Hollowing, PoolParty, NtMapViewOfSection
- **Linux / macOS / Android:** Ptrace, ProcessVmWritev, LdPreload, ProcMem, TaskForPid, DyldInsert, AndroidPtrace
- **Enhanced:** ReflectiveV2 (TLS + exceptions + delay imports), ManualMapV2 (SEH + CRT + API sets)

### Stealth Hardening

Every injection path routes through `vh::inject_stealth` — a shared helper layer that replaces Win32 APIs with indirect syscalls:

| Win32 API | VanHooks replacement | NT syscall |
|---|---|---|
| `OpenProcess` | `vh_open_process` | `NtOpenProcess` |
| `VirtualAllocEx` | `vh_alloc_remote` | `NtAllocateVirtualMemory` |
| `WriteProcessMemory` | `vh_write_remote` | `NtWriteVirtualMemory` |
| `ReadProcessMemory` | `vh_read_remote` | `NtReadVirtualMemory` |
| `VirtualFreeEx` | `vh_free_remote` | `NtFreeVirtualMemory` |
| `VirtualProtectEx` | `vh_protect_remote` | `NtProtectVirtualMemory` |
| `CreateRemoteThread` | `vh_create_thread` | `NtCreateThreadEx` |
| `OpenThread` | `vh_open_thread` | `NtOpenThread` |
| `CloseHandle` | `vh_close` | `NtClose` |
| `CreateToolhelp32Snapshot` | `vh_find_thread` | `NtQuerySystemInformation` |
| — | `vh_queue_apc` | `NtQueueApcThread` |
| — | `vh_write_shellcode` | alloc RW → write → flip RX |

All syscalls execute at ntdll gadget addresses (indirect mode), so the kernel-mode callback stack shows a legitimate ntdll return address. `PAGE_EXECUTE_READWRITE` is never allocated — shellcode goes through the `vh_write_shellcode` helper which allocates RW, writes, then flips to RX.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ❌ Error Handling

VanHooks uses `std::expected<T, vh::Error>` (aliased as `vh::Result<T>`) throughout. No exceptions are thrown, no global error state, zero overhead on the success path.

```cpp
auto r = vh::hook(&fn, &detour, &orig);

if (!r) {
    printf("failed: %s\n", vh::error_to_string(r.error()).data());
    return;
}

vh::Hook h = std::move(*r);
```

Chain results with `.and_then()` and `.transform_error()`:

```cpp
auto r = vh::hook(&fn, &detour, &orig)
    .and_then([](vh::Hook h) -> vh::Result<vh::Hook> {
        h.disable();
        return h;
    });
```

See the [Functions Guide](VanHooks_Functions_Guide.md) for the full error code reference.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🏭 Multi-Module Projects — HookRegistry

`HookRegistry` is a process-wide singleton that owns named Groups. Use it when multiple DLLs in the same process register hooks independently and a single shutdown call should clean all of them up.

```cpp
// Module A (render DLL):
auto render = vh::group("Render");
render.add(vh::vtable_hook(vtbl, 8, (void*)&hk_Present));
vh::HookRegistry::global().register_group(std::move(render));

// Module B (network DLL):
auto net = vh::group("Network");
net.add(vh::api_hook("ws2_32", "send", &hk_send));
vh::HookRegistry::global().register_group(std::move(net));

// Shutdown — one call removes everything from both modules:
vh::HookRegistry::global().remove_all();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🌐 Platform Support

| Platform | x86 | x64 | ARM64 |
|---|---|---|---|
| Windows | ✓ | ✓ | Build from source |
| Linux | — | ✓ | ✓ |
| macOS | — | ✓ | ✓ |

Precompiled `.lib` files are provided for Windows x86 and x64. ARM64 and POSIX targets require a source build — see [`lib/README.md`](lib/README.md).

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🛡️ Stealth & Hardening

VanHooks includes 19 hardening modules that make hooks invisible and resilient. All modules are optional — include only what you need. Some modules require the full source license for custom configurations.

| Category | Module | Header | Purpose |
|---|---|---|---|
| **Core** | Polymorphic trampolines | `<vh/core/polymorphic.vh>` | Every trampoline is unique — randomised registers, junk insertion, order shuffling |
| | Encrypted engine state | `<vh/core/engine_crypt.vh>` | 256-bit XOR with rotating keys on all hook metadata |
| | Tamper detection | `<vh/core/tamper_detect.vh>` | CRC canaries + guard pages + anti-dump watchdog |
| | Auto-rehook | `<vh/core/auto_rehook.vh>` | Background monitor reinstalls hooks removed by anti-cheat |
| **Windows** | Shadow-page integrity | `<vh/vigil/shadow_page.vh>` | Dual SEC_IMAGE mapping for hash-scan evasion |
| | CFG/XFG bypass | `<vh/vigil/cfg_bypass.vh>` | Register trampolines as valid call targets |
| | CIG/ACG awareness | `<vh/vigil/cig_aware.vh>` | Detect policies, recommend fallback strategies |
| | Instrumentation callback | `<vh/vigil/instrumentation_cb.vh>` | Neutralise ProcessInstrumentationCallback |
| | Timing normalisation | `<vh/vigil/timing_normal.vh>` | ML-defeating jitter at hook boundaries |
| | Stack spoof v2 | `<vh/vigil/stack_spoof.vh>` | Synthetic multi-frame call chains |
| | ETW-TI v2 | `<vh/vigil/etwti_blind.vh>` | Provider-level selective ETW-TI filter |
| | Thread pool injection | `<vh/inject/inject_tp.vh>` | TP_WORK-based injection |
| **Linux** | Native syscall stubs | `<vh/vigil/linux_syscalls.vh>` | Direct syscall without libc (x64/ARM64/x86) |
| | /proc/maps scrubbing | `<vh/vigil/maps_scrub.vh>` | Filter VanHooks regions from maps reads |
| | ptrace hardening | `<vh/vigil/ptrace_harden.vh>` | PTRACE_TRACEME + TracerPid monitor |
| | link_map unlinking | `<vh/vigil/link_map_hide.vh>` | Remove .so from dl_iterate_phdr chain |
| | seccomp awareness | `<vh/vigil/seccomp_aware.vh>` | Detect BPF filters, probe syscall availability |
| | ELF .text integrity | `<vh/vigil/elf_integrity.vh>` | CRC watchdog with known-patch exclusion |
| | process_vm injection | `<vh/inject/inject_vm.vh>` | process_vm_writev + ptrace mmap fallback |
| **Hooks** | EPT hooking | `<vh/hooks/ept_hook.vh>` | Hypervisor-assisted execute/read page split |

See the [Functions Guide](VanHooks_Functions_Guide.md) Part XIII for the full API reference.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📤 Shared Library ABI

VanHooks can be built as a shared library (`.dll`/`.so`/`.dylib`) from source. All public API functions and key classes are annotated with `VH_API` macros defined in `<vh/export.vh>`.

| Macro | Shared build (DLL consumer) | Static build (default) |
|---|---|---|
| `VH_API` | `__declspec(dllimport)` on Windows, `visibility("default")` on GCC/Clang | Empty — no effect |
| `VH_SHARED` | Defined | Not defined |
| `VH_EXPORTS` | Defined only when *building* the DLL | Not defined |

The precompiled `.lib` files in this SDK are **static libraries** — `VH_API` resolves to nothing and all symbols are linked directly. Shared library builds require the full source license.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📁 Package Layout

```
VanHooksSDK/
├── include/
│   ├── vh/                         ← public API headers (.vh)
│   │   ├── vh.vh                   ← single-include entry point
│   │   ├── config.vh               ← build configuration
│   │   ├── hook.vh                 ← Hook type and RAII lifetime
│   │   ├── group.vh                ← batch lifecycle management
│   │   ├── mid.vh                  ← mid-function hooks
│   │   ├── export.vh               ← shared library ABI macros (VH_API)
│   │   ├── result.vh               ← Result<T> and error codes
│   │   ├── fwd.vh                  ← forward declarations
│   │   ├── advanced.vh             ← advanced engine API
│   │   ├── disasm.vh               ← disassembler bridge
│   │   ├── detail/                 ← internal details
│   │   │   └── callsite_bridge.vh
│   │   ├── core/                   ← engine hardening
│   │   │   ├── polymorphic.vh      ← polymorphic trampoline generation
│   │   │   ├── engine_crypt.vh     ← encrypted engine state
│   │   │   ├── tamper_detect.vh    ← tamper detection & anti-dump
│   │   │   └── auto_rehook.vh      ← automatic re-hooking engine
│   │   ├── hooks/                  ← hook mechanisms
│   │   │   ├── breakpoint.vh       ← hardware breakpoint hooks
│   │   │   ├── ept_hook.vh         ← EPT/hypervisor-assisted hooking
│   │   │   └── veh_hook.vh         ← VEH-based hooks
│   │   ├── inject/                 ← injection catalogue
│   │   │   ├── inject.vh           ← core 4 injection methods
│   │   │   ├── inject_ex.vh        ← extended techniques
│   │   │   ├── inject_unified.vh   ← full 24-technique catalogue
│   │   │   ├── inject_stealth.vh   ← stealth injection helpers
│   │   │   ├── inject_tp.vh        ← thread pool injection
│   │   │   └── inject_vm.vh        ← process_vm_writev injection
│   │   └── vigil/                  ← stealth & anti-detection
│   │       ├── unhook.vh           ← NTDLL/kernel32 unhooking
│   │       ├── syscalls.vh         ← direct/indirect syscall gate
│   │       ├── api_hash.vh         ← compile-time API hashing
│   │       ├── callstack_spoof.vh  ← call-stack spoofing
│   │       ├── stack_spoof.vh      ← synthetic multi-frame chains
│   │       ├── sleep_obf.vh        ← sleep obfuscation
│   │       ├── thread_hide.vh      ← thread-from-debugger hiding
│   │       ├── peb_mask.vh         ← PEB/BeingDebugged masking
│   │       ├── module_stomp.vh     ← module stomping
│   │       ├── heap_crypt.vh       ← heap encryption
│   │       ├── mem_guard.vh        ← memory guard pages
│   │       ├── etwti_blind.vh      ← ETW-TI selective filter
│   │       ├── sandbox_detect.vh   ← sandbox detection
│   │       ├── shadow_page.vh      ← shadow-page integrity
│   │       ├── cfg_bypass.vh       ← CFG/XFG bypass
│   │       ├── cig_aware.vh        ← CIG/ACG awareness
│   │       ├── instrumentation_cb.vh ← instrumentation callback
│   │       ├── timing_normal.vh    ← behavioral timing normalisation
│   │       ├── telemetry_patch.vh  ← telemetry patching
│   │       ├── linux_syscalls.vh   ← native Linux syscall stubs
│   │       ├── maps_scrub.vh       ← /proc/self/maps scrubbing
│   │       ├── ptrace_harden.vh    ← ptrace hardening
│   │       ├── link_map_hide.vh    ← link_map unlinking
│   │       ├── seccomp_aware.vh    ← seccomp filter awareness
│   │       └── elf_integrity.vh    ← ELF .text integrity
│   └── vanhooks/                   ← implementation headers
│       └── vanhooks.vh
├── lib/
│   ├── win-x64/{Release,Debug}/    vanhooks.lib
│   └── win-x86/{Release,Debug}/    vanhooks.lib
├── VanHooks_Functions_Guide.md     ← complete API reference
├── LICENSE
└── README.md
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📖 Documentation

- **[VanHooks_Functions_Guide.md](VanHooks_Functions_Guide.md)** — Complete API reference: every function, every configuration field, every error code. Includes the injection API and stealth helpers.
- **[lib/README.md](lib/README.md)** — Precompiled library matrix, MSVC project setup, and build-from-source instructions for ARM64 and POSIX.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚖️ License

This SDK — the public headers and prebuilt libraries — is released under the **MIT License**. See [LICENSE](LICENSE).

### Source License

The full VanHooks source code is available under a **commercial source license**. A source license gives you access to the complete implementation, the ability to build custom configurations, target additional architectures, and integrate VanHooks into proprietary toolchains.

For pricing and licensing inquiries, contact **[TeamVanilla](https://www.teamvanilla.org/)** or reach out on [Discord](https://discord.gg/TeJHcV9EJW).

<div align="center">

<sub>Built and maintained by <a href="https://github.com/TsyVM">TsyVM</a> · <a href="https://www.teamvanilla.org/">TeamVanilla</a></sub>

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:DC2626,100:0D0D0D&height=80&section=footer"/>

</div>
