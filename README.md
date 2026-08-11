<div align="center">

<img src="vh-logo.png" width="600" alt="VanHooks"/>

<p><em>Modern C++23 Cross-Platform Function Hooking Library</em></p>

<a href="#">
<img src="https://readme-typing-svg.demolab.com/?lines=Trampoline+%C2%B7+IAT+%C2%B7+PLT+%C2%B7+VTable+%C2%B7+Mid-Function;Pattern+Scanner+%C2%B7+Injection+%C2%B7+Symbols+%C2%B7+Breakpoints;One+API.+Every+Platform.+Zero+Exceptions.;std%3A%3Aexpected+all+the+way+down.&font=Fira%20Code&center=true&width=650&height=45&color=FF3B3B&vCenter=true&size=22&pause=1800"/>
</a>

<br/>

[![License: MIT](https://img.shields.io/badge/License-MIT-FF3B3B?style=for-the-badge&labelColor=000000)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-FF3B3B?style=for-the-badge&labelColor=000000&logo=cplusplus&logoColor=FF3B3B)](https://en.cppreference.com/w/cpp/23)
[![Windows](https://img.shields.io/badge/Windows-x86%20%7C%20x64-FF3B3B?style=for-the-badge&labelColor=000000&logo=windows&logoColor=FF3B3B)](lib/)
[![Linux](https://img.shields.io/badge/Linux-x64%20%7C%20ARM64-FF3B3B?style=for-the-badge&labelColor=000000&logo=linux&logoColor=FF3B3B)](lib/)
[![macOS](https://img.shields.io/badge/macOS-x64%20%7C%20ARM64-FF3B3B?style=for-the-badge&labelColor=000000&logo=apple&logoColor=FF3B3B)](lib/)

<br/>

[![Stars](https://img.shields.io/github/stars/tsyvm/vanhooks?style=for-the-badge&color=FF3B3B&labelColor=000000)](../../stargazers)
[![Issues](https://img.shields.io/github/issues/tsyvm/vanhooks?style=for-the-badge&color=FF3B3B&labelColor=000000)](../../issues)
[![Last Commit](https://img.shields.io/github/last-commit/tsyvm/vanhooks?style=for-the-badge&color=FF3B3B&labelColor=000000)](../../commits)
[![Downloads](https://img.shields.io/github/downloads/tsyvm/vanhooks/total?style=for-the-badge&color=FF3B3B&labelColor=000000)](../../releases)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

VanHooks is a production-grade, cross-platform function hooking and instrumentation library for C++23. It provides inline trampoline hooks, import table hooks, procedure linkage table hooks, virtual function table hooks, and mid-function register-context hooks — all through a single unified API backed by `std::expected` error handling and RAII lifetime management. Beyond hooking, the library ships a complete instrumentation toolkit: a pattern scanner, disassembler, process injector, symbol resolver, PE introspection layer, software and hardware breakpoints, call stack capture, and anti-debug detection. A built-in network layer, **VanNet**, ships in the same library for live packet capture and protocol parsing. Every feature uses the same `Result<T>` error model and the same `#include <vh/vh.hpp>` entry point.

<div align="center">

### 📑 Table of Contents

[Why VanHooks](#-why-vanhooks) · [Features](#-features-at-a-glance) · [Requirements](#️-requirements) · [Installation](#-installation) · [Quick Start](#-quick-start) · [Hook Types](#-hook-types) · [Lifetime & RAII](#️-hook-lifetime-and-raii) · [Groups](#️-groups--batch-lifecycle-management) · [Chaining](#-hook-chaining) · [Error Handling](#-error-handling) · [HookRegistry](#-multi-module-projects--hookregistry) · [Scanner](#-pattern-scanner) · [Anti-Debug](#-anti-debug-detection) · [Disassembler](#-disassembler) · [Injection](#-process-injection) · [Symbols](#-symbol-resolution) · [PE Introspection](#-pe-introspection) · [Breakpoints](#-breakpoints) · [Call Stack](#-call-stack-capture) · [VanNet](#-vannet--built-in-network-layer) · [Optional Modules](#️-optional-modules) · [Platform Support](#️-platform-support) · [FAQ](#-faq) · [Docs](#-documentation)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🩸 Why VanHooks?

<div align="center">

| | MinHook | EasyHook | SafetyHook | PolyHook2 | **VanHooks** |
|---|:---:|:---:|:---:|:---:|:---:|
| **Platforms** | Win | Win | Win / Lin | Win | 🔴 **Win / Lin / macOS** |
| **ARM64** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Hook types** | Trampoline | Trampoline + IAT | Trampoline | Trampoline + IAT + VTable | 🔴 **Trampoline + IAT + PLT + VTable + Mid** |
| **Error handling** | C enum | C enum | exceptions | exceptions | 🔴 **`std::expected`** |
| **C++ standard** | C89 API | .NET | C++23 | C++20 | 🔴 **C++23** |
| **macOS lazy pointers** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **RAII hook lifetime** | ✗ | ✗ | ✓ | ✓ | 🔴 **✓** |
| **Batch group operations** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Hook chaining** | ✗ | ✓ | ✗ | ✓ | 🔴 **✓** |
| **Mid-function hooks** | ✗ | ✗ | ✓ | ✗ | 🔴 **✓** |
| **Built-in packet capture** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (VanNet)** |
| **Pattern scanner** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (IDA-style + BMH)** |
| **Anti-debug detection** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (8 techniques)** |
| **Disassembler API** | ✗ | ✗ | internal | ✗ | 🔴 **✓ (Zydis, public)** |
| **Process injection** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (4 methods)** |
| **Symbol resolution** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (DbgHelp / dladdr)** |
| **PE introspection** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Breakpoints (SW + HW)** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (INT3 / DR0-DR3)** |
| **Call stack capture** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ⚡ Features at a Glance

<div align="center">

| 🪝 | 🧵 | 🧩 | 📦 |
|:---:|:---:|:---:|:---:|
| **5 Hook Types** | **Zero Exceptions** | **RAII Everywhere** | **Single Header** |
| Trampoline · IAT · PLT · VTable · Mid-function | `std::expected` end to end | Hooks, injections, and breakpoints clean up on scope exit | `#include <vh/vh.hpp>` and go |
| 🌐 | 🖥️ | ⚙️ | 🔗 |
| **VanNet Built-in** | **True Cross-Platform** | **C++23 Native** | **Chainable Hooks** |
| Live capture + full protocol parsing | Windows · Linux · macOS · ARM64 | Concepts, `expected`, modern idioms | Stack detours without losing the original |
| 🔍 | 💉 | 🐛 | 🏛️ |
| **Pattern Scanner** | **Process Injection** | **Breakpoints** | **PE Introspection** |
| IDA-style wildcards · Boyer-Moore-Horspool | LoadLibrary · ManualMap · ThreadHijack · ApcQueue | Software (INT3/VEH) + Hardware (DR0–DR3) | Sections · Exports · Imports · Code caves |
| 🔬 | 🔭 | 📡 | 📚 |
| **Disassembler** | **Symbol Resolution** | **Anti-Debug Detection** | **Call Stack Capture** |
| Zydis-backed · rewrite/relocation helpers | DbgHelp · dladdr · libbacktrace · demangling | 8 independent techniques · structured report | Raw + annotated · cross-platform |

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ⚙️ Requirements

| Requirement | Minimum |
|---|---|
| C++ standard | C++23 |
| MSVC | 19.38+ (Visual Studio 2022 17.8+) |
| GCC | 13+ |
| Clang | 17+ |
| CMake | 3.25+ (optional — drop-in use requires no build system) |
| Windows target | Windows 10 1903 / Windows Server 2019 |

> No runtime dependencies for the hooking engine. Zydis is compiled into the library. All optional modules are self-contained except `vh/symbols.hpp` (links `dbghelp.lib` on Windows, `dl` on POSIX) and VanNet (links `wpcap`/`pcap`).

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📥 Installation

### Option A — Drop-in (precompiled, no build system required)

Copy `include/` into your project and link against the precompiled `.lib` for your target.

**Library selection:**

| Target | Configuration | Path |
|---|---|---|
| Windows x64 | Release | `lib/win-x64/Release/vanhooks.lib` |
| Windows x86 | Release | `lib/win-x86/Release/vanhooks.lib` |

All precompiled libs use a static CRT (`/MT` Release, `/MTd` Debug). No Visual C++ Redistributable is required. See [`lib/README.md`](lib/README.md) for MSVC project settings and ARM64 / Linux / macOS build-from-source instructions.

<details>
<summary><b>🔧 CMake (drop-in) — click to expand</b></summary>

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

</details>

<details>
<summary><b>🔧 MSVC project (manual) — click to expand</b></summary>

1. **Additional Include Directories** → add `include\`
2. **Additional Library Directories** → add `lib\win-x64\Release\` (adjust for arch/config)
3. **Additional Dependencies** → add `vanhooks.lib`
4. **Runtime Library** → `Multi-threaded (/MT)` for Release, `Multi-threaded Debug (/MTd)` for Debug

</details>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🩸 Quick Start

One include is all you need:

```cpp
#include <vh/vh.hpp>
```

Everything lives in the `vh::` namespace.

### Intercept a function (no call-through needed)

```cpp
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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🪝 Hook Types

VanHooks provides five hook types, all returning the same `Result<Hook>` type.

<details open>
<summary><b>Inline (trampoline) hook</b></summary>

Patches the first bytes of the target function with a jump. Works on any function whose prologue is large enough — 5 bytes on x86/x64, 16 bytes on ARM64.

```cpp
auto r = vh::inline_hook(&target, &detour, &orig, { .tag = "Module.Function" });
```

</details>

<details>
<summary><b>IAT hook — Windows</b></summary>

Patches an Import Address Table entry. Intercepts calls from a specific module without modifying the target function itself. Useful for short functions that cannot be safely inline-hooked.

```cpp
// Patch the IAT entry in a specific module
auto r = vh::iat_hook("MessageBoxW", (void*)&hk_mbw,
                      { .module_name = "my_app.exe", .tag = "IAT.MessageBoxW" });

// Patch every loaded module's IAT entry at once
auto hooks = vh::iat_hook_all("malloc", (void*)&hk_malloc);
```

</details>

<details>
<summary><b>PLT hook — Linux / macOS</b></summary>

Patches the Procedure Linkage Table (Linux) or lazy pointer (macOS) used by the dynamic linker. The POSIX equivalent of an IAT hook.

```cpp
auto r = vh::plt_hook("libc", "malloc", (void*)&hk_malloc, { .tag = "libc.malloc" });
```

</details>

<details>
<summary><b>VTable hook</b></summary>

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

</details>

<details>
<summary><b>Mid-function hook</b></summary>

Installs a hook at a byte offset inside a function. Does not redirect control flow — observes and optionally modifies CPU register state at that point, then continues original execution.

```cpp
auto r = vh::mid_hook(game_update_fn,
    [](vh::MidContext* ctx) noexcept {
        player_health = static_cast<int>(ctx->rax);
    },
    { .offset = 0x1C, .tag = "Game.HealthReadback" });
```

</details>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ♻️ Hook Lifetime and RAII

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🗂️ Groups — Batch Lifecycle Management

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ❗ Error Handling

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🧩 Multi-Module Projects — HookRegistry

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔍 Pattern Scanner

`#include <vh/vh.hpp>` — available when built with `VH_ENABLE_SCANNER=ON` (default).

Boyer-Moore-Horspool scanner with IDA-style wildcard support. Operates over an arbitrary memory region, a named module, or all readable committed pages in the process.

```cpp
// IDA-style wildcards — scan the entire process
auto r = vanhooks::scanner::scan_process("48 8B 05 ? ? ? ? 48 85 C0");
if (r) {
    for (auto addr : *r)
        printf("match @ 0x%llx\n", (unsigned long long)addr);
}

// Scan within a named module
auto hits = vanhooks::scanner::scan_module("game.exe", "55 48 89 E5 ? ? ? ?");

// Scan a known region
auto addrs = vanhooks::scanner::scan_pattern(base_ptr, region_size, "FF 25 ? ? ? ?");

// Exact byte scan (no wildcards, fastest path)
std::vector<uint8_t> needle = { 0x48, 0x8B, 0xCB };
auto exact = vanhooks::scanner::scan_bytes(base_ptr, region_size, needle);
```

All overloads return `Result<std::vector<uintptr_t>>` or a plain `std::vector<uintptr_t>` for the exact scan. Patterns are validated at parse time; a malformed IDA string returns `Error::InvalidArgument` immediately.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🛡️ Anti-Debug Detection

`#include <vh/vh.hpp>` — available when built with `VH_ENABLE_ANTIDEBUG=ON` (default).

Eight independent detection techniques run in one call and return a structured per-finding report. Useful for understanding what anti-debug measures a target applies, or for verifying that your own research environment is clean before instrumentation.

```cpp
auto report = vanhooks::antidebug::check_all();

if (report.any_detected())
    printf("%d technique(s) flagged a debugger\n", report.detection_count());

for (auto& f : report.findings) {
    printf("[%s] %s — %s\n",
           f.detected ? "DETECTED" : "clean",
           f.technique.c_str(),
           f.detail.c_str());
}
```

**Techniques covered (Windows):**

| Technique | Method |
|---|---|
| `IsDebuggerPresent` | PEB.BeingDebugged flag |
| `CheckRemoteDebuggerPresent` | Cross-process debugger handle |
| `NtQueryInformationProcess(DebugPort)` | Debug port check via ntdll |
| Heap flags | Debugger sets non-standard heap flags in PEB |
| `NtGlobalFlag` | PEB flag bits 0x70 |
| `CloseHandle(invalid)` | Raises `EXCEPTION_INVALID_HANDLE` under a debugger |
| Timing anomaly | Measurable delay introduced by single-step execution |
| Debugger process list | Scans running processes for x64dbg, IDA, WinDbg, Cheat Engine, etc. |

On Linux, `ptrace(TRACEME)` is used as a lightweight substitute. The `Report` struct is the same on all platforms.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔬 Disassembler

`#include <vh/disasm.hpp>` (also pulled in by `<vh/vh.hpp>`). Always available — Zydis is always linked.

VanHooks embeds Zydis for internal trampoline construction. `vh/disasm.hpp` exposes the same engine to end users, adding ergonomic wrappers for prologue decoding, relocation rewriting, and formatted listings.

```cpp
#include <vh/disasm.hpp>

vh::disasm::Disassembler dis;

// Decode one instruction at a known runtime address
auto insn = dis.decode_one(code_span, runtime_address);
if (insn)
    printf("%s  (%u bytes)\n", insn->mnemonic.c_str(), insn->length);

// Decode until the first unconditional branch or return
for (auto& i : vh::disasm::decode_until_branch(fn_ptr, 128))
    printf("  %s\n", vh::disasm::format_insn(i).c_str());

// Compute the minimum safe patch byte count (never splits an instruction)
auto len = vh::disasm::safe_copy_length(fn_ptr, 5 /*min bytes*/);

// Rewrite RIP-relative operands after relocating bytes to a new address
auto rr = vh::disasm::rewrite(insns, original_va, new_va);
if (rr && rr->clean) {
    // rr->code is ready to write to the stub region
}

// Print an entire decoded sequence
auto listing = vh::disasm::format_listing(insns);
```

**ARM64** uses an internal fixed-width 4-byte decoder. Pass an explicit `vh::disasm::Arch` to override auto-detection.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 💉 Process Injection

`#include <vh/inject.hpp>` (also pulled in by `<vh/vh.hpp>` when `VH_INJECT_ENABLED`). Available when built with `VH_ENABLE_INJECT=ON` (default). **Windows only** — returns `Error::Unsupported` on other platforms.

Four injection methods, one unified RAII `Injection` handle. The handle ejects automatically when it goes out of scope, matching the lifetime model of `vh::Hook`.

```cpp
// LoadLibrary — simplest, easiest to detect
auto inj = vh::inject(pid, "C:\\payloads\\research.dll");
if (!inj) {
    fprintf(stderr, "inject failed: %d\n", (int)inj.error());
    return;
}
// DLL running in pid; ejected when inj destructs

// ManualMap — no module-list entry, PE header withheld
std::vector<uint8_t> pe = load_from_resource();
auto inj2 = vh::inject_from_memory(pid, pe,
    { .method = vh::InjectMethod::ManualMap, .tag = "research" });

// ThreadHijack — no CreateRemoteThread syscall
auto inj3 = vh::inject(pid, dll_path,
    { .method = vh::InjectMethod::ThreadHijack });

// ApcQueue — no new thread; fires on next alertable wait
auto inj4 = vh::inject(pid, dll_path,
    { .method = vh::InjectMethod::ApcQueue });

// Explicit early eject
auto r = inj->eject();

// Inspect the handle
printf("pid=%u  method=%d  tag=%s\n",
       inj->pid(), (int)inj->method(), inj->tag().c_str());
```

**Method trade-offs:**

| Method | Stealth | Notes |
|---|---|---|
| `LoadLibrary` | Low | Trivially visible in module list and LoadLibrary hooks |
| `ManualMap` | Medium | No PEB loader-list entry; PE header withheld from remote allocation |
| `ThreadHijack` | Medium-high | No `CreateRemoteThread`; briefly disturbs the hijacked thread |
| `ApcQueue` | Medium-high | No new thread; timing is non-deterministic — fires only on alertable waits |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔭 Symbol Resolution

`#include <vh/symbols.hpp>` (also pulled in by `<vh/vh.hpp>` when `VH_SYMBOLS_ENABLED`). Available when built with `VH_ENABLE_SYMBOLS=ON` (default).

Resolves virtual addresses to human-readable names and source locations using the platform's native debug-info backend. The symbol backend initializes lazily on first use.

```cpp
#include <vh/symbols.hpp>

// Resolve any address to its nearest symbol
if (auto sym = vh::symbols::resolve(some_address)) {
    printf("%s + 0x%zx  [%s]\n",
           sym->name.c_str(),
           some_address - sym->address,
           sym->module.c_str());
}

// Look up a symbol by name (optional module filter)
if (auto addr = vh::symbols::find("NtQuerySystemInformation", "ntdll.dll"))
    printf("found @ 0x%llx\n", (unsigned long long)*addr);

// Source file + line number (requires PDB / DWARF debug info)
if (auto loc = vh::symbols::source_location(some_address))
    printf("%s:%u\n", loc->file.c_str(), loc->line);

// Demangle a C++ symbol name
auto readable = vh::symbols::demangle("_ZN3foo3barEv");

// Capture and print the current call stack
for (auto& line : vh::symbols::current_stack(32))
    puts(line.c_str());

// Pre-warm a module's symbol table before a hot path
vh::symbols::load_module("C:\\MyApp\\engine.dll");
```

**Backend by platform:**

| Platform | Backend | Line info |
|---|---|---|
| Windows | `DbgHelp` — links `dbghelp.lib` | PDB via `_NT_SYMBOL_PATH` |
| Linux | `dladdr` | DWARF via `libbacktrace` (`-DVH_SYMBOLS_BACKTRACE=ON`) |
| macOS | `dladdr` | DWARF via `libbacktrace` (`-DVH_SYMBOLS_BACKTRACE=ON`) |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🏛️ PE Introspection

`#include <vh/pe.hpp>` (also pulled in by `<vh/vh.hpp>` when `VH_PE_ENABLED`). Available when built with `VH_ENABLE_PE=ON` (default). **Windows only** — returns `Error::Unsupported` on other platforms.

Structured, read-only access to any PE image that is currently mapped in the process — no file I/O, no extra dependencies.

```cpp
#include <vh/pe.hpp>

// Open any loaded module by name (empty = main executable)
auto view = vh::pe::open("ntdll.dll");
if (!view) { /* Error::ModuleNotFound */ }

// Walk exports — find a function without GetProcAddress
for (auto& e : view->exports().value_or({}))
    if (e.name == "NtQuerySystemInformation")
        printf("found @ 0x%llx\n", (unsigned long long)e.address);

// Read the IAT slot for a specific import
auto imp = view->find_import("kernel32.dll", "VirtualProtect");
if (imp) {
    auto* slot = reinterpret_cast<void**>(imp->iat_address);
    printf("IAT slot → %p\n", *slot);
}

// Locate code caves large enough for a 32-byte stub
for (auto& cave : view->find_caves(32))
    printf("[%s] 0x%llx  %zu bytes\n",
           cave.section_name, (unsigned long long)cave.address, cave.size);

// List all loaded modules
for (auto& m : vh::pe::modules().value_or({}))
    printf("%s  base=0x%llx\n", m.name().data(), (unsigned long long)m.base());

// Open a module by known base address
auto view2 = vh::pe::open_at(base_va);

// Open by HMODULE
auto view3 = vh::pe::open_handle(hmod);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🐛 Breakpoints

`#include <vh/breakpoint.hpp>` (also pulled in by `<vh/vh.hpp>` when `VH_BREAKPOINT_ENABLED`). Available when built with `VH_ENABLE_BREAKPOINT=ON` (default).

Software and hardware breakpoints with RAII lifetime. The returned `Breakpoint` guard removes the breakpoint when it goes out of scope.

```cpp
#include <vh/breakpoint.hpp>

// Software breakpoint — INT3 patched in-place; handled via VEH (Windows)
// or SIGTRAP signal handler (Linux / macOS)
auto bp = vh::breakpoint::set_software(target_addr,
    [](uintptr_t addr) {
        printf("SW hit @ 0x%llx\n", (unsigned long long)addr);
        return vh::breakpoint::Action::Continue;
    });
if (!bp) { /* handle Error::BreakpointSlotExhausted etc. */ }

// Hardware breakpoint — uses DR0–DR3; x86-64 only
auto hw = vh::breakpoint::set_hardware(
    addr,
    vh::breakpoint::HwCondition::Execute,
    vh::breakpoint::HwSize::Byte,
    [](uintptr_t a) { return vh::breakpoint::Action::Continue; });

// Propagate the hardware BP to a newly created thread (DLL_THREAD_ATTACH)
hw->apply_to_new_thread(hthread_of_new_thread);

// Explicit removal (destructor also does this)
bp->remove();
```

Hardware breakpoints return `Error::Unsupported` on non-x86-64 targets and `Error::BreakpointSlotExhausted` if all four DR slots are already occupied.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📡 Call Stack Capture

`#include <vh/callstack.hpp>` (also pulled in by `<vh/vh.hpp>` when `VH_CALLSTACK_ENABLED`). Available when built with `VH_ENABLE_CALLSTACK=ON` (default). No extra dependencies — uses `RtlCaptureStackBackTrace` on Windows and `backtrace(3)` on POSIX.

```cpp
#include <vh/callstack.hpp>

// Raw addresses — no symbol resolution needed
auto frames = vh::callstack::capture();   // skip=1, max_depth=64
if (frames) {
    for (auto addr : *frames)
        printf("  0x%016llx\n", (unsigned long long)addr);
}

// Inside a hook detour — skip VanHooks frames off the top
auto frames2 = vh::callstack::capture(/* skip= */ 2, /* max_depth= */ 32);

// Annotated frames (requires VH_SYMBOLS_ENABLED)
auto annotated = vh::callstack::capture_annotated();
if (annotated)
    printf("%s", vh::callstack::format(*annotated).c_str());

// Convenience: capture + format in one call
auto stack_str = vh::callstack::format(
    *vh::callstack::capture_annotated().value_or({}));
```

Each annotated frame line has the form:
```
#N  0xADDRESS  symbol_name + 0xOFFSET  [module.dll]  src/file.cpp:42
```
Frames that cannot be resolved fall back to their raw address.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🌐 VanNet — Built-in Network Layer

**VanNet** is VanHooks' built-in network layer: live packet capture, offline
pcap/pcapng read/write, BPF filtering, and full protocol parsing, compiled
directly into `libvanhooks` alongside the hooking engine with no external
runtime dependencies of its own.

### Enable / disable

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release   # VH_ENABLE_NET=ON by default
cmake -B build -DVH_ENABLE_NET=OFF          # hooking only, smaller binary
```

### Quick start

```cpp
#include <vh/vh.hpp>   // VanNet pulled in automatically

// Hook a function
auto hook = vh::hook(&target, &detour);

// Capture packets from the same host
auto cap = vh::net::Capture::open("eth0");
if (cap) {
    cap->filter("tcp port 443");
    cap->start([](vh::net::Packet pkt) {
        printf("captured %zu bytes\n", pkt.raw_len());

        // Full layer-by-layer parse
        if (auto parsed = pkt.parse()) {
            auto* ip = parsed->getLayerOfType<vanhooks::net::IPv4Layer>();
            if (ip)
                printf("  src=%s\n", ip->getSrcIPAddress().to_string().c_str());
        }
    });
}
```

### API reference

| Type | Description |
|---|---|
| `vh::net::Capture` | RAII live capture. `open()` → `filter()` → `start(cb)` → `stop()` |
| `vh::net::PcapReader` | Read `.pcap` / `.pcapng` files packet by packet |
| `vh::net::PcapWriter` | Write raw or parsed packets to a `.pcap` file |
| `vh::net::Filter` | BPF expression builder |
| `vh::net::Packet` | Non-owning view returned in the callback; call `parse()` for full decode |
| `vh::net::devices()` | List all live-capture-capable interfaces |

All factory methods return `vh::Result<T>` (`std::expected<T, vh::Error>`),
matching the rest of the VanHooks API exactly.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ⚙️ Optional Modules

All modules are enabled by default. Pass `-D<FLAG>=OFF` to CMake to exclude any layer from the build, reducing binary size and external dependencies.

| CMake Option | Default | What it gates | Extra link deps |
|---|---|---|---|
| `VH_ENABLE_NET` | `ON` | VanNet packet capture + protocol parsing | `wpcap` / `pcap` |
| `VH_ENABLE_SCANNER` | `ON` | `vanhooks::scanner::` pattern scanner | — |
| `VH_ENABLE_ANTIDEBUG` | `ON` | `vanhooks::antidebug::` detection | — |
| `VH_ENABLE_INJECT` | `ON` | `vh::inject` / `vh::inject_from_memory` | `psapi` (Windows) |
| `VH_ENABLE_SYMBOLS` | `ON` | `vh::symbols::` resolution + demangling | `dbghelp` (Win) / `dl` (POSIX) |
| `VH_ENABLE_PE` | `ON` | `vh::pe::` introspection | `psapi` (Windows) |
| `VH_ENABLE_BREAKPOINT` | `ON` | `vh::breakpoint::set_software/hardware` | `kernel32` (Windows) |
| `VH_ENABLE_CALLSTACK` | `ON` | `vh::callstack::capture` + formatting | — |
| `VH_SYMBOLS_BACKTRACE` | `OFF` | DWARF line-info via `libbacktrace` on POSIX | `backtrace` |

**Minimum build** (hooking engine + disassembler only):

```bash
cmake -B build \
  -DVH_ENABLE_NET=OFF \
  -DVH_ENABLE_SCANNER=OFF \
  -DVH_ENABLE_ANTIDEBUG=OFF \
  -DVH_ENABLE_INJECT=OFF \
  -DVH_ENABLE_SYMBOLS=OFF \
  -DVH_ENABLE_PE=OFF \
  -DVH_ENABLE_BREAKPOINT=OFF \
  -DVH_ENABLE_CALLSTACK=OFF
```

The disassembler (`vh/disasm.hpp`) is always compiled in — Zydis is required by the hooking engine itself.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🖥️ Platform Support

<div align="center">

| Platform | x86 | x64 | ARM64 |
|:---:|:---:|:---:|:---:|
| 🪟 Windows | ✅ | ✅ | 🟡 Build from source |
| 🐧 Linux | — | ✅ | ✅ |
| 🍎 macOS | — | ✅ | ✅ |

</div>

Precompiled `.lib` files are provided for Windows x86 and x64. ARM64 and POSIX targets require a source build — see [`lib/README.md`](lib/README.md).

**Module availability by platform:**

| Module | Windows | Linux | macOS |
|---|:---:|:---:|:---:|
| Hooking (all types) | ✅ | ✅ | ✅ |
| Disassembler | ✅ | ✅ | ✅ |
| Pattern scanner | ✅ | ✅ | ✅ |
| Call stack | ✅ | ✅ | ✅ |
| Anti-debug | ✅ (8 checks) | ✅ (ptrace) | ✅ (ptrace) |
| Symbol resolution | ✅ (DbgHelp) | ✅ (dladdr) | ✅ (dladdr) |
| VanNet | ✅ (Npcap) | ✅ (libpcap) | ✅ (libpcap) |
| PE introspection | ✅ | ✗ | ✗ |
| Process injection | ✅ | ✗ | ✗ |
| Hardware breakpoints | ✅ (DR0–DR3) | 🟡 | 🟡 |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ❓ FAQ

<details>
<summary><b>Does VanHooks throw exceptions?</b></summary>
<br/>
No. Every fallible operation returns <code>vh::Result&lt;T&gt;</code> (<code>std::expected&lt;T, vh::Error&gt;</code>). The library never throws from its own code paths.
</details>

<details>
<summary><b>Do I need CMake to use VanHooks?</b></summary>
<br/>
No — drop-in usage only requires copying <code>include/</code> and linking the precompiled <code>.lib</code>. CMake is optional and mainly useful for ARM64/POSIX source builds, VanNet configuration, and toggling optional modules.
</details>

<details>
<summary><b>Can I use VanHooks without VanNet?</b></summary>
<br/>
Yes. Build with <code>-DVH_ENABLE_NET=OFF</code> to exclude the packet capture and protocol parsing layer entirely.
</details>

<details>
<summary><b>Can I strip out specific modules to reduce binary size?</b></summary>
<br/>
Yes — every optional layer has its own CMake flag. See the <a href="#️-optional-modules">Optional Modules</a> table for the full list. The disassembler is the only component that cannot be excluded, as it is required by the hooking engine itself.
</details>

<details>
<summary><b>What happens if I hook a function that's already hooked by another library?</b></summary>
<br/>
Behavior depends on hook type and installation order. Use <code>HookRegistry</code> and <code>tag()</code> to track ownership across modules, and prefer <code>chain()</code> over re-hooking the same target directly.
</details>

<details>
<summary><b>Do hardware breakpoints apply to threads created after installation?</b></summary>
<br/>
Not automatically. Call <code>hw_bp->apply_to_new_thread(hthread)</code> from <code>DLL_THREAD_ATTACH</code> in your DLL to propagate debug registers to each new thread.
</details>

<details>
<summary><b>Does ManualMap injection hide the DLL completely?</b></summary>
<br/>
It hides the module from the PEB loader list and withholds the PE header from the remote allocation, which defeats common module-list scans. It does not defeat all detection methods — code-section heuristics, memory region attribute scans, and integrity checks that walk image pages may still locate the mapping. Prefer <code>ManualMap</code> over <code>LoadLibrary</code> for research contexts, and combine it with VanHooks' hooking layer to intercept any loader callbacks the target registers.
</details>

<details>
<summary><b>Does symbol resolution work without PDB files?</b></summary>
<br/>
On Windows, function names exported by the module's export table are resolvable without a PDB. Full name resolution (including non-exported functions and inlined frames) requires a matching PDB reachable via <code>_NT_SYMBOL_PATH</code> or Microsoft's public symbol server. On Linux and macOS, compile with <code>-g -rdynamic</code>; for DWARF line info, also link <code>libbacktrace</code> and set <code>-DVH_SYMBOLS_BACKTRACE=ON</code>.
</details>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📚 Documentation

- **[VanHooks_Functions_Guide.md](VanHooks_Functions_Guide.md)** — Complete API reference: every function, every configuration field, every error code.
- **[lib/README.md](lib/README.md)** — Precompiled library matrix, MSVC project setup, and build-from-source instructions for ARM64 and POSIX.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

<div align="center">

## 📄 License

**MIT** — see [LICENSE](LICENSE)
<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:000000,50:8B0000,100:000000&height=120&section=footer"/>

</div>
