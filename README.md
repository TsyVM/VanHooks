<div align="center">

<img src="vh-logo.png" width="600" alt="VanHooks"/>

<p><em>Modern C++23 Cross-Platform Function Hooking & Instrumentation Library</em></p>

<a href="#">
<img src="https://readme-typing-svg.demolab.com/?lines=Trampoline+%C2%B7+IAT+%C2%B7+PLT+%C2%B7+VTable+%C2%B7+Mid-Function;Pattern+Scanner+%C2%B7+Injection+%C2%B7+Symbols+%C2%B7+Breakpoints;Watchdog+%C2%B7+Anti-Debug+%C2%B7+ETW+%C2%B7+AMSI;VanTrace+%C2%B7+Ring+Buffer+%C2%B7+Sinks+%C2%B7+Filters;One+API.+Every+Platform.+Zero+Exceptions.;std%3A%3Aexpected+all+the+way+down.&font=Fira%20Code&center=true&width=650&height=45&color=FF3B3B&vCenter=true&size=22&pause=1800"/>
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

VanHooks is a production-grade C++23 function hooking and instrumentation library for Windows, Linux, and macOS. One header. One API. `std::expected` all the way down — no exceptions, no hidden failure paths, no external dependencies beyond Zydis.

Beyond hooking, it ships a complete instrumentation and stealth toolkit: **VanTrace** (structured runtime tracing), **VanNet** (live packet capture), a pattern scanner, disassembler, PE introspector, software and hardware breakpoints, call stack capture, anti-debug detection, process injection, integrity watchdog, and ETW/AMSI suppression — all behind `#include <vh/vh.hpp>`.

VanHooks is distributed as **precompiled static libraries with public API headers**. Drop the headers and the matching `.lib` into your project and link — no build system integration or source compilation required.

<div align="center">

### 📑 Contents

[Features](#-features-at-a-glance) · [Requirements](#️-requirements) · [Installation](#-installation) · [Quick Start](#-quick-start)

[Hook Types](#-hook-types) · [Lifetime & RAII](#️-hook-lifetime--raii) · [Groups](#️-groups--batch-lifecycle-management) · [Chaining](#-hook-chaining) · [Error Handling](#-error-handling) · [HookRegistry](#️-multi-module-projects--hookregistry)

[Scanner](#-pattern-scanner) · [Anti-Debug](#-anti-debug-detection) · [Disassembler](#-disassembler) · [Injection](#-process-injection) · [Stealth](#-stealth-configuration) · [Watchdog](#-integrity-watchdog) · [Symbols](#-symbol-resolution) · [PE Introspection](#-pe-introspection) · [Breakpoints](#-breakpoints) · [Call Stack](#-call-stack-capture)

[VanTrace](#-vantrace--structured-hook-instrumentation) · [VanNet](#-vannet--built-in-network-layer) · [FAQ](#-faq) · [Docs](#-documentation)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ✨ Features at a Glance

**Hooking**
- **Six hook types** — Trampoline, IAT (`iat_hook` / `iat_hook_all`), PLT/GOT, VTable, Mid-function, Return (x64)
- **Three-level API** — beginner `vh::hook()`, explicit-type `vh::inline_hook()`, group-based `vh::group()`
- **Address-based hooks** — `vh::hook(uintptr_t, …)` for runtime-resolved addresses; no `reinterpret_cast` at the call site
- **Hook chaining** — stack multiple detours on one target; each sees the previous one's trampoline
- **Thread-safe by default** — all installs suspend threads; IP fixup handles prologue races on remove

**Groups & Lifecycle**
- **Named groups & HookRegistry** — batch enable/disable/remove across DLL boundaries
- **`Group::hook_at()`** — trampoline from a raw address directly into a group
- **`Group::hook_pattern()`** — scan for an IDA-style byte pattern and hook the first match in one call
- **`Group::hook_callsite()` / `Group::hook_callsite_pattern()`** — patch a single CALL/JMP site directly into a group
- **`Group::patch<T>()` / `Group::nop()`** — write typed values or NOP slides with automatic page-protection lifting
- **Batch queue** — `queue_enable` / `queue_disable` / `apply` amortises thread-suspension overhead

**Instrumentation**
- **VanTrace** — lock-free ring buffer tracing with pluggable sinks, per-event timing, thread IDs, call depth, and raw context capture
- **VanNet** — live packet capture and protocol parsing; pcapng read/write, full layer-2–7 protocol stack
- **Pattern scanner** — IDA-style wildcard patterns with Boyer–Moore–Horspool acceleration
- **Disassembler** — Zydis-backed length disassembler and full instruction decoder (always available)
- **Software & hardware breakpoints** — RAII lifetime, DR0–DR3, VEH/sigaction, new-thread propagation
- **Call stack capture** — raw VAs or annotated frames (with `VH_SYMBOLS_ENABLED`)
- **PE introspection** — sections, exports, imports, code cave finder
- **Symbol resolution** — DbgHelp (Windows) / libbacktrace (POSIX)

**Stealth & Analysis**
- **Integrity watchdog** — background thread detects and reinstalls hooks removed by kernel drivers
- **ETW suppression** — patches `EtwEventWrite` / `EtwEventWriteFull` to silence user-mode telemetry
- **AMSI suppression** — patches `AmsiScanBuffer` / `AmsiScanString` to return clean without scanning
- **Process injection** — four methods (LoadLibrary, ManualMap, ThreadHijack, ApcQueue) with RAII eject
- **Anti-debug detection** — eight independent techniques with a structured per-technique report

**`std::expected` throughout** — no exceptions, no raw OS error codes, no hidden failure paths.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🛠️ Requirements

| | |
|---|---|
| **Compiler** | GCC 13+, Clang 17+, or MSVC 19.38+ with `/std:c++23` |
| **CMake** | 3.25+ (optional — drop-in linking works without CMake) |
| **Zydis** | Linked into the precompiled library — no separate install needed |
| **Windows** | x86 / x64 — MinGW i686 cross-compilation supported |
| **Linux** | x64 / ARM64 |
| **macOS** | x64 / ARM64 |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📦 Installation

VanHooks is distributed as **precompiled static libraries with public headers**. Copy `include/` into your project, link against the `.lib` for your target, and you're done. No Redistributable required — all libs use a static CRT.

| Target | Configuration | Path |
|---|---|---|
| Windows x64 | Release | `libs/MSVC/win-x64/Release/vanhooks.lib` |
| Windows x86 | Release | `libs/MSVC/win-x86/Release/vanhooks.lib` |

### MSVC project setup

1. **Additional Include Directories** → `include\`
2. **Additional Library Directories** → `lib\win-x64\Release\`
3. **Additional Dependencies** → `vanhooks.lib`
4. **Runtime Library** → `Multi-threaded (/MT)` for Release, `Multi-threaded Debug (/MTd)` for Debug

### CMake (drop-in)

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

See [`lib/README.md`](lib/) for ARM64 and Linux / macOS library paths.

### Single include

```cpp
#include <vh/vh.hpp>  // everything you need
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ⚡ Quick Start

```cpp
#include <vh/vh.hpp>

// Windows — intercept MessageBoxA
static int (WINAPI* orig_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = nullptr;

int WINAPI hk_MessageBoxA(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    caption = "VanHooks";
    return orig_MessageBoxA(hwnd, text, caption, type);
}

// Linux — intercept malloc via PLT
static void* (*orig_malloc)(size_t) = nullptr;

void* hk_malloc(size_t size) {
    printf("[malloc] %zu bytes\n", size);
    return orig_malloc(size);
}

void setup() {
    // Function pointer target
    auto h1 = vh::hook(&MessageBoxA, &hk_MessageBoxA, &orig_MessageBoxA);

    // Runtime address target — no reinterpret_cast needed
    auto h2 = vh::hook(0x5D5DB0u, &hk_MessageBoxA, &orig_MessageBoxA);

    // PLT hook (Linux / macOS)
    auto h3 = vh::plt_hook("libc.so.6", "malloc", &hk_malloc, &orig_malloc);

    if (!h1) {
        printf("failed: %s\n", vanhooks::error_to_string(h1.error()).data());
    }

    // Hooks go out of scope → originals automatically restored
}
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🎣 Hook Types

VanHooks exposes six distinct hook mechanisms, all returning `Result<Hook>` or `Result<HookHandle>`.

### Trampoline (Inline)

Patches the target function's prologue with a jump to your detour. The original instructions are relocated into a trampoline stub, allowing you to call through to the original.

```cpp
auto h  = vh::inline_hook(&target_fn, &my_detour, &orig_fn);
auto h2 = vh::inline_hook(0x5D5DB0u, &my_detour, &orig_fn);  // address-based
```

On **x86** a 5-byte rel32 JMP is used. On **x64** a 14-byte `FF 25` indirect when the target is outside ±2 GB. On **ARM64** a 4-byte `B` (±128 MB) or a 20-byte `MOVZ/MOVK/BR` sequence.

### API Hook (by name)

Resolves a symbol at runtime via `GetProcAddress` / `dlsym`, then installs a trampoline.

```cpp
auto h = vh::hook("user32.dll", "MessageBoxA", &hk_MessageBoxA, &orig_MessageBoxA);
```

### IAT Hook

Patches the Import Address Table slot in a specific module, or every loaded module that imports the symbol.

```cpp
auto h  = vh::iat_hook("VirtualAlloc", &hk_VAlloc, { .module_name = "my.dll" });
auto hs = vh::iat_hook_all("VirtualAlloc", &hk_VAlloc);
```

### PLT / GOT Hook (Linux / macOS)

Redirects the Procedure Linkage Table / Global Offset Table entry for a shared library symbol. The POSIX equivalent of an IAT hook.

```cpp
auto h = vh::plt_hook("libc.so.6", "malloc", &hk_malloc, &orig_malloc);
```

### VTable Hook

Patches a single slot in a C++ virtual dispatch table.

```cpp
void** vtbl = *reinterpret_cast<void***>(object_ptr);
auto h = vh::vtable_hook(vtbl, /*slot=*/3, &hk_Render);
```

### Mid-Function Hook

Installs a hook at a byte offset inside a function. A `MidContext*` is passed to your callback with a full GPR + flags snapshot. The original instructions still execute after the callback returns — mid hooks observe or modify register state, they do not redirect control flow.

```cpp
auto h = vh::mid_hook(&target_fn,
    [](vanhooks::MidContext* ctx) noexcept {
        ctx->rax = 0;
    },
    { .offset = 0x2A });
```

| Architecture | Available fields |
|---|---|
| **x64** | `rax`…`r15`, `rflags` — all `uint64_t` |
| **x86** | `eax`…`edi`, `eflags` — all `uint32_t` |
| **ARM64** | `x[0]`…`x[7]`, `lr` — all `uint64_t` |

### CallSite Hook

Patches the 32-bit relative displacement of a **single** `CALL` (E8) or `JMP` (E9) instruction, redirecting only that one call site. Every other caller of the same function is unaffected.

```cpp
using PFN = int(__cdecl*)(int);
PFN g_orig = nullptr;

int my_detour(int x) {
    printf("intercepted: %d\n", x);
    return g_orig(x);
}

// Address-based (primary form — common with pattern-scanned addresses)
auto h = vh::callsite_hook(0x12AB34u, &my_detour, &g_orig,
                           { .tag = "Game.SpeedCall" });

// Function-pointer form
auto h2 = vh::callsite_hook(&known_call_site, &my_detour, &g_orig);
```

| | Trampoline | CallSite |
|---|---|---|
| What is patched | Target function prologue | Displacement at one `CALL`/`JMP` site |
| Callers affected | All callers | Only the one patched site |
| ARM64 | ✓ | Returns `Error::Unsupported` |

### Return Hook (x64 only)

Captures the function's return value and lets you modify it before the caller sees it.

```cpp
auto& eng = vanhooks::global_engine();
auto h = eng.hook_mid_return(
    &target_fn, /*byte_offset=*/0, /*enter_cb=*/nullptr,
    [](vanhooks::ReturnContext* ctx) noexcept {
        ctx->retval_rax = 42;
    });
```

`ReturnContext` fields (x64): `retval_rax`, `retval_rdx`, `retval_xmm0`, `hook_id`, `real_ret_addr`. Returns `Error::Unsupported` on ARM64 and x86.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ♻️ Hook Lifetime & RAII

Every `vh::Hook` object owns its installation. Going out of scope automatically removes the hook and restores the original bytes — no manual cleanup required.

```cpp
{
    auto h = vh::hook(&target, &detour, &orig);
    // hook active
} // removed automatically

// Explicit control
h.enable();   // returns Result<ref<Hook>>
h.disable();  // returns Result<ref<Hook>>
h.remove();   // idempotent — safe to call multiple times
h.valid();    // false after removal
h.tag();      // optional string label set at install time
```

### Thread Safety & IP Fixup

When `thread_safe = true` (the default), VanHooks suspends all threads during the patch window and uses IP fixup to advance any thread whose instruction pointer landed inside the stolen prologue bytes — removing a hook under live traffic never leaves a thread in an inconsistent state.

```cpp
auto h = vh::inline_hook(&target, &detour, &orig, { .thread_safe = false, .tag = "my_hook" });
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🗂️ Groups & Batch Lifecycle Management

`vh::Group` is a named RAII container that owns a set of hooks and operates on all of them in a single atomic thread-suspension window.

```cpp
auto grp = vh::group("render_hooks");
grp.add(vh::hook(&fn_a, &hk_a, &orig_a))
   .add(vh::hook(&fn_b, &hk_b, &orig_b))
   .add(vh::hook(&fn_c, &hk_c, &orig_c));

grp.enable();   // one suspension window — all three enabled atomically
grp.disable();
// grp destructor calls remove_all() automatically
```

### Address-based install

```cpp
grp.hook_at(0x5D5DB0u, &MyDetour, &orig_fn);
grp.hook_at(addr, &MyDetour, nullptr, { .tag = "my_hook" });
```

### CallSite install

```cpp
// Direct address
grp.hook_callsite(0x12AB34u, &MyDetour, &g_orig);
grp.hook_callsite(0x12AB34u, &MyDetour, &g_orig, { .tag = "NFS.SpeedCall" });

// Pattern scan — finds the pattern, treats the found byte as the E8/E9 site
grp.hook_callsite_pattern("E8 ? ? ? ? 83 C4 04", 0, &MyDetour, &g_orig);

// Advance past a preceding instruction to land on the E8 byte
grp.hook_callsite_pattern("89 04 24 E8 ? ? ? ?", 3, &MyDetour, &g_orig);
```

### Pattern-scan hook

```cpp
grp.hook_pattern("E8 ? ? ? ? 83 C4 04", -5, &MyDetour);
grp.hook_pattern("48 8B 05 ? ? ? ?",     0,  &MyDetour, &orig_fn);
```

Only the first match is hooked. No-op if the pattern is not found.

### Memory patch helpers

```cpp
grp.patch<uint8_t>(0x581E72, 32);       // typed write, auto page-protection lift
grp.patch<float>(0x5D88D1 + 6, 0.25f);
grp.nop(0x14E738B, 2);                  // NOP slide
```

### Tagged lookup & batch queue

```cpp
auto res = grp.at("shadow_hook");
if (res) res->get().disable();

// Cross-group atomic flush
auto& eng = vanhooks::global_engine();
eng.queue_enable(h1);
eng.queue_disable(h2);
eng.apply_queued();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔗 Hook Chaining

Stack additional detours onto an already-hooked target. Each link receives the previous detour's trampoline as its "original":

```
target → detour_N → ... → detour_1 → original
```

```cpp
auto base = vh::hook(&fn, &first_detour, &orig_fn);
auto link = base->chain(&second_detour, &orig_for_second);
// Remove in reverse order — ChainOrderViolation returned otherwise
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ❌ Error Handling

Every VanHooks function returns `Result<T>` — a `std::expected<T, vanhooks::Error>`. No exceptions anywhere in the library.

```cpp
auto result = vh::hook(&target, &detour, &orig);
if (!result) {
    switch (result.error()) {
        case vanhooks::Error::HookAlreadyExists:   break;
        case vanhooks::Error::MemoryProtectFailed: break;
        default:
            printf("error: %s\n", vanhooks::error_to_string(result.error()).data());
    }
}

// Monadic chaining (C++23)
vh::hook(&target, &detour, &orig)
    .and_then([](vh::Hook h) -> Result<void> { return {}; })
    .or_else([](vanhooks::Error e) -> Result<void> { return {}; });
```

| Error code | Meaning |
|---|---|
| `ThreadInPrologue` | A thread's IP was inside the stolen bytes during remove; IP fixup resolved it |
| `BreakpointSlotExhausted` | All four DR0–DR3 hardware slots are in use |
| `ChainOrderViolation` | A chain link was removed before its base hook |
| `TrampolineNoSpace` | Prologue too short to steal bytes, or (on x64 CallSite) `&detour` is outside ±2 GB of the call site |
| `ModuleNotFound` | `GetModuleHandle` / `dlopen` found no matching module |
| `SymbolNotFound` | Symbol name not found in debug info |
| `QueueEmpty` | `apply_queued()` called with nothing in the queue |
| `ChainBaseNotFound` | Base `HookHandle` passed to `chain()` is unknown to the engine |
| `InvalidAddress` | Byte at the given address is not the expected opcode (e.g. not E8/E9 for a CallSite hook) |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🗃️ Multi-Module Projects — HookRegistry

`vh::HookRegistry` is a process-wide singleton for sharing named groups across DLL boundaries.

```cpp
// Module A
auto grp = vh::group("input_hooks");
grp.add(vh::hook(&fn1, &hk1));
vh::HookRegistry::global().register_group(std::move(grp));

// Module B
if (auto* g = vh::HookRegistry::global().find_group("input_hooks"))
    g->disable();

vh::HookRegistry::global().enable_all();
vh::HookRegistry::global().disable_all();
vh::HookRegistry::global().remove_all();

size_t n = vh::HookRegistry::global().total_hook_count();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔍 Pattern Scanner

IDA-style wildcard pattern scanning with Boyer–Moore–Horspool acceleration.

```cpp
// Scan the entire process
auto result = vanhooks::scanner::scan_process("48 8B 05 ? ? ? ? 48 85 C0");
if (result && !result->empty()) {
    uintptr_t addr = (*result)[0];
}

// Scan a named module
auto r2 = vanhooks::scanner::scan_module("target.exe", "E8 ? ? ? ? 85 C0 74");

// Scan an explicit range
auto r3 = vanhooks::scanner::scan_pattern(base_ptr, size, "48 8B 05 ? ? ? ?");

// Pre-compile for repeated use
auto pat = vanhooks::scanner::parse_pattern("48 8B 05 ? ? ? ?").value();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🐛 Anti-Debug Detection

Eight independent detection techniques returning a structured `Report` with per-technique `Finding` records.

```cpp
auto report = vanhooks::antidebug::check_all();

if (report.any_detected())
    printf("%d technique(s) detected\n", report.detection_count());

for (auto& f : report.findings)
    printf("[%s] %-45s %s\n",
        f.detected ? "DETECTED" : "clean   ",
        f.technique.c_str(), f.detail.c_str());
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔬 Disassembler

Zydis-backed length disassembler and full instruction decoder. Always available — no optional flag required.

```cpp
#include <vh/disasm.hpp>

vh::disasm::Disassembler dis;

auto insn    = dis.decode_one(code_span, runtime_address);
auto insns   = vh::disasm::decode_until_branch(fn_ptr, 128);
auto prologue = vh::disasm::decode_prologue(fn_ptr, 14);
auto rr      = vh::disasm::rewrite(insns, original_va, new_va);

printf("%s", vh::disasm::format_listing(insns).c_str());
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 💉 Process Injection

Four injection methods, each with distinct stealth and compatibility trade-offs.

```cpp
#include <vh/inject.hpp>

auto inj  = vh::inject(pid, "C:\\path\\payload.dll", { .method = vh::InjectMethod::ManualMap });
auto inj2 = vh::inject_from_memory(pid, pe_bytes,    { .method = vh::InjectMethod::ThreadHijack });

inj->eject();   // RAII — or explicit
```

| Method | Module-list entry | Remote thread | Stealth |
|---|:---:|:---:|:---:|
| `LoadLibrary` | ✓ visible | ✓ | Low |
| `ManualMap` | ✗ | ✓ shellcode | Medium |
| `ThreadHijack` | Configurable | ✗ | High |
| `ApcQueue` | Configurable | ✗ | High |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🥷 Stealth Configuration

ETW and AMSI suppression are configured through the global engine, accessible via `vanhooks::global_engine()`. The engine is pre-initialised with default settings; to override them (custom watchdog intervals, allocator, etc.) [contact us about a source license](https://www.teamvanilla.org/).

```cpp
// Access the global engine for interop and advanced operations
auto& eng = vanhooks::global_engine();

// ETW / AMSI suppression — call once during initialisation
eng.suppress_etw();    // patches EtwEventWrite / EtwEventWriteFull
eng.suppress_amsi();   // patches AmsiScanBuffer / AmsiScanString
```

> ETW and AMSI suppression are user-mode measures. They have no effect on HVCI / VBS-protected systems.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🐕 Integrity Watchdog

Background thread that polls all installed hooks and reinstalls any removed externally by a kernel driver. The watchdog is configurable through `Engine::Config`; contact us about a source license for full config access.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔣 Symbol Resolution

Requires `VH_SYMBOLS_ENABLED`. Uses DbgHelp on Windows and libbacktrace on POSIX.

```cpp
#include <vh/symbols.hpp>

auto sym  = vh::symbols::resolve(address);
auto addr = vh::symbols::find("NtQuerySystemInformation", "ntdll.dll");
auto loc  = vh::symbols::source_location(address);
auto name = vh::symbols::demangle(raw_name);

for (auto& line : vh::symbols::current_stack())
    puts(line.c_str());
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📄 PE Introspection

Zero-copy in-process PE reader. Windows only.

```cpp
#include <vh/pe.hpp>

auto pe = vh::pe::open("target.dll");

for (auto& sec : pe->sections().value_or({}))
    printf("%-8s  VA=0x%llx\n", sec.name.c_str(), sec.virtual_address);

auto exp = pe->find_export("SomeFunction");
auto imp = pe->find_import("kernel32.dll", "VirtualProtect");

for (auto& cave : pe->find_caves(/*min_size=*/32, /*executable_only=*/true))
    printf("[%s] 0x%llx  %zu bytes\n",
        cave.section_name.c_str(), (ull)cave.address, cave.size);

for (auto& m : vh::pe::modules().value_or({}))
    printf("%s  base=0x%llx\n", m.name().data(), (ull)m.base());
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔴 Breakpoints

Software (INT3 / VEH) and hardware (DR0–DR3 / DR7) breakpoints with RAII lifetime management.

```cpp
#include <vh/breakpoint.hpp>

auto sw = vh::breakpoint::set_software(target_address,
    [](uintptr_t addr) { return vh::breakpoint::Action::Continue; });

auto hw = vh::breakpoint::set_hardware(
    target_address,
    vh::breakpoint::HwCondition::Execute,
    vh::breakpoint::HwSize::Byte,
    [](uintptr_t addr) { return vh::breakpoint::Action::Remove; });

hw->apply_to_new_thread(new_thread_handle); // Windows, hardware BPs only
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📚 Call Stack Capture

```cpp
#include <vh/callstack.hpp>

auto frames = vh::callstack::capture(/*skip=*/1, /*max_depth=*/32);
for (auto addr : frames.value_or({}))
    printf("  0x%016llx\n", addr);

// Annotated (requires VH_SYMBOLS_ENABLED)
auto ann = vh::callstack::capture_annotated();
if (ann) printf("%s", vh::callstack::format(*ann).c_str());
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📡 VanTrace — Structured Hook Instrumentation

Lock-free ring buffer tracing with zero heap allocation per event and no synchronous I/O on the hook hot path.

```cpp
#include <vh/trace.hpp>

static vh::Tracer tracer;

auto sink = std::make_shared<vh::CallbackSink>(
    [](const vh::TraceEvent& ev, const vh::TraceMeta* meta) {
        if (ev.kind == vh::TraceEventKind::HookEnter)
            printf("[+] %s  tid=%u  depth=%u  ts=%lldns\n",
                meta ? meta->tag.c_str() : "?",
                ev.thread_id, ev.call_depth,
                ev.timestamp.time_since_epoch().count());
    });

tracer.set_sink(sink);
tracer.start();

auto h = vh::hook("d3d9.dll", "EndScene", &hk_EndScene, &orig_EndScene).value();
static vh::AttachedHook g_trace_hook = tracer.attach(h, "d3d9.EndScene").value();

HRESULT __stdcall hk_EndScene(IDirect3DDevice9* dev) {
    vh::CallScope scope(g_trace_hook);  // HookEnter on construct, HookExit on destruct
    return orig_EndScene(dev);
}
```

### Sinks

| Sink | Description |
|---|---|
| `NullSink` | Discards all events. Default when no sink is set. |
| `CallbackSink` | Delivers each event to a `std::function`. |
| Custom `ISink` | Implement `on_events(span<const Event>, meta_for_fn)` and optionally `flush()`. |

### Filters

```cpp
vh::TraceFilter f;
f.include_handles = { hook_a.handle(), hook_b.handle() };
f.include_kinds   = { vanhooks::HookKind::Trampoline };
f.include_threads = { GetCurrentThreadId() };
f.min_duration    = std::chrono::microseconds(100);
f.sample_every_n  = 10;
tracer.set_filter(f);
```

### Configuration

```cpp
vh::TraceConfig cfg;
cfg.ring_capacity     = 8192;  // must be power of two
cfg.overflow_policy   = vanhooks::trace::OverflowPolicy::BlockNewer;
cfg.enable_timing     = true;
cfg.enable_thread_id  = true;
cfg.enable_call_depth = true;

vh::Tracer tracer(cfg);
```

### Raw context capture

```cpp
HRESULT __stdcall hk_CreateBuffer(ID3D11Device* dev, D3D11_BUFFER_DESC* desc, ...) {
    g_trace_hook.capture_context(desc, sizeof(*desc));
    vh::CallScope scope(g_trace_hook);
    return orig_CreateBuffer(dev, desc, ...);
}
```

### Event fields

| Field | Type | Description |
|---|---|---|
| `kind` | `TraceEventKind` | `HookEnter`, `HookExit`, or `TraceDropped` |
| `hook_kind` | `HookKind` | Trampoline / IAT / PLT / VTable / Mid / CallSite |
| `hook_id` | `uint64_t` | Stable identifier matching `HookHandle::id` |
| `thread_id` | `uint32_t` | OS thread ID at event time |
| `timestamp` | `TimePoint` | Monotonic clock point when event was produced |
| `duration` | `Duration` | `HookExit` only: nanoseconds between enter and exit |
| `call_depth` | `uint32_t` | Thread-local nesting depth at event time |
| `has_context` | `bool` | Whether `context` is populated |
| `context` | `RawContext` | Up to 64 bytes captured via `capture_context()` |
| `dropped_count` | `uint64_t` | `TraceDropped` only: events lost since last delivery |

### Statistics

```cpp
auto s = tracer.stats();
printf("produced=%llu  consumed=%llu  dropped=%llu  overflows=%llu\n",
    s.events_produced, s.events_consumed, s.events_dropped, s.buffer_overflows);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🌐 VanNet — Built-in Network Layer

Live packet capture and protocol parsing. Requires Npcap (Windows) / libpcap (POSIX).

```cpp
#include <vh/net.hpp>

// Live capture
auto cap = vh::net::Capture::open("eth0").value();
cap.filter("tcp port 443").promiscuous(true);
cap.start([](vh::net::Packet pkt) {
    auto parsed = pkt.parse();
    if (auto* ip = parsed->getLayerOfType<vanhooks::net::IPv4Layer>())
        printf("%s → %s\n",
            ip->getSrcIPAddress().toString().c_str(),
            ip->getDstIPAddress().toString().c_str());
});

// Offline pcap / pcapng
auto reader = vh::net::PcapReader::open("capture.pcapng").value();
while (auto pkt = reader.next()) { /* ... */ }

auto writer = vh::net::PcapWriter::open("out.pcap").value();
writer.write(*pkt);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ❓ FAQ

**Does VanHooks work with MinGW i686 cross-compilation?**
Yes. Windows x86 and x64 targets build cleanly under MinGW with static linking.

**Will the watchdog fight with kernel-mode anti-cheat?**
The watchdog detects user-mode patch removal by reading bytes. Kernel drivers that use kernel-mode hooks or memory scanning operate below the watchdog's visibility.

**What happens if all four DR slots are full?**
`set_hardware` returns `Error::BreakpointSlotExhausted`. Remove an existing hardware breakpoint to free a slot.

**Is there a global engine or must I construct one?**
`vanhooks::global_engine()` returns a process-wide singleton accessible through the public API. Custom `Engine` instances with full `Config` control (independent trampoline pools, custom allocators, per-subsystem watchdog settings) are available via a source license.

**Can I use VanHooks inside a DLL injected via ManualMap?**
Yes — VanHooks does not rely on `DllMain` or the loader lock internally.

**Does VanTrace allocate on the hook hot path?**
No. Events are fixed-size structs written into a pre-allocated ring buffer. `capture_context()` writes into thread-local storage — no heap involved.

**Can I have multiple Tracer instances?**
Yes. Each `vh::Tracer` owns an independent ring buffer, consumer thread, sink, and filter. There is no shared state between instances.

**What's the difference between `vh::hook(uintptr_t, …)` and `reinterpret_cast`?**
They're equivalent at the machine level. The address-based overloads exist to remove the cast at every call site when working with runtime-resolved or pattern-scanned addresses.

**Can I configure the Engine pool size, allocator, or watchdog interval?**
Full `Engine::Config` control is available via a source license. The precompiled SDK exposes the global engine and all hook operations but does not allow constructing a custom-configured Engine directly.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📖 Documentation

Full API reference, architecture notes, and worked examples are in the **[Functions Guide](VanHooks_Functions_Guide.md)**.

<div align="center">

<sub>Built and maintained by <a href="https://github.com/TsyVM">TsyVM</a> · <a href="https://www.teamvanilla.org/">TeamVanilla</a></sub>

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:8B0000,100:000000&height=80&section=footer"/>

</div>
