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

VanHooks is a production-grade, cross-platform function hooking and instrumentation library for C++23. It provides inline trampoline hooks, import table hooks, procedure linkage table hooks, virtual function table hooks, and mid-function register-context hooks — all through a single unified API backed by `std::expected` error handling and RAII lifetime management.

Beyond hooking, the library ships a complete instrumentation and stealth toolkit: a structured runtime tracing layer (**VanTrace**), a pattern scanner, disassembler, PE introspector (sections, exports, imports, code cave finder), software and hardware breakpoints, call stack capture, multi-technique anti-debug detection, four-method process injector, an integrity watchdog, and user-mode ETW/AMSI suppression — all enabled by default with **zero external dependencies beyond Zydis**. A built-in network layer (**VanNet**, for live packet capture and protocol parsing) ships alongside the core and is on by default when Npcap / libpcap is present. An optional symbol resolution layer can be enabled when needed. Every feature uses the same `Result<T>` error model and the same `#include <vh/vh.hpp>` entry point.

<div align="center">

### 📑 Table of Contents

[Why VanHooks](#-why-vanhooks) · [Features](#-features-at-a-glance) · [Requirements](#️-requirements) · [Installation](#-installation) · [Quick Start](#-quick-start) · [Hook Types](#-hook-types) · [Lifetime & RAII](#️-hook-lifetime-and-raii) · [Groups](#️-groups--batch-lifecycle-management) · [Chaining](#-hook-chaining) · [Error Handling](#-error-handling) · [HookRegistry](#-multi-module-projects--hookregistry) · [Scanner](#-pattern-scanner) · [Anti-Debug](#-anti-debug-detection) · [Disassembler](#-disassembler) · [Injection](#-process-injection) · [Stealth](#-stealth-configuration) · [Watchdog](#-integrity-watchdog) · [Symbols](#-symbol-resolution) · [PE Introspection](#-pe-introspection) · [Breakpoints](#-breakpoints) · [Call Stack](#-call-stack-capture) · [VanTrace](#-vantrace--structured-hook-instrumentation) · [VanNet](#-vannet--built-in-network-layer) · [Optional Modules](#️-optional-modules) · [Platform Support](#️-platform-support) · [FAQ](#-faq) · [Docs](#-documentation)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🩸 Why VanHooks?

<div align="center">

| | MinHook | EasyHook | SafetyHook | PolyHook2 | **VanHooks** |
|---|:---:|:---:|:---:|:---:|:---:|
| **Platforms** | Win | Win | Win / Lin | Win | 🔴 **Win / Lin / macOS** |
| **ARM64** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Hook types** | Trampoline | Trampoline + IAT | Trampoline | Trampoline + IAT + VTable | 🔴 **Trampoline + IAT + PLT + VTable + Mid + Return** |
| **Error handling** | C enum | C enum | exceptions | exceptions | 🔴 **`std::expected`** |
| **C++ standard** | C89 API | .NET | C++23 | C++20 | 🔴 **C++23** |
| **macOS lazy pointers** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **RAII hook lifetime** | ✗ | ✗ | ✓ | ✓ | 🔴 **✓** |
| **Batch group operations** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Hook chaining** | ✗ | ✓ | ✗ | ✓ | 🔴 **✓** |
| **Mid-function hooks** | ✗ | ✗ | ✓ | ✗ | 🔴 **✓** |
| **Return-value hooks** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Address-based hook API** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Pattern-scan hook** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (Group::hook_pattern)** |
| **Memory patch helpers** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (patch / nop)** |
| **Structured tracing** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (VanTrace)** |
| **Integrity watchdog** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **ETW / AMSI suppression** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Multi-method injection** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (4 methods)** |
| **Anti-debug detection** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (8 techniques)** |
| **SW + HW breakpoints** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (RAII)** |
| **PE introspection** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Built-in packet capture** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (VanNet)** |
| **Pattern scanner** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (IDA-style + BMH)** |

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ✨ Features at a Glance

- **Six hook types** — Trampoline, IAT (`iat_hook` / `iat_hook_all`), PLT/GOT, VTable, Mid-function, Return (x64)
- **Three-level API** — beginner `vh::hook()`, explicit-type `vh::inline_hook()`, group-based `vh::group()`
- **Address-based hooks** — `vh::hook(uintptr_t, …)` and `vh::inline_hook(uintptr_t, …)` for runtime-resolved addresses; no `reinterpret_cast` at the call site
- **VanTrace** — structured runtime event tracing with a lock-free ring buffer, pluggable sinks, per-event timing, thread IDs, call depth, and raw context capture
- **VanNet** — built-in packet capture and protocol parsing; live device capture, pcapng read/write, and a full layer-2–7 protocol stack
- **Named groups & HookRegistry** — batch enable/disable/remove across DLL boundaries
- **`Group::hook_at()`** — install a trampoline hook from a raw address directly into a group
- **`Group::hook_pattern()`** — scan the process for an IDA-style byte pattern and hook the first match, all in one call
- **`Group::patch<T>()` / `Group::nop()`** — write arbitrary typed values or NOP slides to runtime addresses with automatic page-protection lifting
- **Batch queue** — `queue_enable` / `queue_disable` / `apply_queued` amortises thread-suspension overhead
- **Hook chaining** — stack multiple detours on one target; each sees the previous one's trampoline
- **Integrity watchdog** — background thread detects and reinstalls hooks removed by kernel drivers
- **ETW suppression** — patches `EtwEventWrite` / `EtwEventWriteFull` to silence user-mode telemetry
- **AMSI suppression** — patches `AmsiScanBuffer` / `AmsiScanString` to return clean without scanning
- **Process injection** — four methods (LoadLibrary, ManualMap, ThreadHijack, ApcQueue) with RAII eject
- **Anti-debug detection** — eight independent techniques with a structured per-technique report
- **Software & hardware breakpoints** — RAII lifetime, DR0–DR3, VEH/sigaction, new-thread propagation
- **PE introspection** — sections, exports (by name/ordinal), imports (by module), code cave finder
- **Call stack capture** — raw VAs or annotated frames (with `VH_SYMBOLS_ENABLED`)
- **Pattern scanner** — IDA-style wildcard patterns with Boyer–Moore–Horspool acceleration
- **Disassembler** — Zydis-backed length disassembler and instruction decoder (always available)
- **Symbol resolution** — DbgHelp (Windows) / libbacktrace (POSIX) behind `VH_SYMBOLS_ENABLED`
- **Thread-safe by default** — all hook installs suspend threads; IP fixup handles prologue races on remove
- **`std::expected` throughout** — no exceptions, no raw OS error codes, no hidden failure paths

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🛠️ Requirements

- **Compiler:** GCC 13+, Clang 17+, or MSVC 19.38+ with `/std:c++23`
- **CMake:** 3.25+
- **Zydis:** fetched automatically via CMake FetchContent (v4.1.0)
- **Windows:** x86 / x64 (MinGW i686 cross-compilation supported)
- **Linux:** x64 / ARM64
- **macOS:** x64 / ARM64

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📦 Installation

### CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(vanhooks
    GIT_REPOSITORY https://github.com/tsyvm/vanhooks.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(vanhooks)

target_link_libraries(my_target PRIVATE vanhooks)
```

All core features — including VanTrace, the pattern scanner, anti-debug detection, and VanNet — are compiled in by default. Modules can be turned off explicitly if not needed:

```cmake
# Opt out of specific layers (all ON by default)
set(VH_BUILD_SHARED       OFF)  # build as shared library instead of static
set(VH_ENABLE_NET         OFF)  # VanNet packet capture (requires Npcap/libpcap)
set(VH_ENABLE_SCANNER     OFF)  # pattern scanner
set(VH_ENABLE_ANTIDEBUG   OFF)  # anti-debug detection
set(VH_ENABLE_TRACE       OFF)  # VanTrace structured hook instrumentation
set(VH_ENABLE_INJECT      OFF)  # process injection
set(VH_ENABLE_SYMBOLS     OFF)  # symbol resolution (DbgHelp / libbacktrace)
set(VH_SYMBOLS_BACKTRACE  OFF)  # use libbacktrace for DWARF line info on POSIX
set(VH_ENABLE_PE          OFF)  # PE introspection
set(VH_ENABLE_BREAKPOINT  OFF)  # software + hardware breakpoints
set(VH_ENABLE_CALLSTACK   OFF)  # call stack capture
```

### Single include

```cpp
#include <vh/vh.hpp>  // everything you need
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ⚡ Quick Start

```cpp
#include <vh/vh.hpp>

static int (WINAPI* orig_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = nullptr;

int WINAPI hk_MessageBoxA(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    caption = "VanHooks";
    return orig_MessageBoxA(hwnd, text, caption, type);
}

void setup() {
    // Level 1 — simplest path (function pointer target)
    auto hook = vh::hook(&MessageBoxA, &hk_MessageBoxA, &orig_MessageBoxA);
    if (!hook) {
        // hook.error() is a vanhooks::Error enum value
    }

    // Level 1 — runtime address target (no reinterpret_cast needed)
    auto hook2 = vh::hook(0x5D5DB0u, &hk_MessageBoxA, &orig_MessageBoxA);

    // hook goes out of scope → MessageBoxA automatically restored
}
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🎣 Hook Types

VanHooks exposes six distinct hook mechanisms, all returning `Result<Hook>` or `Result<HookHandle>`.

### Trampoline (Inline)

Patches the target function's prologue with a jump to your detour. The original instructions are relocated into a trampoline stub, allowing you to call through to the original.

```cpp
// Function-pointer target
auto h = vh::inline_hook(&target_fn, &my_detour, &orig_fn);

// Runtime address target
auto h2 = vh::inline_hook(0x5D5DB0u, &my_detour, &orig_fn);
```

On **x86** a 5-byte rel32 JMP is always used. On **x64** a 14-byte `FF 25` indirect is used when the target is outside ±2 GB (no register clobber). On **ARM64** a 4-byte `B` (±128 MB) or a 20-byte `MOVZ/MOVK/BR` sequence.

### API Hook (by name)

Resolves a symbol at runtime via `GetProcAddress` / `dlsym`, then installs a trampoline.

```cpp
auto h = vh::hook("user32.dll", "MessageBoxA", &hk_MessageBoxA, &orig_MessageBoxA);
```

### IAT Hook

Patches the Import Address Table slot in a specific module (or every module that imports it).

```cpp
// Single module
auto h = vh::iat_hook("VirtualAlloc", &hk_VAlloc,
                      { .module_name = "my.dll" });

// Every loaded module that imports this symbol
auto hs = vh::iat_hook_all("VirtualAlloc", &hk_VAlloc);
```

### PLT / GOT Hook (Linux / macOS)

Redirects the Procedure Linkage Table / Global Offset Table entry for a shared library symbol.

```cpp
auto h = vh::plt_hook("libc.so.6", "malloc", &hk_malloc);
```

### VTable Hook

Patches a single slot in a C++ virtual dispatch table.

```cpp
void** vtbl = *reinterpret_cast<void***>(object_ptr);
auto h = vh::vtable_hook(vtbl, /*slot=*/3, &hk_Render);
```

### Mid-Function Hook

Installs a hook at a byte offset inside a function. A `MidContext*` is passed to your callback with a full GPR + flags snapshot; the original instructions still execute after the callback returns. Mid hooks observe or modify register state — they do not redirect control flow.

```cpp
auto h = vh::mid_hook(&target_fn,
    [](vanhooks::MidContext* ctx) noexcept {
        ctx->rax = 0; // zero out a register at this program point
    },
    { .offset = 0x2A });
```

**`MidContext` fields (x64):** `rax`…`r15`, `rflags` — all `uint64_t`. Writes take effect when the callback returns.

**`MidContext` fields (x86):** `eax`…`edi`, `eflags` — all `uint32_t`.

**`MidContext` fields (ARM64):** `x[0]`…`x[7]`, `lr` — all `uint64_t`.

### Return Hook (x64 only)

`hook_mid_return()` captures the function's return value and lets you modify it before the caller sees it. Internally installs an entry thunk and a shared return stub — both tracked under one `HookHandle`.

```cpp
// Via the raw Engine (power-user path)
auto& eng = vanhooks::global_engine();
auto h = eng.hook_mid_return(
    &target_fn,
    /*byte_offset=*/0,
    /*enter_cb=*/nullptr,        // optional; same as hook_mid entry callback
    [](vanhooks::ReturnContext* ctx) noexcept {
        ctx->retval_rax = 42;   // override integer return value
    });
```

**`ReturnContext` fields (x64):** `retval_rax`, `retval_rdx`, `retval_xmm0`, `hook_id`, `real_ret_addr`.

Returns `Error::Unsupported` on ARM64 and x86.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ♻️ Hook Lifetime and RAII

Every `vh::Hook` object owns its installation. When it goes out of scope the hook is automatically removed and the original bytes are restored — no manual cleanup required.

```cpp
{
    auto h = vh::hook(&target, &detour, &orig);
    // hook active
} // hook removed here automatically

// Explicit control
if (auto r = h.enable();  !r) { /* handle error */ }
if (auto r = h.disable(); !r) { /* handle error */ }
h.remove(); // idempotent — safe to call multiple times
```

`enable()` and `disable()` return `Result<std::reference_wrapper<Hook>>` — check them or chain with `.and_then()`.

`h.valid()` is false after removal. `h.tag()` returns the optional string label attached at install time. `h.handle()` gives the raw `HookHandle` for use with the Engine API directly.

### Thread Safety & IP Fixup

When `thread_safe = true` (the default), VanHooks suspends all threads in the process during the patch window and uses `ip_fixup_on_remove` to advance any thread whose instruction pointer landed inside the stolen prologue bytes, so removing a hook under live traffic never leaves a thread in an inconsistent state.

```cpp
vanhooks::TrampolineOptions opts;
opts.thread_safe = false; // disable if you own all threads
opts.tag = "my_hook";
auto h = vh::inline_hook(&target, &detour, &orig, { .thread_safe = false, .tag = "my_hook" });
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🗂️ Groups & Batch Lifecycle Management

`vh::Group` is a named RAII container that owns a set of hooks and lets you enable, disable, or remove them all in a single atomic thread-suspension window. Groups also expose helpers for address-based hooking, memory patching, and pattern-scanning that cover the most common runtime patterns without requiring per-call error handling.

```cpp
auto grp = vh::group("render_hooks");
grp.add(vh::hook(&fn_a, &hk_a, &orig_a))
   .add(vh::hook(&fn_b, &hk_b, &orig_b))
   .add(vh::hook(&fn_c, &hk_c, &orig_c));

grp.enable();   // one suspension window — all three enabled atomically
grp.disable();  // same
// grp destructor calls remove_all() automatically
```

### Address-based install

```cpp
// Install a trampoline from a raw runtime address
grp.hook_at(0x5D5DB0u, &MyDetour, &orig_fn);
grp.hook_at(addr, &MyDetour, nullptr, { .tag = "my_hook" });
```

### Pattern-scan hook

```cpp
// Scan the process for a byte pattern, offset to the target instruction, hook it
grp.hook_pattern("E8 ? ? ? ? 83 C4 04", -5, &MyDetour);
grp.hook_pattern("48 8B 05 ? ? ? ?",     0,  &MyDetour, &orig_fn);
```

Only the first match is hooked. If the pattern is not found the call is a no-op.

### Memory patch helpers

```cpp
// Write a typed value to an address (lifts page protection automatically)
grp.patch<uint8_t>(0x581E72, 32);
grp.patch<float>(0x5D88D1 + 6, 0.25f);

// Fill a range with NOP (0x90) bytes
grp.nop(0x14E738B, 2);
```

### Tagged lookup

```cpp
auto res = grp.at("shadow_hook");
if (res) res->get().disable();
```

`at()` returns `Result<std::reference_wrapper<Hook>>` — `HookNotFound` if the tag isn't present.

### Batch Queue API

For finer control, queue operations and flush them in one window across group boundaries:

```cpp
auto& eng = vanhooks::global_engine();
eng.queue_enable(h1);
eng.queue_enable(h2);
eng.queue_disable(h3);
eng.apply_queued(); // single thread-suspension, all patches applied atomically
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔗 Hook Chaining

Chain additional detours onto an already-hooked target. Each link in the chain receives the previous detour's trampoline as its "original", forming a singly-linked list:

```
target → detour_N → ... → detour_1 → original
```

```cpp
auto base = vh::hook(&fn, &first_detour, &orig_fn);
auto link = base->chain(&second_detour, &orig_for_second);
// Remove link before base — ChainOrderViolation is returned otherwise
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ❌ Error Handling

Every VanHooks function returns `Result<T>` — a `std::expected<T, vanhooks::Error>`. No exceptions are thrown anywhere in the library.

```cpp
auto result = vh::hook(&target, &detour, &orig);
if (!result) {
    switch (result.error()) {
        case vanhooks::Error::HookAlreadyExists:   /* ... */ break;
        case vanhooks::Error::MemoryProtectFailed: /* ... */ break;
        default:
            printf("error: %s\n", vanhooks::error_to_string(result.error()).data());
    }
}

// Or with monadic chaining (C++23)
vh::hook(&target, &detour, &orig)
    .and_then([](vh::Hook h) -> Result<void> { /* use h */ return {}; })
    .or_else([](vanhooks::Error e) -> Result<void> { /* log e */ return {}; });
```

Notable error codes:

| Code | Meaning |
|---|---|
| `ThreadInPrologue` | A thread's IP was inside the stolen bytes during a remove; IP fixup resolved it |
| `BreakpointSlotExhausted` | All four DR0–DR3 hardware slots are in use |
| `ChainOrderViolation` | A chain link was removed before its base hook |
| `TrampolineNoSpace` | Trampoline pool slab exhausted — increase `trampoline_pool_size` in `Config` |
| `ModuleNotFound` | `GetModuleHandle` / `dlopen` found no matching module |
| `SymbolNotFound` | Symbol name not found in debug info |
| `QueueEmpty` | `apply_queued()` called with nothing in the queue |
| `ChainBaseNotFound` | Base `HookHandle` passed to `chain()` is unknown to the engine |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🗃️ Multi-Module Projects — HookRegistry

`vh::HookRegistry` is a process-wide singleton that lets code in separate DLLs register and look up named groups.

```cpp
// In module A
auto grp = vh::group("input_hooks");
grp.add(vh::hook(&fn1, &hk1));
vh::HookRegistry::global().register_group(std::move(grp));

// In module B
if (auto* g = vh::HookRegistry::global().find_group("input_hooks"))
    g->disable();

// Global operations across all registered groups
vh::HookRegistry::global().enable_all();
vh::HookRegistry::global().disable_all();
vh::HookRegistry::global().remove_all();

// Total hook count across all groups
size_t n = vh::HookRegistry::global().total_hook_count();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔍 Pattern Scanner

Scans a memory region for a byte pattern using IDA-style wildcard syntax, accelerated with Boyer–Moore–Horspool.

```cpp
#include <vh/vh.hpp>

// Scan the entire process
auto result = vanhooks::scanner::scan_process("48 8B 05 ? ? ? ? 48 85 C0");
if (result && !result->empty()) {
    uintptr_t addr = (*result)[0];
}

// Scan a named module
auto r2 = vanhooks::scanner::scan_module("game.exe", "E8 ? ? ? ? 85 C0 74");

// Scan an explicit range
auto r3 = vanhooks::scanner::scan_pattern(base_ptr, size, "48 8B 05 ? ? ? ?");

// Pre-compile a pattern for repeated use
auto pat = vanhooks::scanner::parse_pattern("48 8B 05 ? ? ? ?").value();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🐛 Anti-Debug Detection

`vanhooks::antidebug::check_all()` runs eight independent detection techniques and returns a structured `Report` with per-technique `Finding` records.

```cpp
auto report = vanhooks::antidebug::check_all();

if (report.any_detected()) {
    printf("%d technique(s) detected a debugger\n", report.detection_count());
}

for (auto& f : report.findings) {
    printf("[%s] %-45s %s\n",
        f.detected ? "DETECTED" : "clean   ",
        f.technique.c_str(),
        f.detail.c_str());
}
```

### Techniques (Windows)

| # | Technique | Method |
|---|---|---|
| 1 | `IsDebuggerPresent` | Reads `PEB.BeingDebugged` |
| 2 | `CheckRemoteDebuggerPresent` | Cross-process debugger handle check |
| 3 | `NtQueryInformationProcess(DebugPort)` | `ProcessDebugPort` via ntdll |
| 4 | `HeapFlags` | Reads heap `Flags` / `ForceFlags` from PEB (x86 and x64 offsets) |
| 5 | `NtGlobalFlag` | Checks bits `0x70` in `PEB.NtGlobalFlag` |
| 6 | `CloseHandle(invalid)` | Raises `EXCEPTION_INVALID_HANDLE` under a debugger |
| 7 | `TimingCheck` | Measures loop duration — >50 ms threshold is suspicious |
| 8 | `DebuggerProcessList` | Snapshots running processes and matches known tool names (x64dbg, OllyDbg, IDA, Cheat Engine, Wireshark, etc.) |

On **Linux** a `ptrace(PTRACE_TRACEME)` check is performed instead.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔬 Disassembler

A Zydis-backed length disassembler and full instruction decoder, always available without any optional flag.

```cpp
#include <vh/disasm.hpp>

vh::disasm::Disassembler dis;

// Decode one instruction
auto insn = dis.decode_one(code_span, runtime_address);
if (insn) printf("%s  (%u bytes)\n", insn->mnemonic.c_str(), insn->length);

// Decode until first branch / terminal instruction
auto insns = vh::disasm::decode_until_branch(fn_ptr, 128);

// Decode at least N bytes (safe trampoline copy length)
auto prologue = vh::disasm::decode_prologue(fn_ptr, 14);

// Rewrite RIP-relative references after relocating to a new address
auto rr = vh::disasm::rewrite(insns, original_va, new_va);

// Human-readable listing
printf("%s", vh::disasm::format_listing(insns).c_str());
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 💉 Process Injection

Four injection methods are available, each with distinct stealth and compatibility trade-offs.

```cpp
#include <vh/inject.hpp>

// Inject by path
auto inj = vh::inject(pid, "C:\\path\\to\\payload.dll",
                      { .method = vh::InjectMethod::ManualMap });

// Inject from in-memory PE bytes (no file on disk required)
auto inj2 = vh::inject_from_memory(pid, pe_bytes,
                                    { .method = vh::InjectMethod::ThreadHijack });

// RAII — eject when Injection goes out of scope, or explicitly:
if (auto r = inj->eject(); !r) { /* handle error */ }

// Free-function form
vh::eject(*inj2);
```

### Method Comparison

| Method | Module-list entry | Remote thread created | Stealth |
|---|:---:|:---:|:---:|
| `LoadLibrary` | ✓ (visible) | ✓ | Low |
| `ManualMap` | ✗ | ✓ (shellcode) | Medium |
| `ThreadHijack` | Configurable | ✗ | High |
| `ApcQueue` | Configurable | ✗ | High |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🥷 Stealth Configuration

```cpp
vanhooks::Engine::Config cfg;
cfg.suppress_etw  = true;   // patches EtwEventWrite / EtwEventWriteFull
cfg.suppress_amsi = true;   // patches AmsiScanBuffer / AmsiScanString
cfg.enable_integrity_watchdog = true;

vanhooks::Engine eng(cfg);
```

> **Note:** ETW and AMSI suppression are user-mode Tier 3 measures. They have no effect on HVCI / VBS-protected systems.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🐕 Integrity Watchdog

Background thread that polls all installed hooks and reinstalls any removed externally by a kernel driver.

```cpp
vanhooks::Engine::Config cfg;
cfg.enable_integrity_watchdog = true;
cfg.watchdog_interval_ms      = 250;

vanhooks::Engine eng(cfg);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔣 Symbol Resolution

Requires `VH_SYMBOLS_ENABLED`. Uses DbgHelp on Windows and libbacktrace on POSIX.

```cpp
#include <vh/symbols.hpp>

// Resolve an address to its symbol
auto sym = vh::symbols::resolve(address);
if (sym) printf("%s + 0x%zx  [%s]\n",
    sym->name.c_str(), address - sym->address, sym->module.c_str());

// Find a symbol's address by name
auto addr = vh::symbols::find("NtQuerySystemInformation", "ntdll.dll");

// Source file + line number
auto loc = vh::symbols::source_location(address);

// Capture and print the current call stack
for (auto& line : vh::symbols::current_stack())
    puts(line.c_str());

// Demangle a C++ symbol name
auto name = vh::symbols::demangle(raw_name);
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

// Enumerate all loaded modules
for (auto& m : vh::pe::modules().value_or({}))
    printf("%s  base=0x%llx\n", m.name().data(), (ull)m.base());
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔴 Breakpoints

Software (INT3 / VEH) and hardware (DR0–DR3 / DR7) breakpoints with full RAII lifetime management.

```cpp
#include <vh/breakpoint.hpp>

auto sw = vh::breakpoint::set_software(target_address,
    [](uintptr_t addr) {
        return vh::breakpoint::Action::Continue;
    });

auto hw = vh::breakpoint::set_hardware(
    target_address,
    vh::breakpoint::HwCondition::Execute,
    vh::breakpoint::HwSize::Byte,
    [](uintptr_t addr) {
        return vh::breakpoint::Action::Remove;
    });

// Propagate to a new thread (Windows, hardware BPs only)
hw->apply_to_new_thread(new_thread_handle);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📚 Call Stack Capture

```cpp
#include <vh/callstack.hpp>

// Raw addresses
auto frames = vh::callstack::capture(/*skip=*/1, /*max_depth=*/32);
for (auto addr : frames.value_or({}))
    printf("  0x%016llx\n", addr);

// Annotated (requires VH_SYMBOLS_ENABLED)
auto ann = vh::callstack::capture_annotated();
if (ann) printf("%s", vh::callstack::format(*ann).c_str());
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📡 VanTrace — Structured Hook Instrumentation

VanTrace is VanHooks' built-in structured tracing layer. It records hook enter/exit events into a lock-free ring buffer, drains them on a background consumer thread, and delivers them to any `ISink` implementation — with zero heap allocation per event and no synchronous I/O on the hook hot path.

```cpp
#include <vh/trace.hpp>   // or <vh/vh.hpp> with VH_TRACE_ENABLED
```

### Quick start

```cpp
// 1. Create a tracer
static vh::Tracer tracer;

// 2. Install a sink
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

// 3. Attach a hook — tag_override is optional
auto h = vh::hook("d3d9.dll", "EndScene", &hk_EndScene, &orig_EndScene).value();
static vh::AttachedHook g_trace_hook = tracer.attach(h, "d3d9.EndScene").value();

// 4. Inside your detour — RAII scope records enter + exit
HRESULT __stdcall hk_EndScene(IDirect3DDevice9* dev) {
    vh::CallScope scope(g_trace_hook);   // HookEnter recorded here
    return orig_EndScene(dev);           // HookExit recorded on scope exit
}
```

### Sinks

| Sink | Description |
|---|---|
| `NullSink` | Discards all events. Default when no sink is set. |
| `CallbackSink` | Delivers each event to a `std::function<void(const Event&, const HookMeta*)>`. |
| Custom `ISink` | Implement `on_events(span<const Event>, meta_for_fn)` and optionally `flush()`. |

```cpp
class FileSink : public vh::ISink {
public:
    explicit FileSink(const char* path) : f_(fopen(path, "wb")) {}
    ~FileSink() { if (f_) fclose(f_); }

    void on_events(std::span<const vh::TraceEvent> events,
                   const std::function<const vh::TraceMeta*(uint64_t)>& meta_for) override
    {
        for (const auto& ev : events) {
            auto* m = meta_for(ev.hook_id);
            fprintf(f_, "%s %s %u\n",
                ev.kind == vh::TraceEventKind::HookEnter ? "ENTER" : "EXIT",
                m ? m->tag.c_str() : "?",
                ev.thread_id);
        }
    }

    void flush() override { if (f_) fflush(f_); }
private:
    FILE* f_;
};

tracer.set_sink(std::make_shared<FileSink>("trace.log"));
```

### Filters

Pre-buffer predicates that gate which events enter the ring at all:

```cpp
vh::TraceFilter f;
f.include_handles  = { hook_a.handle(), hook_b.handle() }; // only these hooks
f.include_kinds    = { vanhooks::HookKind::Trampoline };   // only trampoline hooks
f.include_threads  = { GetCurrentThreadId() };             // only this thread
f.min_duration     = std::chrono::microseconds(100);       // exits >=100 µs only
f.sample_every_n   = 10;                                   // every 10th call

tracer.set_filter(f);
```

### Configuration

```cpp
vanhooks::trace::TracerConfig cfg;
cfg.ring_capacity    = 8192;                              // must be power of two
cfg.overflow_policy  = vanhooks::trace::OverflowPolicy::BlockNewer; // or DropOldest
cfg.enable_timing    = true;
cfg.enable_thread_id = true;
cfg.enable_call_depth = true;

vh::Tracer tracer(cfg);
```

### Raw context capture

Attach up to 64 bytes of arbitrary data to the next enter event from the calling thread:

```cpp
HRESULT __stdcall hk_CreateBuffer(ID3D11Device* dev,
                                   D3D11_BUFFER_DESC* desc, ...)
{
    g_trace_hook.capture_context(desc, sizeof(*desc));
    vh::CallScope scope(g_trace_hook);
    return orig_CreateBuffer(dev, desc, ...);
}
// ev.has_context == true; ev.context.data holds the raw bytes
```

### Statistics

```cpp
auto s = tracer.stats();
printf("produced=%llu  consumed=%llu  dropped=%llu  overflows=%llu\n",
       s.events_produced, s.events_consumed,
       s.events_dropped,  s.buffer_overflows);
```

### Event fields

| Field | Type | Description |
|---|---|---|
| `kind` | `TraceEventKind` | `HookEnter`, `HookExit`, or `TraceDropped` |
| `hook_kind` | `HookKind` | Trampoline / IAT / PLT / VTable / Mid |
| `hook_id` | `uint64_t` | Stable hook identifier (matches `HookHandle::id`) |
| `thread_id` | `uint32_t` | OS thread ID at event time |
| `timestamp` | `TimePoint` | Monotonic clock point when event was produced |
| `duration` | `Duration` | `HookExit` only: nanoseconds between enter and exit |
| `call_depth` | `uint32_t` | Thread-local nesting depth at event time |
| `has_context` | `bool` | Whether `context` is populated |
| `context` | `RawContext` | Up to 64 bytes captured via `capture_context()` |
| `dropped_count` | `uint64_t` | `TraceDropped` only: events lost since last delivery |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🌐 VanNet — Built-in Network Layer

VanNet is VanHooks' built-in packet capture and protocol parsing layer. It ships alongside the core and is compiled in by default when Npcap / libpcap is present on the host. Disable with `VH_ENABLE_NET=OFF` if it is not needed.

```cpp
#include <vh/net.hpp>

// Live capture
auto cap = vh::net::Capture::open("eth0").value();
cap.filter("tcp port 443").promiscuous(true);
cap.start([](vh::net::Packet pkt) {
    auto parsed = pkt.parse();
    if (auto* ip = parsed->getLayerOfType<vanhooks::net::IPv4Layer>()) {
        printf("%s → %s\n",
            ip->getSrcIPAddress().toString().c_str(),
            ip->getDstIPAddress().toString().c_str());
    }
});

// Offline pcap/pcapng
auto reader = vh::net::PcapReader::open("capture.pcapng").value();
while (auto pkt = reader.next()) { /* ... */ }

// Write packets
auto writer = vh::net::PcapWriter::open("out.pcap").value();
writer.write(*pkt);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🖥️ Platform Support

| Feature | Windows x86 | Windows x64 | Linux x64 | Linux ARM64 | macOS x64 | macOS ARM64 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Trampoline hook | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| IAT hook | ✓ | ✓ | — | — | — | — |
| PLT / GOT hook | — | — | ✓ | ✓ | ✓ | ✓ |
| macOS lazy pointer hook | — | — | — | — | ✓ | ✓ |
| VTable hook | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Mid-function hook | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Return hook (`hook_mid_return`) | ✓ | ✓ | — | — | — | — |
| VanTrace | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Software breakpoints | ✓ | ✓ | ✓ | — | ✓ | — |
| Hardware breakpoints (DR) | ✓ | ✓ | ✓ | — | stub | stub |
| Anti-debug (full suite) | ✓ | ✓ | ptrace | ptrace | — | — |
| ETW / AMSI suppression | ✓ | ✓ | — | — | — | — |
| Process injection | ✓ | ✓ | — | — | — | — |
| Integrity watchdog | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| MinGW cross-compile | ✓ | ✓ | — | — | — | — |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ❓ FAQ

**Does VanHooks work with MinGW i686 cross-compilation?**
Yes. Windows x86 and x64 targets build cleanly under MinGW with static linking. All Windows-specific code guards against MSVC intrinsics that MinGW does not provide.

**Will the watchdog fight with kernel-mode anti-cheat?**
The watchdog detects *user-mode* patch removal by reading bytes. Kernel drivers that use kernel-mode hooks or memory scanning operate below the watchdog's visibility.

**What happens if all four DR slots are full?**
`set_hardware` returns `Error::BreakpointSlotExhausted`. Remove an existing hardware breakpoint to free a slot.

**Is there a global engine or must I construct one?**
`vanhooks::global_engine()` returns a default-constructed process-wide singleton. You can also construct your own `Engine` instances with custom `Config` for isolated trampoline pools or per-subsystem watchdog settings.

**Can I use VanHooks inside a DLL injected via ManualMap?**
Yes — VanHooks does not rely on `DllMain` or the loader lock internally.

**Does VanTrace allocate on the hook hot path?**
No. Events are fixed-size structs written into a pre-allocated ring buffer. The only allocation is at `Tracer` construction time (the ring buffer vector). `capture_context()` writes into thread-local storage — no heap involved.

**Can I have multiple Tracer instances?**
Yes. Each `vh::Tracer` owns an independent ring buffer, consumer thread, sink, and filter. There is no shared state between instances.

**What's the difference between `vh::hook(uintptr_t, …)` and `reinterpret_cast`?**
They're equivalent at the machine level. The address-based overloads exist purely to remove the cast at every call site when working with runtime-resolved or pattern-scanned addresses — a common pattern in game modding and RE work.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📖 Documentation

Full API reference, architecture notes, and worked examples are in the [Functions Guide](VanHooks_Functions_Guide.md).
