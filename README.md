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
| **Hook types** | Trampoline | Trampoline + IAT | Trampoline | Trampoline + IAT + VTable | 🔴 **Trampoline + IAT + PLT + VTable + Mid** |
| **Error handling** | C enum | C enum | exceptions | exceptions | 🔴 **`std::expected`** |
| **C++ standard** | C89 API | .NET | C++23 | C++20 | 🔴 **C++23** |
| **macOS lazy pointers** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **RAII hook lifetime** | ✗ | ✗ | ✓ | ✓ | 🔴 **✓** |
| **Batch group operations** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓** |
| **Hook chaining** | ✗ | ✓ | ✗ | ✓ | 🔴 **✓** |
| **Mid-function hooks** | ✗ | ✗ | ✓ | ✗ | 🔴 **✓** |
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

- **Five hook types** — Trampoline, IAT (`hook_iat` / `hook_iat_all`), PLT/GOT, VTable, Mid-function
- **Three-level API** — beginner `vh::hook()`, fluent `vh::inline_hook()`, advanced `vh::Engine`
- **VanTrace** — structured runtime event tracing with a lock-free ring buffer, pluggable sinks, cooperative and transparent attach modes, per-event timing, thread IDs, call depth, and raw context capture
- **VanNet** — built-in packet capture and protocol parsing; live device capture, pcapng read/write, and a full layer-2–7 protocol stack
- **Named groups & HookRegistry** — batch enable/disable/remove across DLL boundaries
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
- **Zydis:** fetched automatically via CMake FetchContent
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

All core features — including VanTrace and VanNet — are compiled in by default. The few modules below that carry heavier system dependencies can be turned off explicitly if not needed:

```cmake
# Opt out of specific layers (all on by default)
set(VH_ENABLE_NET         OFF)  # VanNet packet capture (requires Npcap/libpcap)
set(VH_ENABLE_TRACE       OFF)  # VanTrace structured hook instrumentation
set(VH_ENABLE_INJECT      OFF)  # Process injection
set(VH_ENABLE_SYMBOLS     OFF)  # Symbol resolution (DbgHelp / libbacktrace)
set(VH_ENABLE_PE          OFF)  # PE introspection
set(VH_ENABLE_BREAKPOINT  OFF)  # Software + hardware breakpoints
set(VH_ENABLE_CALLSTACK   OFF)  # Call stack capture
```

### Single include

```cpp
#include <vh/vh.hpp>  // everything you need
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ⚡ Quick Start

```cpp
#include <vh/vh.hpp>

// Original function signature
static int (WINAPI* orig_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = nullptr;

int WINAPI hk_MessageBoxA(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    caption = "VanHooks";
    return orig_MessageBoxA(hwnd, text, caption, type);
}

void setup() {
    // Level 1 — simplest path
    auto hook = vh::hook(&MessageBoxA, &hk_MessageBoxA, &orig_MessageBoxA);
    if (!hook) {
        // hook.error() is a vanhooks::Error enum value
    }
    // hook goes out of scope → MessageBoxA automatically restored
}
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🎣 Hook Types

VanHooks exposes five distinct hook mechanisms, all returning `Result<Hook>` or `Result<HookHandle>`.

### Trampoline (Inline)

Patches the target function's prologue with a jump to your detour. The original instructions are relocated into a trampoline stub, allowing you to call through to the original.

```cpp
auto h = vh::inline_hook(&target_fn, &my_detour, &orig_fn);
```

On **x86** a 5-byte rel32 JMP is always used. On **x64** a 14-byte `FF 25` indirect is used when the target is outside ±2 GB (no register clobber). On **ARM64** a 4-byte `B` (±128 MB) or a 20-byte `MOVZ/MOVK/BR` sequence.

### API Hook (by name)

Resolves a symbol at runtime via `GetProcAddress` / `dlsym`, then installs a trampoline. Equivalent to MinHook's `MH_CreateHookApiEx`.

```cpp
auto h = vh::hook("user32.dll", "MessageBoxA", &hk_MessageBoxA, &orig_MessageBoxA);
```

### IAT Hook

Patches the Import Address Table slot in a specific module (or every module that imports it).

```cpp
// Single module
auto h = vh::iat_hook("my.dll", "kernel32.dll", "VirtualAlloc", &hk_VAlloc);

// Every loaded module that imports this symbol
auto hs = vh::iat_hook_all("kernel32.dll", "VirtualAlloc", &hk_VAlloc);
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

Installs a hook at a byte offset inside a function. The patch site is rounded up to the nearest complete instruction boundary. A `MidContext*` is passed to your callback with a full GPR + flags snapshot; the original instructions still execute after the callback returns. Mid hooks observe or modify register state — they do not redirect control flow.

```cpp
auto h = vh::mid_hook(&target_fn, /*byte_offset=*/0x2A,
    [](vanhooks::MidContext* ctx) noexcept {
        ctx->rax = 0; // zero out the return value at this program point
    });
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ♻️ Hook Lifetime and RAII

Every `vh::Hook` object owns its installation. When it goes out of scope the hook is automatically removed and the original bytes are restored — no manual cleanup required.

```cpp
{
    auto h = vh::hook(&target, &detour, &orig);
    // hook active
} // hook removed here automatically

// Explicit control
h.enable();
h.disable();
h.remove(); // idempotent — safe to call multiple times
```

`h.valid()` is false after removal. `h.tag()` returns the optional string label attached at install time. `h.handle()` gives the raw `HookHandle` for use with the Engine API directly.

### Thread Safety & IP Fixup

When `thread_safe = true` (the default), VanHooks suspends all threads in the process during the patch window and uses `ip_fixup_on_remove` to advance any thread whose instruction pointer landed inside the stolen prologue bytes, so removing a hook under live traffic never leaves a thread in an inconsistent state.

```cpp
vanhooks::TrampolineOptions opts;
opts.thread_safe = false; // disable if you own all threads
opts.tag = "my_hook";
auto h = vh::inline_hook(&target, &detour, &orig, opts);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🗂️ Groups & Batch Lifecycle Management

`vh::Group` is a named RAII container that owns a set of hooks and lets you enable, disable, or remove them all in a single atomic thread-suspension window.

```cpp
auto grp = vh::Group("render_hooks");
grp.add(vh::hook(&fn_a, &hk_a, &orig_a))
   .add(vh::hook(&fn_b, &hk_b, &orig_b))
   .add(vh::hook(&fn_c, &hk_c, &orig_c));

grp.enable();   // one suspension window — all three enabled atomically
grp.disable();  // same
// grp destructor calls remove_all() automatically
```

Tags let you retrieve individual hooks by name:

```cpp
grp.at("shadow_hook").disable();
```

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
auto link = vh::Engine::chain(base.handle(), &second_detour, &orig_for_second);
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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🗃️ Multi-Module Projects — HookRegistry

`vh::HookRegistry` is a process-wide singleton that lets code in separate DLLs register and look up named groups.

```cpp
// In module A
auto grp = vh::Group("input_hooks");
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

// IDA-style: '?' is a wildcard byte
auto result = vh::scan("48 8B 05 ? ? ? ? 48 85 C0");
if (result) {
    uintptr_t addr = *result;
}

// Scan a specific range
auto result2 = vh::scan("E8 ? ? ? ? 85 C0 74", base, size);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🐛 Anti-Debug Detection

`vanhooks::antidebug::check_all()` runs eight independent detection techniques and returns a structured `Report` with per-technique `Finding` records.

```cpp
#include <vanhooks/antidebug.hpp>

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

// Length-disassemble (for prologue walking)
size_t len = vh::disasm::instruction_length(address);

// Full decode
auto insn = vh::disasm::decode(address);
if (insn) {
    printf("%s\n", insn->mnemonic.c_str());
}

// Decode a range
for (auto& i : vh::disasm::decode_range(start, end)) {
    printf("0x%llx  %s\n", i.address, i.text.c_str());
}
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 💉 Process Injection

Four injection methods are available, each with distinct stealth and compatibility trade-offs.

```cpp
#include <vh/inject.hpp>

// Inject by path
auto inj = vh::inject(pid, "C:\\path\\to\\payload.dll", vh::InjectMethod::ManualMap);

// Inject from in-memory PE bytes (no file on disk required)
auto inj2 = vh::inject_from_memory(pid, pe_bytes, vh::InjectMethod::ManualMap);

// RAII — eject when Injection goes out of scope, or explicitly:
inj->eject();
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

auto sym = vh::symbols::resolve(address);
if (sym) {
    printf("%s  (%s:%u)\n", sym->name.c_str(), sym->file.c_str(), sym->line);
}
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📄 PE Introspection

Zero-copy in-process PE reader.

```cpp
#include <vh/pe.hpp>

auto pe = vh::pe::from_module("target.dll");

for (auto& sec : pe->sections().value_or({}))
    printf("%-8s  VA=0x%llx\n", sec.name.c_str(), sec.virtual_address);

auto exp = pe->find_export("SomeFunction");
auto caves = pe->find_caves(/*min_size=*/32, /*executable_only=*/true);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔴 Breakpoints

Software (INT3 / VEH) and hardware (DR0–DR3 / DR7) breakpoints with full RAII lifetime management.

```cpp
#include <vh/breakpoint.hpp>

auto sw = vanhooks::breakpoint::set_software(target_address,
    [](uintptr_t addr) {
        return vanhooks::breakpoint::Action::Continue;
    });

auto hw = vanhooks::breakpoint::set_hardware(
    target_address,
    vanhooks::breakpoint::HwCondition::Execute,
    vanhooks::breakpoint::HwSize::Byte,
    [](uintptr_t addr) {
        return vanhooks::breakpoint::Action::Remove;
    });
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📚 Call Stack Capture

```cpp
#include <vh/callstack.hpp>

auto frames = vanhooks::callstack::capture(/*skip=*/1, /*max_depth=*/32);
for (auto addr : frames.value_or({}))
    printf("  0x%llx\n", addr);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📡 VanTrace — Structured Hook Instrumentation

VanTrace is VanHooks' built-in structured tracing layer. It records hook enter/exit events into a lock-free ring buffer, drains them on a background consumer thread, and delivers them to any `ISink` implementation — with zero heap allocation per event and no synchronous I/O on the hook hot path.

```cpp
#include <vh/trace.hpp>   // or <vh/vh.hpp>
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

// 3. Attach hooks — cooperative mode (detour calls enter/exit)
auto h = vh::hook("d3d9.dll", "EndScene", &hk_EndScene, &orig_EndScene).value();
static vh::AttachedHook g_trace_hook = tracer.attach(h).value();

// 4. Inside your detour — RAII scope records enter + exit
HRESULT __stdcall hk_EndScene(IDirect3DDevice9* dev) {
    vh::CallScope scope(g_trace_hook);   // HookEnter recorded here
    return orig_EndScene(dev);           // HookExit recorded on scope exit
}
```

### Transparent mode — zero detour changes required

```cpp
// Transparent: VanTrace auto-instruments entry + exit via internal mid hooks
// The detour needs no modification at all.
auto h = vh::hook("ntdll.dll", "NtQuerySystemInformation",
                  &hk_NtQSI, &orig_NtQSI).value();

static vh::AttachedHook g_hook = tracer.attach(
    h,
    /*tag_override=*/"ntdll.NtQuerySystemInformation",
    vanhooks::trace::AttachMode::Transparent   // entry + exit, x64; degrades gracefully
).value();
```

### Attach modes

| Mode | Description |
|---|---|
| `AttachMode::Cooperative` | Detour calls `enter()` / `exit()` (or holds a `CallScope`) manually. Lowest overhead; works on all hook kinds and platforms. Default. |
| `AttachMode::Transparent` | VanTrace installs internal `hook_mid` / `hook_mid_return` stubs on the detour automatically. Entry + exit recorded with no detour changes. x64 exit recording; degrades to entry-only on other architectures. |
| `AttachMode::TransparentEntry` | Like `Transparent` but only records entry events. Use when timing or exit notification is not needed. |

### Sinks

| Sink | Description |
|---|---|
| `NullSink` | Discards all events. Default when no sink is set. |
| `CallbackSink` | Delivers each event to a `std::function<void(const Event&, const HookMeta*)>`. |
| Custom `ISink` | Implement `on_events(span<const Event>, meta_for_fn)` and optionally `flush()`. |

```cpp
// Custom sink — write events to a file
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
cfg.enable_timing    = true;   // timestamp + duration per event
cfg.enable_thread_id = true;   // OS thread ID per event
cfg.enable_call_depth = true;  // per-thread nesting depth

vh::Tracer tracer(cfg);
```

### Raw context capture

Attach up to 64 bytes of arbitrary data (register snapshot, argument values, etc.) to the next enter event from the calling thread:

```cpp
HRESULT __stdcall hk_CreateBuffer(ID3D11Device* dev,
                                   D3D11_BUFFER_DESC* desc, ...)
{
    // Capture the buffer description before calling enter()
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

auto dev = vh::net::open_device("eth0");
dev->start_capture([](vh::net::Packet& pkt) {
    if (auto* ip = pkt.layer<vh::net::IPv4Layer>()) {
        printf("%s → %s\n",
            ip->src_addr().to_string().c_str(),
            ip->dst_addr().to_string().c_str());
    }
});

auto reader = vh::net::open_pcapng("capture.pcapng");
while (auto pkt = reader->next_packet()) { /* ... */ }
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🧩 Optional Modules

The modules below carry external system dependencies and are therefore opt-out rather than always-on. All other features — including VanTrace and VanNet — compile in unconditionally.

| Module | CMake flag | Header | Description |
|---|---|---|---|
| Symbol resolution | `VH_ENABLE_SYMBOLS` | `<vh/symbols.hpp>` | Function name / file / line annotation (DbgHelp / libbacktrace) |
| PE introspection | `VH_ENABLE_PE` | `<vh/pe.hpp>` | Sections, exports, imports, code caves |
| Breakpoints | `VH_ENABLE_BREAKPOINT` | `<vh/breakpoint.hpp>` | SW (INT3/VEH) and HW (DR0–DR3) |
| Call stack | `VH_ENABLE_CALLSTACK` | `<vh/callstack.hpp>` | `RtlCaptureStackBackTrace` / `backtrace()` |
| Injection | `VH_ENABLE_INJECT` | `<vh/inject.hpp>` | LoadLibrary, ManualMap, ThreadHijack, ApcQueue |

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
| VanTrace (cooperative) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| VanTrace (transparent exit) | ✓ | ✓ | ✓ | — | ✓ | — |
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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📖 Documentation

Full API reference, architecture notes, and worked examples are in the [Functions_Guide](
https://github.com/TsyVM/VanHooks/blob/main/VanHooks_Functions_Guide.md).
