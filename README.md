<div align="center">

<img src="vh-logo.png" width="600" alt="VanHooks"/>

<p><em>Modern C++23 Cross-Platform Function Hooking & Instrumentation Library</em></p>

<a href="#">
<img src="https://readme-typing-svg.demolab.com/?lines=Trampoline+%C2%B7+IAT+%C2%B7+PLT+%C2%B7+VTable+%C2%B7+Mid-Function;Pattern+Scanner+%C2%B7+Injection+%C2%B7+Symbols+%C2%B7+Breakpoints;Watchdog+%C2%B7+Anti-Debug+%C2%B7+ETW+%C2%B7+AMSI;One+API.+Every+Platform.+Zero+Exceptions.;std%3A%3Aexpected+all+the+way+down.&font=Fira%20Code&center=true&width=650&height=45&color=FF3B3B&vCenter=true&size=22&pause=1800"/>
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

Beyond hooking, the library ships a complete instrumentation and stealth toolkit: a pattern scanner, disassembler, PE introspector (sections, exports, imports, code cave finder), software and hardware breakpoints, call stack capture, multi-technique anti-debug detection, four-method process injector, an integrity watchdog, and user-mode ETW/AMSI suppression — all enabled by default with **zero external dependencies beyond Zydis**. An optional symbol resolution layer and an optional network layer (**VanNet**, for live packet capture and protocol parsing) can be enabled when needed. Every feature uses the same `Result<T>` error model and the same `#include <vh/vh.hpp>` entry point.

<div align="center">

### 📑 Table of Contents

[Why VanHooks](#-why-vanhooks) · [Features](#-features-at-a-glance) · [Requirements](#️-requirements) · [Installation](#-installation) · [Quick Start](#-quick-start) · [Hook Types](#-hook-types) · [Lifetime & RAII](#️-hook-lifetime-and-raii) · [Groups](#️-groups--batch-lifecycle-management) · [Chaining](#-hook-chaining) · [Error Handling](#-error-handling) · [HookRegistry](#-multi-module-projects--hookregistry) · [Scanner](#-pattern-scanner) · [Anti-Debug](#-anti-debug-detection) · [Disassembler](#-disassembler) · [Injection](#-process-injection) · [Stealth](#-stealth-configuration) · [Watchdog](#-integrity-watchdog) · [Symbols](#-symbol-resolution) · [PE Introspection](#-pe-introspection) · [Breakpoints](#-breakpoints) · [Call Stack](#-call-stack-capture) · [VanNet](#-vannet--built-in-network-layer) · [Optional Modules](#️-optional-modules) · [Platform Support](#️-platform-support) · [FAQ](#-faq) · [Docs](#-documentation)

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
- **VanNet** — PcapPlusPlus-derived packet capture and protocol parsing behind `VH_NET_ENABLED`
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

Optional modules are controlled by CMake options:

```cmake
# Enable optional layers (all off by default)
set(VH_NET_ENABLED        ON)   # VanNet packet capture (requires Npcap/libpcap)
set(VH_INJECT_ENABLED     ON)   # Process injection
set(VH_SYMBOLS_ENABLED    ON)   # Symbol resolution (DbgHelp / libbacktrace)
set(VH_PE_ENABLED         ON)   # PE introspection
set(VH_BREAKPOINT_ENABLED ON)   # Software + hardware breakpoints
set(VH_CALLSTACK_ENABLED  ON)   # Call stack capture
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

`vanhooks::antidebug::check_all()` runs eight independent detection techniques and returns a structured `Report` with per-technique `Finding` records. Intended for vulnerability research tooling to enumerate what anti-debug measures a target uses, or to verify that a research environment is clean.

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

The disassembler is used internally by the trampoline builder for instruction-boundary alignment during prologue stealing and by the mid-function hook installer.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 💉 Process Injection

Four injection methods are available, each with distinct stealth and compatibility trade-offs. Requires `VH_INJECT_ENABLED`.

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

**LoadLibrary** — `CreateRemoteThread` + `LoadLibraryA`. Simple but leaves a module-list entry and is trivially detectable by any `EnumProcessModules` scan.

**ManualMap** — Parses the PE in-process, maps sections into the target without calling `LoadLibraryA`. No module-list entry. The PE header is withheld from the remote allocation. Shellcode is zeroed after execution, and no IAT trampolines are left behind.

**ThreadHijack** — Suspends an existing thread, redirects its `RIP` to a compact shellcode stub that loads the payload, restores all volatile registers and the original instruction pointer via a RIP-relative jump, then resumes. No remote thread is created; no `CreateThread` call appears in any trace.

**ApcQueue** — Queues a `LoadLibraryA` APC to every alertable thread. The DLL loads the next time any thread calls an alertable wait (`SleepEx`, `WaitForSingleObjectEx`, etc.). No remote thread; no visible injection event in ETW until the alertable wait fires.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🥷 Stealth Configuration

Stealth features are controlled through `Engine::Config` at construction time.

```cpp
vanhooks::Engine::Config cfg;

// ETW suppression — patches ntdll!EtwEventWrite and EtwEventWriteFull
// to return STATUS_SUCCESS immediately, silencing user-mode ETW telemetry
// used by many EDR/AV products to detect API activity.
cfg.suppress_etw = true;

// AMSI suppression — patches amsi.dll!AmsiScanBuffer and AmsiScanString
// to return AMSI_RESULT_CLEAN without scanning.
// No-op if amsi.dll is not loaded in the process.
cfg.suppress_amsi = true;

// Watchdog thread is spawned via NtCreateThreadEx so CreateThread does
// not appear in the IAT and avoids trivial thread-creation telemetry.
cfg.enable_integrity_watchdog = true;

vanhooks::Engine eng(cfg);
```

> **Note:** ETW and AMSI suppression are user-mode Tier 3 measures. They have no effect on HVCI / VBS-protected systems where kernel-mode ETW providers cannot be silenced from user mode.

### Why NtCreateThreadEx?

The integrity watchdog and internal background operations use `NtCreateThreadEx` (called directly via ntdll) rather than `CreateThread`. This means `CreateThread` does not appear in VanHooks' IAT, and thread-creation events attributed to VanHooks are not visible to `CreateThread`-level monitors.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🐕 Integrity Watchdog

The integrity watchdog is a background thread that polls all installed hooks at a configurable interval and reinstalls any that have been removed externally — for example, by a kernel driver that clears user-mode hooks.

```cpp
vanhooks::Engine::Config cfg;
cfg.enable_integrity_watchdog = true;
cfg.watchdog_interval_ms      = 250; // check every 250 ms (default: 500)

vanhooks::Engine eng(cfg);
```

The watchdog detects removal by reading the first bytes of each hooked target and comparing them against the expected jump patch. If the bytes no longer match, the patch is reapplied within the next interval. This is transparent to the rest of the hook lifecycle — RAII destructors and explicit `remove()` calls still work normally; the watchdog only reacts to *external* removal.

The watchdog thread is spawned via `NtCreateThreadEx` (see [Stealth Configuration](#-stealth-configuration)) and stops cleanly when the `Engine` is destroyed.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔣 Symbol Resolution

Annotates addresses with function names, file names, and line numbers. Requires `VH_SYMBOLS_ENABLED`. Uses DbgHelp on Windows and libbacktrace on POSIX.

```cpp
#include <vh/symbols.hpp>

auto sym = vh::symbols::resolve(address);
if (sym) {
    printf("%s  (%s:%u)\n", sym->name.c_str(), sym->file.c_str(), sym->line);
}
```

When `VH_SYMBOLS_ENABLED` is defined, `callstack::capture_annotated()` automatically annotates each captured frame.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📄 PE Introspection

A zero-copy in-process PE reader that wraps a loaded module's memory. Requires `VH_PE_ENABLED`.

```cpp
#include <vh/pe.hpp>

auto pe = vh::pe::from_module("target.dll");

// Sections
for (auto& sec : pe->sections().value_or({}))
    printf("%-8s  VA=0x%llx  size=0x%x  %c%c%c\n",
        sec.name.c_str(), sec.virtual_address, sec.virtual_size,
        sec.readable() ? 'R' : '-',
        sec.writable() ? 'W' : '-',
        sec.executable() ? 'X' : '-');

// Exports
auto exp = pe->find_export("SomeFunction");
auto exp2 = pe->find_export_by_ordinal(42);

// Imports
auto imports = pe->imports_from("kernel32.dll");

// Code cave finder — find N bytes of zero-padding in executable sections
auto caves = pe->find_caves(/*min_size=*/32, /*executable_only=*/true);
for (auto& cave : caves)
    printf("cave @ 0x%llx  size=%zu  in %s\n",
        cave.address, cave.size, cave.section.c_str());
```

`Pe` can also be constructed from a raw byte span (for offline / on-disk analysis) or from a base address directly.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🔴 Breakpoints

Software (INT3 / VEH) and hardware (DR0–DR3 / DR7) breakpoints with full RAII lifetime management. Requires `VH_BREAKPOINT_ENABLED`.

```cpp
#include <vh/breakpoint.hpp>

// Software breakpoint — patches one byte to 0xCC, installs a VEH handler
auto sw = vanhooks::breakpoint::set_software(target_address,
    [](uintptr_t addr) {
        printf("SW BP hit @ 0x%llx\n", addr);
        return vanhooks::breakpoint::Action::Continue; // re-arm and resume
    });

// Hardware breakpoint — DR0–DR3, applied to all currently-running threads
auto hw = vanhooks::breakpoint::set_hardware(
    target_address,
    vanhooks::breakpoint::HwCondition::Execute,
    vanhooks::breakpoint::HwSize::Byte,
    [](uintptr_t addr) {
        printf("HW BP hit @ 0x%llx\n", addr);
        return vanhooks::breakpoint::Action::Remove; // one-shot
    });

// Both removed automatically when sw / hw go out of scope
```

### Conditions and Sizes

| `HwCondition` | DR7 encoding | Description |
|---|---|---|
| `Execute` | `00` | Break on instruction fetch (size must be `Byte`) |
| `Write` | `01` | Break on memory write |
| `ReadWrite` | `11` | Break on read or write (not execute) |

| `HwSize` | DR7 encoding | Range |
|---|---|---|
| `Byte` | `00` | 1 byte |
| `Word` | `01` | 2 bytes |
| `Dword` | `11` | 4 bytes |
| `Qword` | `10` | 8 bytes (x64 only) |

### New Thread Propagation

Hardware breakpoints are applied per-thread at install time. For threads created after the breakpoint is installed, call `apply_to_new_thread` from a `DLL_THREAD_ATTACH` notification:

```cpp
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_THREAD_ATTACH && hw_bp.active())
        hw_bp->apply_to_new_thread(GetCurrentThread());
    return TRUE;
}
```

`BreakpointSlotExhausted` is returned when all four DR slots (DR0–DR3) are occupied.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📚 Call Stack Capture

Thin wrapper around `RtlCaptureStackBackTrace` (Windows) / `backtrace()` (POSIX). Requires `VH_CALLSTACK_ENABLED`.

```cpp
#include <vh/callstack.hpp>

// Raw frame addresses — no heap allocation on Windows capture path
auto frames = vanhooks::callstack::capture(/*skip=*/1, /*max_depth=*/32);
for (auto addr : frames.value_or({}))
    printf("  0x%llx\n", addr);

// Annotated frames (requires VH_SYMBOLS_ENABLED)
auto annotated = vanhooks::callstack::capture_annotated();
for (auto& f : annotated.value_or({}))
    printf("  %-40s  %s:%u\n", f.name.c_str(), f.file.c_str(), f.line);
```

The `skip` parameter lets you omit VanHooks' own frames when capturing from inside a detour. Maximum depth is capped at 64 frames; deeper stacks are silently truncated.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🌐 VanNet — Built-in Network Layer

An optional packet capture and protocol parsing layer derived from PcapPlusPlus, rewritten in VanHooks' snake_case conventions and integrated into the `vanhooks::net` namespace. Requires `VH_NET_ENABLED` and an installed Npcap / libpcap.

```cpp
#include <vh/net.hpp>

// Open a live capture device
auto dev = vh::net::open_device("eth0");
dev->start_capture([](vh::net::Packet& pkt) {
    if (auto* ip = pkt.layer<vh::net::IPv4Layer>()) {
        printf("%s → %s\n",
            ip->src_addr().to_string().c_str(),
            ip->dst_addr().to_string().c_str());
    }
});

// Read an offline pcapng file
auto reader = vh::net::open_pcapng("capture.pcapng");
while (auto pkt = reader->next_packet()) { /* ... */ }
```

Protocol layers include L2 (Ethernet, VLAN, SLL), L3 (IPv4, IPv6, ARP, ICMP), L4 (TCP, UDP, SCTP), and higher-level layers (DNS, HTTP, TLS, DHCP, and more). The `VHPcapNg` module provides a flattened reader/writer for `.pcapng` files with interface block and enhanced packet block support.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🧩 Optional Modules

| Module | CMake flag | Header | Description |
|---|---|---|---|
| Symbol resolution | `VH_SYMBOLS_ENABLED` | `<vh/symbols.hpp>` | Function name / file / line annotation |
| PE introspection | `VH_PE_ENABLED` | `<vh/pe.hpp>` | Sections, exports, imports, code caves |
| Breakpoints | `VH_BREAKPOINT_ENABLED` | `<vh/breakpoint.hpp>` | SW (INT3/VEH) and HW (DR0–DR3) |
| Call stack | `VH_CALLSTACK_ENABLED` | `<vh/callstack.hpp>` | `RtlCaptureStackBackTrace` / `backtrace()` |
| Injection | `VH_INJECT_ENABLED` | `<vh/inject.hpp>` | LoadLibrary, ManualMap, ThreadHijack, ApcQueue |
| VanNet | `VH_NET_ENABLED` | `<vh/net.hpp>` | Packet capture + protocol parsing |

All of the above are off by default. The always-on core (hooking, scanner, disassembler, antidebug) has **zero dependencies beyond Zydis**.

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
The watchdog detects *user-mode* patch removal by reading bytes. Kernel drivers that use kernel-mode hooks or memory scanning operate below the watchdog's visibility. The watchdog is designed for the case where a kernel driver clears user-mode hooks in the IAT or prologue; it is not a bypass for protected-process anti-cheat.

**What happens if all four DR slots are full?**
`set_hardware` returns `Error::BreakpointSlotExhausted`. Remove an existing hardware breakpoint to free a slot.

**Is there a global engine or must I construct one?**
`vanhooks::global_engine()` returns a default-constructed process-wide singleton. You can also construct your own `Engine` instances with custom `Config` for isolated trampoline pools or per-subsystem watchdog settings.

**Can I use VanHooks inside a DLL injected via ManualMap?**
Yes — VanHooks does not rely on `DllMain` or the loader lock internally.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📖 Documentation

Full API reference, architecture notes, and worked examples are in the [Wiki](../../wiki).
