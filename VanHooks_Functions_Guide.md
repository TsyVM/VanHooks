<div align="center">
<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:0A0A0A,50:7A0C0C,100:0A0A0A&height=170&section=header&text=Functions%20Guide&fontSize=48&fontColor=FF4444&animation=fadeIn&fontAlignY=40&desc=Public%20API%20Reference%20%C2%B7%20v0.1.0&descAlignY=62&descSize=14&descColor=B8B8B8"/>

[![Standard](https://img.shields.io/badge/C%2B%2B-23-FF4444?style=flat-square&labelColor=0A0A0A)](https://en.cppreference.com/w/cpp/23)
[![Windows](https://img.shields.io/badge/Windows-x86%20%7C%20x64-FF4444?style=flat-square&labelColor=0A0A0A)](lib/)
[![Linux](https://img.shields.io/badge/Linux-x64%20%7C%20ARM64-FF4444?style=flat-square&labelColor=0A0A0A)](lib/)
[![macOS](https://img.shields.io/badge/macOS-x64%20%7C%20ARM64-FF4444?style=flat-square&labelColor=0A0A0A)](lib/)

</div>

<br/>

VanHooks is distributed as **precompiled static libraries with public API headers**. Everything documented here is available through those headers and the matching `.lib`. One include, all platforms.

```cpp
#include <vh/vh.hpp>
```

---

## Contents

[Glossary](#glossary) · [Result Type](#result-type) · [Level 1 API](#level-1-api) · [Level 2 API](#level-2-api) · [Hook Object](#hook-object) · [Group](#group) · [HookRegistry](#hookregistry) · [Config Structs](#config-structs) · [Engine Access](#engine-access) · [Error Codes](#error-codes) · [Pattern Scanner](#pattern-scanner) · [Anti-Debug Detection](#anti-debug-detection) · [Disassembler](#disassembler) · [Process Injection](#process-injection) · [Stealth Subsystems](#stealth-subsystems) · [Symbol Resolution](#symbol-resolution) · [PE Introspection](#pe-introspection) · [Breakpoints](#breakpoints) · [Call Stack Capture](#call-stack-capture) · [VanTrace](#vantrace) · [Network API](#network-api) · [Quick Reference](#quick-reference)

---

## Glossary

| Term | Meaning |
|---|---|
| **Hook** | Both the act of interception and the RAII object representing it. Owns the interception for its lifetime; removes it automatically on destruction. |
| **Target** | The function or address being intercepted. |
| **Detour** | Your replacement function. Must match the target's calling convention and signature exactly. |
| **Original** | A function pointer VanHooks fills in so your detour can call through to the real function. |
| **Call Site** | A single `CALL` (E8) or `JMP` (E9) instruction in the caller's code. A CallSite hook patches only this one instruction's displacement, leaving the target function's prologue untouched. |
| **Enable** | Activate a hook so calls to the target go to the detour. Default state when created. |
| **Disable** | Deactivate a hook without removing it. Target behaves as unhooked; the object remains valid. |
| **Remove** | Permanently uninstall a hook and release all resources. The `Hook` destructor does this automatically. |
| **AttachedHook** | A VanTrace handle representing one hook registered with a `Tracer`. Returned by `Tracer::attach()`. |
| **CallScope** | RAII guard that calls `AttachedHook::enter()` on construction and `exit()` on destruction. |

---

## Result Type

Every hook creation function returns `Result<Hook>`. `Result<T>` is an alias for `std::expected<T, vh::Error>` — no exceptions, no global error state, zero overhead on the success path.

```cpp
auto r = vh::hook(&my_fn, &my_detour);

if (!r) {
    printf("failed: %s\n", vh::error_to_string(r.error()).data());
    return;
}

vh::Hook h = std::move(*r);
```

**Chaining with `.and_then()`:**

```cpp
auto r = vh::hook(&fn, &detour, &orig)
    .and_then([](vh::Hook h) -> vh::Result<vh::Hook> {
        h.disable();
        return h;
    });
```

**`error_to_string`:**

```cpp
std::string_view vh::error_to_string(vh::Error e) noexcept;
```

Returns a human-readable name for any `Error` code as a `string_view` into static storage.

---

## Level 1 API

### `vh::hook(target, detour)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(Fn* target, Fn* detour);

template<typename Fn>
Result<Hook> vh::hook(uintptr_t target, Fn* detour);
```

Intercepts `target` so calls go to `detour`. No call-through. The `uintptr_t` overload accepts a runtime-resolved address without requiring a `reinterpret_cast` at the call site.

### `vh::hook(target, detour, original_out)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(Fn* target, Fn* detour, Fn** original_out);

template<typename Fn>
Result<Hook> vh::hook(uintptr_t target, Fn* detour, Fn** original_out);
```

Same, but fills `*original_out` with the trampoline address.

```cpp
static int (*orig_add)(int, int) = nullptr;

int detour_add(int a, int b) {
    printf("add(%d, %d)\n", a, b);
    return orig_add(a, b);
}

auto r = vh::hook(&add, &detour_add, &orig_add);

// Runtime address form — common in game modding
auto r2 = vh::hook(0x5D5DB0u, &detour_add, &orig_add);
```

### `vh::hook(module, symbol, detour, original_out)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(std::string_view module,
                      std::string_view symbol,
                      Fn* detour,
                      Fn** original_out = nullptr);
```

Resolves the target by module and symbol name (`GetProcAddress` / `dlsym`), then installs an inline hook.

```cpp
static decltype(&MessageBoxW) orig_mbw = nullptr;

BOOL WINAPI hk_mbw(HWND h, LPCWSTR t, LPCWSTR c, UINT f) {
    return orig_mbw(h, L"[Intercepted]", c, f);
}

auto r = vh::hook("user32", "MessageBoxW", &hk_mbw, &orig_mbw);
```

---

## Level 2 API

### `vh::inline_hook`

```cpp
template<typename Fn>
Result<Hook> vh::inline_hook(Fn* target,
                             Fn* detour,
                             Fn** original_out = nullptr,
                             config::Trampoline opts = {});

template<typename Fn>
Result<Hook> vh::inline_hook(uintptr_t target,
                             Fn* detour,
                             Fn** original_out = nullptr,
                             config::Trampoline opts = {});
```

Patches the first bytes of `target` with a jump and builds a trampoline. The `uintptr_t` overload works identically to the pointer form; use it when the address came from a pattern scan or version table. Options: [`config::Trampoline`](#configtrampoline).

### `vh::api_hook`

```cpp
template<typename Fn>
Result<Hook> vh::api_hook(std::string_view module,
                          std::string_view symbol,
                          Fn* detour,
                          Fn** original_out = nullptr,
                          config::Trampoline opts = {});
```

Resolves the target by module and symbol name, then installs an inline hook.

### `vh::vtable_hook`

```cpp
Result<Hook> vh::vtable_hook(void** vtable,
                             size_t slot,
                             void* detour,
                             void** original_out = nullptr,
                             config::VTable opts = {});
```

Patches a single slot in a C++ virtual function table. Slots are zero-indexed in declaration order. `original_out` is accepted for API consistency but VTable hooks do not produce a callable trampoline stub — to call the original, save the vtable pointer yourself before installing the hook.

```cpp
void** vtbl = *reinterpret_cast<void***>(swap_chain);

static HRESULT (STDMETHODCALLTYPE *orig_Present)(IDXGISwapChain*, UINT, UINT) =
    reinterpret_cast<decltype(orig_Present)>(vtbl[8]);

HRESULT STDMETHODCALLTYPE hk_Present(IDXGISwapChain* sc, UINT sync, UINT flags) {
    return orig_Present(sc, sync, flags);
}

auto r = vh::vtable_hook(vtbl, 8, (void*)&hk_Present, nullptr, { .tag = "DXGI.Present" });
```

### `vh::iat_hook`

```cpp
Result<Hook> vh::iat_hook(std::string_view import_name,
                          void* detour,
                          config::IAT opts = {});
```

**Windows only.** Patches one IAT entry. `opts.module_name` restricts the patch to a single module; leave empty to target all loaded modules. Options: [`config::IAT`](#configiat).

### `vh::iat_hook_all`

```cpp
Result<std::vector<Hook>> vh::iat_hook_all(std::string_view import_name,
                                           void* detour,
                                           config::IAT opts = {});
```

**Windows only.** Patches every IAT entry matching `import_name` across all loaded modules.

### `vh::plt_hook`

```cpp
Result<Hook> vh::plt_hook(std::string_view library,
                          std::string_view symbol,
                          void* detour,
                          config::PLT opts = {});
```

**Linux and macOS only.** Patches a PLT entry or lazy pointer.

### `vh::mid_hook`

```cpp
Result<Hook> vh::mid_hook(void* target,
                          MidCallback callback,
                          config::Mid opts = {});
```

Installs a callback at a byte offset inside a function (`opts.offset`). Does not redirect control flow — exposes CPU register state at that instruction boundary.

**`MidCallback` signature:**

```cpp
using MidCallback = void (*)(MidContext*) noexcept;
```

**`MidContext` fields:**

| Architecture | Fields |
|---|---|
| x64 | `rax`…`r15`, `rflags` — all `uint64_t` |
| x86 | `eax`…`edi`, `eflags` — all `uint32_t` |
| ARM64 | `x[0]`…`x[7]`, `lr` — all `uint64_t` |

Writes take effect when the callback returns.

```cpp
auto r = vh::mid_hook(&game_update,
    [](vh::MidContext* ctx) noexcept {
        player_health = static_cast<int>(ctx->rax);
    },
    { .offset = 0x1C, .tag = "Game.HealthReadback" });
```

### `vh::callsite_hook`

```cpp
// Address-based — primary API for pattern-scanned or version-table addresses
template<typename Detour>
Result<Hook> vh::callsite_hook(uintptr_t         site_addr,
                               Detour*           detour,
                               auto*             orig,
                               vanhooks::CallSiteOptions opts = {});

// Function-pointer overload
template<typename Fn>
Result<Hook> vh::callsite_hook(Fn*  site_addr,
                               Fn*  detour,
                               Fn** orig = nullptr,
                               vanhooks::CallSiteOptions opts = {});
```

Patches the 32-bit relative displacement of a **single** `CALL` (E8) or `JMP` (E9) instruction at `site_addr`, redirecting only that one call site. `*orig` receives the resolved absolute address of the original target.

| | Trampoline | CallSite |
|---|---|---|
| What is patched | Target function prologue | Displacement at one `CALL`/`JMP` site |
| Callers affected | All callers | Only the one patched site |
| ARM64 | ✓ | Returns `Error::Unsupported` |

```cpp
using PFN = int(__cdecl*)(int);
PFN g_orig = nullptr;

int my_detour(int x) { return g_orig(x); }

auto addr = vanhooks::scanner::scan_process("E8 ? ? ? ? 83 C4 04").value()[0];
auto h = vh::callsite_hook(addr, &my_detour, &g_orig, { .tag = "Game.SpeedCall" });
```

Options: [`vanhooks::CallSiteOptions`](#vanhookscallsiteoptions).

### `vh::hwbp_hook`

```cpp
Result<Hook> vh::hwbp_hook(void*                 target,
                           vanhooks::MidCallback  callback,
                           vanhooks::HwBpOptions  opts = {});

template<typename Fn>
Result<Hook> vh::hwbp_hook(Fn*                   target,
                           vanhooks::MidCallback  callback,
                           vanhooks::HwBpOptions  opts = {});
```

Hardware breakpoint hook using DR0–DR3 + VEH. No bytes written to the target. Windows x64 only; returns `Error::Unsupported` on other platforms. Maximum 4 active HwBp hooks simultaneously.

```cpp
auto h = vh::hwbp_hook(&target_fn,
    [](vanhooks::MidContext* ctx) noexcept { ctx->rax = 0; },
    { .tag = "silent" });
```

### `vh::page_guard_hook`

```cpp
Result<Hook> vh::page_guard_hook(void*                         target,
                                  vanhooks::MidCallback         callback,
                                  vanhooks::PageGuardOptions    opts = {});
```

Sets `PAGE_GUARD` on the target's memory page and intercepts `EXCEPTION_GUARD_PAGE` in a VEH. No inline patch is written. Windows only; returns `Error::Unsupported` on POSIX.

```cpp
auto h = vh::page_guard_hook(&target_fn, &my_callback,
    { .condition = vanhooks::PageGuardCondition::Write, .auto_rearm = true });
```

### `vh::ic_hook` — Instrumentation Callback

```cpp
Result<Hook> vh::ic_hook(vanhooks::ICCallback  callback,
                          vanhooks::ICOptions   opts = {});
```

Sets `KPROCESS.InstrumentationCallback` via `NtSetInformationProcess(0x28)`, firing on every kernel-to-user-mode transition. Process-wide singleton — a second install returns `Error::HookAlreadyExists`. Windows x64 only. The `callback` must be a valid naked/executable stub.

### Return hooks — Engine API (x64 only)

`hook_mid_return()` captures the return value of a function before the caller sees it. Returns `Error::Unsupported` on ARM64 and x86.

```cpp
auto& eng = vanhooks::global_engine();

auto h = eng.hook_mid_return(
    &target_fn,
    /*byte_offset=*/0,
    /*enter_cb=*/nullptr,
    [](vanhooks::ReturnContext* ctx) noexcept {
        ctx->retval_rax = 1;
    });
```

**`ReturnContext` fields (x64):** `retval_rax`, `retval_rdx`, `retval_xmm0` (double), `hook_id`, `real_ret_addr`.

---

## Hook Object

Every creation function returns `Result<Hook>`. Move-only. The destructor calls `remove()` automatically.

### Lifecycle

| Method | Return | Description |
|---|---|---|
| `enable()` | `Hook&` | Activates the hook. Chainable. |
| `disable()` | `Hook&` | Deactivates without removing. Chainable. |
| `remove()` | `void` | Permanently uninstalls. `valid()` returns `false` afterward. Idempotent. |

### Chaining

```cpp
template<typename Fn>
Result<Hook> chain(Fn* next_detour,
                   Fn** next_original_out = nullptr,
                   std::string tag = {});

Result<Hook> chain(void* next_detour,
                   void** next_original_out = nullptr,
                   std::string tag = {});
```

Inserts a detour in front of an existing hook. Remove links before base hooks — `ChainOrderViolation` otherwise.

### Introspection

| Method | Return Type | Description |
|---|---|---|
| `valid()` | `bool` | Hook is installed and usable. |
| `enabled()` | `bool` | Hook is currently active. |
| `tag()` | `std::string` | Label set at creation, or empty. |
| `kind()` | `HookKind` | Which hook type this is. |
| `target()` | `void*` | Address of the original function (or call site for CallSite hooks). |
| `detour()` | `void*` | Address of the replacement function. |
| `trampoline()` | `void*` | Call-through trampoline. `nullptr` for IAT/PLT/VTable/CallSite. |
| `handle()` | `HookHandle` | Raw handle for Engine interop. |
| `engine()` | `Engine&` | Reference to the owning engine. |

---

## Group

Owns a collection of `Hook` objects. All batch lifecycle operations happen in a single thread-suspension window.

```cpp
auto grp = vh::group("RenderHooks");
grp.add(vh::vtable_hook(vtbl, 8,  (void*)&hk_Present))
   .add(vh::vtable_hook(vtbl, 16, (void*)&hk_Reset));

grp.enable();
grp.disable();
grp.remove_all();
```

### Add hooks

| Method | Description |
|---|---|
| `add(Hook)` | Takes ownership. Returns `*this`. |
| `add(Result<Hook>)` | Silently skips errors. Returns `*this`. |

### Address-based install

```cpp
template<typename Fn>
Group& hook_at(uintptr_t target, Fn* detour, Fn** original = nullptr,
               config::Trampoline opts = {});
```

Installs a trampoline from a raw runtime address. Failed installs are silently dropped and do not invalidate the chain. Use `add(vh::inline_hook(…))` directly when you need failure visibility.

```cpp
grp.hook_at(0x5D5DB0u, &MyDetour);
grp.hook_at(0x5E7859u, &MyDetour, &orig_fn);
grp.hook_at(addr, &MyDetour, nullptr, { .tag = "my_hook" });
```

### Hardware breakpoint install

```cpp
Group& hook_hwbp(uintptr_t              target,
                 vanhooks::MidCallback   callback,
                 vanhooks::HwBpOptions   opts = {});

template<typename Fn>
Group& hook_hwbp(Fn*                    target,
                 vanhooks::MidCallback   callback,
                 vanhooks::HwBpOptions   opts = {});
```

Windows x64 only; silently a no-op on other platforms (same behaviour as `hook_at` on failure).

```cpp
grp.hook_hwbp(0xDEADBEEFu, &MyMidCallback);
grp.hook_hwbp(fn_ptr, &MyMidCallback, { .dr_slot = 1 });
```

### CallSite install

```cpp
template<typename Detour>
Group& hook_callsite(uintptr_t site_addr, Detour* detour, auto* orig,
                     vanhooks::CallSiteOptions opts = {});

template<typename Detour>
Group& hook_callsite_pattern(std::string_view pattern, ptrdiff_t byte_offset,
                              Detour* detour, auto* orig,
                              vanhooks::CallSiteOptions opts = {});

// Nth-match overload
template<typename Detour>
Group& hook_callsite_pattern(std::string_view pattern, ptrdiff_t byte_offset,
                              size_t match_index,
                              Detour* detour, auto* orig,
                              vanhooks::CallSiteOptions opts = {});
```

`hook_callsite_pattern` is a no-op (not an error) when the pattern is not found. Failed installs are silently dropped.

```cpp
grp.hook_callsite(0x12AB34u, &MyDetour, &g_orig);
grp.hook_callsite(0x12AB34u, &MyDetour, &g_orig, { .tag = "NFS.SpeedCall" });

// Pattern scan — first match, byte 0 is the E8/E9 site
grp.hook_callsite_pattern("E8 ? ? ? ? 83 C4 04", 0, &MyDetour, &g_orig);

// Advance past a preceding instruction to land on E8
grp.hook_callsite_pattern("89 04 24 E8 ? ? ? ?", 3, &MyDetour, &g_orig);

// Hook the third match (zero-indexed)
grp.hook_callsite_pattern("E8 ? ? ? ? 85 C0", 0, 2, &MyDetour, &g_orig);
```

### Pattern-scan hook

```cpp
template<typename Fn>
Group& hook_pattern(std::string_view pattern, ptrdiff_t offset,
                    Fn* detour, Fn** original = nullptr,
                    config::Trampoline opts = {});
```

Scans the process for the pattern, offsets to the hook site, and installs a trampoline. Only the first match is hooked. No-op if the pattern is not found.

```cpp
grp.hook_pattern("E8 ? ? ? ? 83 C4 04", -5, &MyDetour);
grp.hook_pattern("48 8B 05 ? ? ? ?",     0,  &MyDetour, &orig_fn);
```

### Memory patch helpers

```cpp
template<typename T>
Group& patch(uintptr_t addr, const T& value);

Group& nop(uintptr_t addr, size_t count);
```

`patch()` writes a typed value with automatic page-protection lifting. `nop()` fills the range with multi-byte NOPs.

```cpp
grp.patch<uint8_t>(0x581E72, 32);
grp.patch<float>(0x5D88D1 + 6, 0.25f);
grp.nop(0x14E738B, 2);
```

### Lifecycle

| Method | Description |
|---|---|
| `enable()` | Enables all hooks in one thread-suspension window. Returns `*this`. |
| `disable()` | Disables all hooks. Returns `*this`. |
| `remove_all()` / `clear()` | Removes and destroys all hooks. |
| `queue_enable()` | Queue enable without flushing. Returns `*this`. |
| `queue_disable()` | Queue disable without flushing. Returns `*this`. |
| `apply()` | Flush all queued operations in one window. Returns `Status`. |

### Introspection

| Method | Description |
|---|---|
| `at(string_view tag)` | Find by tag. Returns `Hook&`. Throws `std::out_of_range` if not found. |
| `operator[](size_t)` | Index access. Throws `std::out_of_range`. |
| `size()` | Number of hooks. |
| `empty()` | True if no hooks. |
| `name()` | Group name. |

Range-based for is supported:

```cpp
for (auto& h : grp) {
    if (h.tag().starts_with("Network")) h.disable();
}
```

---

## HookRegistry

Process-wide singleton. Access via `vh::HookRegistry::global()`.

```cpp
// Register
auto render = vh::group("Render");
render.add(vh::vtable_hook(vtbl, 8, (void*)&hk_Present));
vh::HookRegistry::global().register_group(std::move(render));

// Look up from another module
if (auto* g = vh::HookRegistry::global().find_group("Render"))
    g->disable();

// Shutdown
vh::HookRegistry::global().remove_all();
```

| Method | Description |
|---|---|
| `register_group(Group)` | Takes ownership. Keyed by group name. |
| `find_group(name)` | Returns `Group*` or `nullptr`. Thread-safe. |
| `enable_all()` / `disable_all()` / `remove_all()` | Operate across all groups. |
| `total_hook_count()` | Sum of all hooks across all groups. |

---

## Config Structs

All in `vh::config::`, defined in `<vh/config.hpp>` (included by `<vh/vh.hpp>`).

### `config::Trampoline`

```cpp
struct Trampoline {
    bool        thread_safe = true;
    std::string tag;
};
```

### `config::API`

```cpp
struct API {
    std::string_view module_name;
    std::string_view function_name;
    bool             thread_safe = true;
    std::string      tag;
};
```

### `config::IAT`

```cpp
struct IAT {
    std::string_view module_name;    // module containing the IAT (empty = all loaded)
    std::string_view import_name;
    std::string      tag;
};
```

### `config::PLT`

```cpp
struct PLT {
    std::string_view library_name;
    std::string_view symbol_name;
    std::string      tag;
};
```

### `config::VTable`

```cpp
struct VTable {
    void**      vtable = nullptr;
    size_t      slot   = 0;
    std::string tag;
};
```

### `config::Mid`

```cpp
struct Mid {
    size_t      offset      = 0;
    bool        thread_safe = true;
    std::string tag;
};
```

### `vanhooks::CallSiteOptions`

```cpp
struct CallSiteOptions {
    bool        thread_safe = true;
    std::string tag;
};
```

### `config::Inject`

```cpp
struct Inject {
    InjectMethod method = InjectMethod::LoadLibrary;
    std::string  tag;
};
```

---

## Engine Access

The global `Engine` is accessible through `vanhooks::global_engine()` and the `vh::advanced::engine()` alias. It manages trampoline pools, thread suspension, and the hook registry internally.

```cpp
auto& eng = vanhooks::global_engine();   // or vh::advanced::engine()

// Queue multiple operations and apply in one thread-suspension window
eng.queue_enable(h1.handle());
eng.queue_disable(h2.handle());
eng.apply_queued();

// Return hook (x64 only)
eng.hook_mid_return(&target, 0, nullptr, [](vanhooks::ReturnContext* ctx) noexcept {
    ctx->retval_rax = 0;
});

// Chain a second detour onto an existing hook
eng.chain(h1.handle(), (void*)&second_detour, (void**)&orig_for_second);
```

Full `Engine::Config` control — custom allocators, independent engine instances, watchdog interval, ETW/AMSI suppression flags — is available via a [source license](https://www.teamvanilla.org/).

---

## Error Codes

All codes are `vh::Error` values. Use `vh::error_to_string(e)` for the name.

### General

| Code | Meaning |
|---|---|
| `Ok` | Success. |
| `NotInitialized` | Engine not initialised. |
| `AlreadyInitialized` | Initialisation attempted twice. |
| `InvalidArgument` | Null pointer or out-of-range value. |
| `Unsupported` | Operation not supported on this platform or architecture (e.g. CallSite on ARM64, HwBp on non-Windows). |
| `OutOfRange` | Index or offset outside valid bounds. |
| `OsError` | OS call failed. |
| `InvalidAddress` | Byte at the given address is not the expected opcode (e.g. not E8/E9 for a CallSite hook). |

### Memory

| Code | Meaning |
|---|---|
| `MemoryAllocationFailed` | Could not allocate trampoline memory. |
| `MemoryProtectFailed` | Could not change memory protection. |
| `MemoryReadFailed` | Could not read from target address. |
| `MemoryWriteFailed` | Could not write patch bytes. |
| `TrampolineNoSpace` | Prologue too short to steal bytes, or (on x64 CallSite) `&detour` is outside ±2 GB of the call site. |

### Hook lifecycle

| Code | Meaning |
|---|---|
| `HookNotFound` | Handle refers to a removed or unknown hook. |
| `HookAlreadyExists` | Target already hooked (also: second `ic_hook` install). |
| `HookInstallFailed` | Install failed (usually a memory error). |
| `HookRemoveFailed` | Remove failed. |
| `HookAlreadyEnabled` | `enable()` on an active hook. |
| `HookAlreadyDisabled` | `disable()` on an inactive hook. |

### Disassembly

| Code | Meaning |
|---|---|
| `DisassemblyFailed` | Zydis could not decode the instruction stream. |
| `InstructionTooShort` | Not enough bytes to form a complete instruction. |
| `UnsupportedInstruction` | Instruction cannot be relocated (e.g. certain RIP-relative forms). |

### Module / symbol

| Code | Meaning |
|---|---|
| `ModuleNotFound` | `GetModuleHandle` / `dlopen` found no matching module. |
| `SymbolNotFound` | Symbol name not found in debug info. |
| `IATEntryNotFound` | No matching IAT entry in the target module. |
| `PLTEntryNotFound` | No matching PLT/GOT entry in the target library. |

### Thread / chain / PE / breakpoint / callstack

| Code | Meaning |
|---|---|
| `ThreadSuspendFailed` | Could not suspend one or more threads. |
| `ThreadResumeFailed` | Could not resume a suspended thread. |
| `ThreadInPrologue` | Thread IP was inside stolen bytes; IP fixup applied. Informational. |
| `QueueEmpty` | `apply_queued()` called with nothing queued. |
| `ChainBaseNotFound` | Base `HookHandle` passed to `chain()` is unknown. |
| `ChainOrderViolation` | Chain link removed before its base. |
| `PeInvalidHeader` | DOS/NT signature mismatch or bad offset. |
| `PeNoExportDirectory` | Module has no export directory. |
| `PeNoImportDirectory` | Module has no import directory. |
| `PeItemNotFound` | Named export/import/section not found. |
| `BreakpointAlreadySet` | A breakpoint is already installed at this address. |
| `BreakpointNotFound` | No breakpoint at the given address. |
| `BreakpointSlotExhausted` | All DR0–DR3 slots occupied. |
| `BreakpointInstallFailed` | OS call to set/clear context failed. |
| `CallstackCaptureFailed` | `RtlCaptureStackBackTrace` / `backtrace()` returned 0. |

---

## Pattern Scanner

All in `vanhooks::scanner::`.

### `scan_process` — process-wide (Windows)

```cpp
Result<std::vector<uintptr_t>> vanhooks::scanner::scan_process(std::string_view ida_pattern);
```

### `scan_module` — named module (Windows)

```cpp
Result<std::vector<uintptr_t>> vanhooks::scanner::scan_module(
    std::string_view module_name,
    std::string_view ida_pattern);
```

### `scan_pattern` — explicit range

```cpp
Result<std::vector<uintptr_t>> vanhooks::scanner::scan_pattern(
    const void*      base,
    size_t           size,
    std::string_view ida_pattern);
```

`?` or `??` matches any byte.

### `scan_bytes` — exact bytes

```cpp
std::vector<uintptr_t> vanhooks::scanner::scan_bytes(
    const void*              base,
    size_t                   size,
    std::span<const uint8_t> needle);
```

### `parse_pattern` — pre-compile for reuse

```cpp
Result<Pattern> vanhooks::scanner::parse_pattern(std::string_view input);
```

---

## Anti-Debug Detection

All in `vanhooks::antidebug::`.

### `check_all`

```cpp
vanhooks::antidebug::Report vanhooks::antidebug::check_all();
```

```cpp
auto report = vanhooks::antidebug::check_all();
if (report.any_detected())
    printf("%d technique(s) triggered\n", report.detection_count());

for (auto& f : report.findings)
    printf("[%s] %s — %s\n",
        f.detected ? "DETECTED" : "clean",
        f.technique.c_str(), f.detail.c_str());
```

### Techniques

**Windows (8 techniques):**

| Technique | Method |
|---|---|
| `IsDebuggerPresent` | `PEB.BeingDebugged` |
| `CheckRemoteDebuggerPresent` | Cross-process debugger handle |
| `NtQueryInformationProcess(DebugPort)` | ntdll direct |
| `HeapFlags` | PEB heap flags (x86 + x64 offsets) |
| `NtGlobalFlag` | Bits `0x70` in `PEB.NtGlobalFlag` |
| `CloseHandle(invalid)` | `EXCEPTION_INVALID_HANDLE` under debugger |
| `TimingCheck` | Loop duration >50 ms |
| `DebuggerProcessList` | Process snapshot vs known tool names |

**Linux:** `ptrace(PTRACE_TRACEME)`.

Individual checks also available: `check_is_debugger_present()`, `check_remote_debugger()`, `check_debug_port()`, `check_heap_flags()`, `check_nt_global_flag()`, `check_close_handle_exception()`, `check_timing()`, `check_debugger_processes()`.

---

## Disassembler

Zydis-backed. Always available. Types in `vh::disasm::`.

```cpp
vh::disasm::Disassembler dis;

// Decode one instruction
auto insn = dis.decode_one(code_span, runtime_va);

// Decode instructions until the first branch / terminal
auto insns = vh::disasm::decode_until_branch(fn_ptr, 128);

// Decode until at least N bytes are covered (safe for trampoline copy)
auto prologue = vh::disasm::decode_prologue(fn_ptr, 14);

// Minimum instruction-aligned byte count covering at least N bytes
auto safe_len = vh::disasm::safe_copy_length(fn_ptr, 5);

// Rewrite RIP-relative references after relocation
auto rr = vh::disasm::rewrite(insns, original_va, new_va);

// Human-readable listing
puts(vh::disasm::format_listing(insns).c_str());
```

**`Instruction` fields:** `address`, `length`, `kind` (`InsnKind`), `bytes[16]`, `absolute_target`, `mnemonic`.

**`InsnKind` values:** `Generic`, `Call`, `Jump`, `JumpConditional`, `Return`, `Nop`, `RipRelative`, `PcRelative`, `Privileged`.

---

## Process Injection

**Windows only.**

```cpp
#include <vh/inject.hpp>

// Inject by path
auto inj = vh::inject(pid, "C:\\payload.dll",
                      { .method = vh::InjectMethod::ManualMap });

// Inject from in-memory PE bytes
auto inj2 = vh::inject_from_memory(pid, pe_bytes,
                                    { .method = vh::InjectMethod::ThreadHijack });

// Explicit eject (or let it destruct)
inj->eject();          // method on Injection
vh::eject(*inj2);      // free-function alias
```

| Method | Module-list entry | Remote thread | Stealth |
|---|:---:|:---:|:---:|
| `LoadLibrary` | ✓ | ✓ | Low |
| `ManualMap` | ✗ | ✓ (shellcode) | Medium |
| `ThreadHijack` | Configurable | ✗ | High |
| `ApcQueue` | Configurable | ✗ | High |

**`Injection` methods:** `eject()` → `Result<void>`, `valid()`, `pid()`, `method()`, `tag()`, `handle()`.

**Extended injection** (17 additional techniques) is available via `#include <vh/inject_ex.hpp>` and the unified `vh::inject_by_method()` dispatcher in `#include <vh/inject_unified.hpp>`.

---

## Stealth Subsystems

All stealth headers are included automatically by `<vh/vh.hpp>`. They are Windows-only unless noted, and each returns `Error::Unsupported` on POSIX.

### Module Unhooking — `vh::unhook`

Restores a system DLL's `.text` from its `\KnownDlls` section object (or disk fallback), stripping EDR/AV inline hooks.

```cpp
#include <vh/unhook.vh>

// Restore the four most-hooked DLLs in one call
auto reports = vh::unhook::restore_defaults();

// Restore a specific module
auto r = vh::unhook::restore_module("wininet.dll");

// Diff only — see differing bytes without patching
auto diff = vh::unhook::diff_module("ntdll.dll");
```

**`RestoreReport` fields:** `module_name`, `bytes_rewritten`, `regions_rewritten`.

**`DiffReport`:** describes a single contiguous run of differing bytes (offset, size, original/current bytes).

Call `restore_defaults()` once, as early as possible in your DLL's init, before installing any other hooks.

### Syscall Gate — `vh::syscalls`

Direct and indirect syscall stubs with automatic SSN resolution. Windows x64 primary; all entry points return `Error::Unsupported` on POSIX and ARM64.

SSN resolution chain (`ResolveMode::Auto`): Hell's Gate → Halo's Gate → Tartarus Gate. Results are cached process-wide.

```cpp
#include <vh/syscalls.vh>

// Get a callable stub (indirect by default — syscall executes inside ntdll gadget)
auto stub = vh::syscalls::stub_for("NtProtectVirtualMemory");
if (stub) {
    using PFN = NTSTATUS (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    auto NtProtect = reinterpret_cast<PFN>(*stub);
    NtProtect(...);
}

// Direct stub (syscall executes in VanHooks-allocated page)
auto d = vh::syscalls::stub_for("NtAllocateVirtualMemory",
                                 vh::syscalls::StubKind::Direct);

// Raw SSN resolution (for custom stub emission)
auto ssn = vh::syscalls::resolve_ssn("NtWriteVirtualMemory");
auto ssn2 = vh::syscalls::resolve_ssn_by_hash(0xABCD1234u); // djb2 hash
```

`StubKind::Indirect` is the default and preferred — the `syscall` instruction runs at an ntdll address, matching a legitimate dispatch to kernel stack walkers.

### Call Stack Spoofing — `vh::callstack_spoof`

RAII scope that swaps the current frame's saved return address to a clean ntdll gadget, hiding the hook from user-mode stack-walking scanners.

```cpp
#include <vh/callstack_spoof.vh>

NTSTATUS __stdcall DoSensitive(...) {
    VH_CALLSTACK_SPOOF();   // return addr → ntdll gadget for this scope
    return NtProtectVirtualMemory(...);
}
```

`VH_CALLSTACK_SPOOF()` is a no-op on non-Windows and non-x64 targets.

Lower-level control:

```cpp
auto gadget = vh::callstack_spoof::pick_gadget();   // Result<void*>
auto count  = vh::callstack_spoof::gadget_count();  // number of available gadgets
vh::callstack_spoof::refresh_gadgets();             // rebuild gadget pool
```

### PEB Masking — `vh::peb_mask`

Clears debugger-indicator fields from the PEB. Windows only.

```cpp
#include <vh/peb_mask.vh>

// Apply all three masks at once (default)
vh::peb_mask::apply(vh::peb_mask::All);

// Or selectively
vh::peb_mask::apply(vh::peb_mask::BeingDebugged | vh::peb_mask::NtGlobalFlag);

// Unlink a module from PEB.Ldr (hides it from module enumeration)
vh::peb_mask::unlink_module("payload.dll");

// Reverse everything apply() and unlink_module() changed
vh::peb_mask::restore();

// Query
auto unlinked = vh::peb_mask::unlinked_modules();
```

**`Flags`:** `BeingDebugged`, `NtGlobalFlag`, `HeapFlags`, `All`.

### Thread Hiding — `vh::thread_hide`

Marks threads invisible to debugger events and protects DR registers from user-mode scanners. Windows only.

```cpp
#include <vh/thread_hide.vh>

// Hide the current thread from debugger events (NtSetInformationThread)
vh::thread_hide::hide_current_thread();

// Hide an arbitrary thread by handle
vh::thread_hide::hide_thread(thread_handle);

// Install a NtGetContextThread hook that clears DR0-DR3 for peer queries
vh::thread_hide::install_dr_camouflage();

// Check state / uninstall
bool active = vh::thread_hide::dr_camouflage_active();
vh::thread_hide::uninstall_dr_camouflage();
```

DR camouflage is best-effort against user-mode scanners; kernel-mode drivers reading via `PsGetContextThread` bypass it.

### Sleep Obfuscation — `vh::sleep_obf`

RC4-encrypts a memory region for the duration of a sleep, so in-memory scanners see ciphertext during the sleep window. Windows only.

```cpp
#include <vh/sleep_obf.vh>

// Sleep 3 s with main-module .text encrypted
HMODULE self = GetModuleHandleW(nullptr);
MODULEINFO mi{};
GetModuleInformation(GetCurrentProcess(), self, &mi, sizeof(mi));
vh::sleep_obf::sleep_encrypted(3000, mi.lpBaseOfDll, mi.SizeOfImage);

// Span overload
vh::sleep_obf::sleep_encrypted(3000, std::span<uint8_t>{ptr, size});

// Convenience: auto-locate and encrypt main-module .text
vh::sleep_obf::sleep_encrypted_main_text(3000);
```

A fresh 16-byte RC4 key is generated per sleep via `BCryptGenRandom`. The encrypted region must not contain any code executed by any thread during the sleep window.

### API Hashing — `vh::api_hash`

String-free PEB-walking module+export resolver. No API names in `.rdata`.

```cpp
#include <vh/api_hash.vh>

using namespace vh::api_hash;

// Compile-time hashes
constexpr auto H_K32 = module_djb2("kernel32.dll");
constexpr auto H_VP  = export_djb2("VirtualProtect");

// Resolve at runtime (result is cached)
using PFN_VP = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
auto VirtualProtect_ = reinterpret_cast<PFN_VP>(resolve(H_K32, H_VP));
```

Two hash functions: `djb2` / `module_djb2` (ASCII case-insensitive for module names) and `fnv1a`. Both are `constexpr`.

### Module Stomping — `vh::module_stomp`

Places a payload inside a signed system DLL's `.text` for `MEM_IMAGE` VAD attribution.

```cpp
#include <vh/module_stomp.vh>

// Auto-select a safe host, overwrite its .text with shellcode
auto s = vh::module_stomp::stomp(payload_span);
if (s) {
    auto entry = reinterpret_cast<void(*)()>(s->entry);
    entry();
    vh::module_stomp::restore(std::move(*s));
}

// Place at a specific address (manual host selection)
auto s2 = vh::module_stomp::stomp_at(address, payload_span);

// Find a suitable host address yourself
auto addr = vh::module_stomp::find_stomp_target(payload.size());
```

**`Stomp` fields:** `entry` (void* entry point in the host), `host_base`, `host_size`, original bytes for restore.

### VEH Hook — `vh::veh_hook`

INT3/BRK-based breakpoint hook via the Vectored Exception Handler. No DR registers; coexists with HwBp hooks. Up to 256 concurrent VEH hooks.

```cpp
#include <vh/veh_hook.vh>

auto h = vh::veh_hook::install(&target_fn,
    [](vanhooks::MidContext* ctx) noexcept { ctx->rax = 0; });

// Explicit remove
vh::veh_hook::remove(*h);

// Remove all VEH hooks installed by this module
vh::veh_hook::remove_all();
```

**`Handle` fields:** `id`. Use `handle.valid()` to test validity.

---

## Symbol Resolution

**Requires `VH_SYMBOLS_ENABLED`. DbgHelp (Windows) / `dladdr` + libbacktrace (POSIX).**

```cpp
#include <vh/symbols.hpp>

// Initialize (called automatically on first use; explicit call recommended
// before entering performance-critical paths or before load_module())
vh::symbols::initialize();

// Resolve an address to its nearest symbol
auto sym = vh::symbols::resolve(address);
if (sym)
    printf("%s + 0x%zx  [%s]\n",
           sym->name.c_str(), address - sym->address, sym->module.c_str());

// Function-pointer overload
auto sym2 = vh::symbols::resolve(&MessageBoxW);

// Find a symbol's address by name
auto addr = vh::symbols::find("NtQuerySystemInformation", "ntdll.dll");

// Source file + line number
auto loc = vh::symbols::source_location(address);

// Pre-load symbols for a module (call before resolving from that module)
vh::symbols::load_module("C:\\Windows\\System32\\ntdll.dll");

// Capture and format the current call stack (annotated strings)
for (auto& line : vh::symbols::current_stack())
    puts(line.c_str());

// Demangle a C++ symbol
auto name = vh::symbols::demangle(raw_name);
```

**`Symbol` fields:** `name`, `raw_name`, `address`, `size`, `module`, `file`, `line`.

---

## PE Introspection

**Windows only.**

```cpp
#include <vh/pe.hpp>

// Open by module name (empty string = main executable)
auto pe = vh::pe::open("ntdll.dll");

// Open at a known base address
auto pe2 = vh::pe::open_at(base_va);

// Open by HMODULE
auto pe3 = vh::pe::open_handle(hmod);

// Sections
for (auto& s : pe->sections().value_or({}))
    printf("%-8s  VA=0x%llx  %c%c%c\n",
           s.name.c_str(), (ull)s.virtual_address,
           s.readable() ? 'R' : '-',
           s.writable() ? 'W' : '-',
           s.executable() ? 'X' : '-');

// Exports
auto exp  = pe->find_export("NtQuerySystemInformation");
auto exp2 = pe->find_export_by_ordinal(42);

// Imports
auto imports = pe->imports_from("kernel32.dll");
auto imp     = pe->find_import("kernel32.dll", "VirtualProtect");

// Code caves
for (auto& cave : pe->find_caves(32, /*exec_only=*/true))
    printf("cave @ 0x%llx  %zu bytes  [%s]\n",
           (ull)cave.address, cave.size, cave.section_name);

// All loaded modules
for (auto& m : vh::pe::modules().value_or({}))
    printf("%s  base=0x%llx\n", m.name().data(), (ull)m.base());
```

**`PeView` methods:** `base()`, `name()`, `sections()`, `find_export()`, `find_export_by_ordinal()`, `imports_from()`, `find_import()`, `find_caves()`.

---

## Breakpoints

**Requires `VH_BREAKPOINT_ENABLED`.**

```cpp
#include <vh/breakpoint.hpp>

// Software (INT3 / VEH on Windows; SIGTRAP on Linux)
auto sw = vh::breakpoint::set_software(addr,
    [](uintptr_t a) { return vh::breakpoint::Action::Continue; });

// Hardware (DR0–DR3, x86-64 only)
auto hw = vh::breakpoint::set_hardware(addr,
    vh::breakpoint::HwCondition::Write,
    vh::breakpoint::HwSize::Dword,
    [](uintptr_t a) { return vh::breakpoint::Action::Remove; });

// Propagate to a new thread (Windows, hardware BPs only)
hw->apply_to_new_thread(new_thread_handle);
```

**`Action`:** `Continue` (re-arm) · `Remove` (one-shot)

**`HwCondition`:** `Execute` · `Write` · `ReadWrite`

**`HwSize`:** `Byte` · `Word` · `Dword` · `Qword` (x64 only)

**`Breakpoint` methods:** `remove()` · `active()` · `address()`

---

## Call Stack Capture

**Requires `VH_CALLSTACK_ENABLED`.**

```cpp
#include <vh/callstack.hpp>

// Raw addresses
auto frames = vh::callstack::capture(/*skip=*/2, /*max_depth=*/32);
for (auto addr : frames.value_or({}))
    printf("  0x%016llx\n", addr);

// Annotated frames (requires VH_SYMBOLS_ENABLED)
auto ann = vh::callstack::capture_annotated();
if (ann) puts(vh::callstack::format(*ann).c_str());
```

`kMaxDepth` is 64. Platform backend: `RtlCaptureStackBackTrace` on Windows, `backtrace()` on POSIX.

---

## VanTrace

Structured runtime event tracing. Lock-free ring buffer, background consumer, pluggable sinks. **Requires `VH_TRACE_ENABLED`.**

```cpp
#include <vh/trace.hpp>   // or <vh/vh.hpp> with VH_TRACE_ENABLED
```

### Lifecycle

```cpp
vh::Tracer tracer(cfg);        // construct (background thread not yet running)
tracer.set_sink(my_sink);      // install a sink
tracer.set_filter(my_filter);  // optional: pre-buffer gate
tracer.start();                // start consumer thread

// ... install hooks and attach them ...

tracer.stop();                 // flush + join consumer
// destructor calls stop() automatically
```

### Sinks

| Type | Description |
|---|---|
| `vh::NullSink` | Discards all events. Default. |
| `vh::CallbackSink` | Calls `std::function<void(const TraceEvent&, const TraceMeta*)>` per event. |
| Custom `vh::ISink` | Implement `on_events(span<const TraceEvent>, meta_for_fn)` and optionally `flush()`. |

```cpp
auto sink = std::make_shared<vh::CallbackSink>(
    [](const vh::TraceEvent& ev, const vh::TraceMeta* meta) {
        if (ev.kind == vh::TraceEventKind::HookEnter)
            printf("[ENTER] %s  tid=%u  depth=%u\n",
                   meta ? meta->tag.c_str() : "?",
                   ev.thread_id, ev.call_depth);
        else if (ev.kind == vh::TraceEventKind::HookExit)
            printf("[EXIT]  %s  duration=%lldns\n",
                   meta ? meta->tag.c_str() : "?",
                   ev.duration.count());
    });
tracer.set_sink(sink);
```

### Attaching hooks

`vh::Tracer::attach()` accepts a `vh::Hook` directly (Cooperative mode — the detour calls `enter()`/`exit()` manually or via `CallScope`). For Transparent auto-instrumentation, use the underlying `tracer.inner().attach()` with an explicit `AttachMode`.

```cpp
// Cooperative attach (default)
auto h = vh::hook("d3d9.dll", "EndScene", &hk_EndScene, &orig_EndScene).value();
static vh::AttachedHook g_hook = tracer.attach(h, "d3d9.EndScene").value();

// Transparent attach — auto-instruments entry + exit (x64; degrades gracefully)
tracer.inner().attach(h.engine(), h.handle(),
                      "d3d9.EndScene",
                      vanhooks::trace::AttachMode::Transparent);
```

### Cooperative usage — `CallScope`

```cpp
static vh::AttachedHook g_es_hook;

HRESULT __stdcall hk_EndScene(IDirect3DDevice9* dev) {
    vh::CallScope scope(g_es_hook);   // HookEnter on construct, HookExit on destruct
    return orig_EndScene(dev);
}
```

Manual form (when you need to pair the timestamps yourself):

```cpp
HRESULT __stdcall hk_EndScene(IDirect3DDevice9* dev) {
    auto ts = g_es_hook.enter();
    HRESULT hr = orig_EndScene(dev);
    g_es_hook.exit(ts);
    return hr;
}
```

### `AttachedHook` methods

| Method | Description |
|---|---|
| `enter()` | Records `HookEnter`. Returns `TimePoint` for pairing with `exit()`. |
| `exit(TimePoint)` | Records `HookExit` with duration computed from `enter()`. |
| `capture_context(data, size)` | Stores up to 64 bytes in thread-local storage; attached to the next `HookEnter` on this thread. |
| `valid()` | True if the hook is still registered with the tracer. |
| `meta()` | Returns `const TraceMeta&` — handle, kind, target, detour, tag. |

### Raw context capture

```cpp
HRESULT __stdcall hk_CreateBuffer(ID3D11Device* dev,
                                   D3D11_BUFFER_DESC* desc, ...)
{
    g_hook.capture_context(desc, sizeof(*desc));
    vh::CallScope scope(g_hook);
    return orig(dev, desc, ...);
}
// In the sink: ev.has_context == true, ev.context holds the raw bytes
```

`kRawContextCapacity` is 64 bytes. Larger captures are silently truncated.

### Filters

Pre-buffer gate — events that fail the filter never enter the ring:

```cpp
vh::TraceFilter f;
f.include_handles  = { h1.handle(), h2.handle() };  // empty = all hooks
f.include_kinds    = { vanhooks::HookKind::CallSite };
f.include_threads  = { GetCurrentThreadId() };
f.min_duration     = std::chrono::microseconds(100); // HookExit events only
f.sample_every_n   = 10;                             // every 10th event per hook

tracer.set_filter(f);
```

### Configuration

```cpp
vh::TraceConfig cfg;
cfg.ring_capacity     = 8192;  // must be power of two; default 4096
cfg.overflow_policy   = vanhooks::trace::OverflowPolicy::BlockNewer; // or DropOldest
cfg.enable_timing     = true;
cfg.enable_thread_id  = true;
cfg.enable_call_depth = true;

vh::Tracer tracer(cfg);
```

| `OverflowPolicy` | Behaviour when ring is full |
|---|---|
| `BlockNewer` | Drop the incoming event. Default. |
| `DropOldest` | Overwrite the oldest unconsumed event. |

### `TraceEvent` fields

| Field | Type | Description |
|---|---|---|
| `kind` | `TraceEventKind` (`EventKind`) | `HookEnter`, `HookExit`, `TraceDropped` |
| `hook_kind` | `HookKind` | Trampoline / IAT / PLT / VTable / Mid / CallSite / HwBp / PageGuard / IC |
| `hook_id` | `uint64_t` | Matches `HookHandle::id` |
| `thread_id` | `uint32_t` | OS thread ID |
| `timestamp` | `TimePoint` | Monotonic clock point |
| `duration` | `Duration` | `HookExit` only: ns between enter/exit |
| `call_depth` | `uint32_t` | Thread-local nesting depth |
| `has_context` | `bool` | Whether `context` is populated |
| `context` | `RawContext` | Up to 64 bytes from `capture_context()` |
| `dropped_count` | `uint64_t` | `TraceDropped` only: events lost |

### Statistics

```cpp
auto s = tracer.stats();
printf("produced=%llu  consumed=%llu  dropped=%llu  overflows=%llu\n",
       s.events_produced, s.events_consumed,
       s.events_dropped,  s.buffer_overflows);
```

### Detaching

```cpp
tracer.detach(g_hook.meta().handle);   // by HookHandle
tracer.detach(h);                      // by vh::Hook
```

After detach, `AttachedHook::valid()` returns `false`. Outstanding `CallScope` objects in flight complete normally.

### Custom sink example

```cpp
class BinaryFileSink : public vh::ISink {
public:
    explicit BinaryFileSink(const char* path) : f_(fopen(path, "wb")) {}
    ~BinaryFileSink() { if (f_) fclose(f_); }

    void on_events(std::span<const vh::TraceEvent> events,
                   const std::function<const vh::TraceMeta*(uint64_t)>&) override
    {
        if (f_) fwrite(events.data(), sizeof(vh::TraceEvent), events.size(), f_);
    }

    void flush() override { if (f_) fflush(f_); }

private:
    FILE* f_;
};

tracer.set_sink(std::make_shared<BinaryFileSink>("vantrace.bin"));
```

---

## Network API

Requires Npcap (Windows) / libpcap (POSIX). Types in `vh::net::`.

### Devices

```cpp
for (const auto& d : vh::net::devices())
    printf("%-20s %s  loopback=%d\n", d.name.c_str(), d.ip4.c_str(), d.loopback);
```

**`DeviceInfo` fields:** `name`, `description`, `ip4`, `loopback`.

### Live capture

```cpp
auto cap = vh::net::Capture::open("eth0").value();       // by name
auto cap2 = vh::net::Capture::open_by_ip("10.0.0.5").value(); // by IP

cap.filter("tcp port 443")
   .snap_len(65535)
   .promiscuous(true);

cap.start([](vh::net::Packet p) {
    auto parsed = p.parse();
    if (auto* tcp = parsed->getLayerOfType<vanhooks::net::TcpLayer>())
        printf("%u -> %u\n", tcp->getSrcPort(), tcp->getDstPort());
});

cap.stop();
auto s = cap.stats();   // optional<Stats> — received, dropped, if_dropped
```

> ⚠️ The `Packet` passed to the callback is a non-owning view. Copy `raw_data()` if you need it after the callback returns.

### Offline files

```cpp
// Read pcap / pcapng
auto r = vh::net::PcapReader::open("dump.pcap").value();
r.filter("udp port 53");
while (auto pkt = r.next()) { /* process */ }
printf("read %llu packets\n", r.packets_read());

// Write
auto w = vh::net::PcapWriter::open("out.pcap").value();
w.write(*pkt);
printf("wrote %llu packets\n", w.packets_written());
```

### Parsed layers

```cpp
auto parsed = pkt.parse();
parsed->getFirstLayer();
parsed->getLastLayer();
parsed->getLayerOfType<vanhooks::net::IPv4Layer>();
parsed->getLayerOfType<vanhooks::net::TcpLayer>();
```

Common layer classes: `EthLayer`, `VlanLayer`, `ArpLayer`, `IPv4Layer`, `IPv6Layer`, `IcmpLayer`, `TcpLayer`, `UdpLayer`, `VxlanLayer`.

---

## Quick Reference

```cpp
#include <vh/vh.hpp>
```

**Level 1**
```cpp
// Function-pointer targets
vh::hook(&fn, &det)
vh::hook(&fn, &det, &orig)
vh::hook("module", "Symbol", &det, &orig)

// Runtime address targets
vh::hook(0x5D5DB0u, &det)
vh::hook(0x5D5DB0u, &det, &orig)
```

**Level 2**
```cpp
vh::inline_hook(&fn,        &det, &orig, { .tag = "x" })
vh::inline_hook(0x5D5DB0u, &det, &orig, { .tag = "x" })
vh::api_hook    ("mod", "sym", &det, &orig)
vh::vtable_hook (vtbl,  slot,  det, nullptr)
vh::iat_hook    ("Sym", det,  { .module_name = "m.exe" })
vh::iat_hook_all("Sym", det)
vh::plt_hook    ("lib", "sym", det)
vh::mid_hook    (ptr,   cb,   { .offset = 0x1C })

// CallSite
vh::callsite_hook(0x12AB34u, &det, &orig)
vh::callsite_hook(&site_fn, &det, &orig)

// HwBp (Windows x64 only)
vh::hwbp_hook(&fn, cb)
vh::hwbp_hook(reinterpret_cast<void*>(addr), cb, { .dr_slot = 1 })

// PageGuard (Windows only)
vh::page_guard_hook(&fn, cb, { .auto_rearm = true })

// Instrumentation Callback (Windows x64 only, singleton)
vh::ic_hook(&my_naked_stub)

// Return hook — Engine API (x64 only)
vanhooks::global_engine().hook_mid_return(ptr, 0, enter_cb, return_cb)
```

**Hook methods**
```cpp
h.enable()       // → Hook& (chainable)
h.disable()      // → Hook&
h.remove()       // → void
h.valid()        h.enabled()      h.tag()
h.kind()         h.target()       h.detour()       h.trampoline()
h.chain(&det2, &orig2, "tag")
```

**Group**
```cpp
auto g = vh::group("Name");
g.add(vh::hook(...)).add(vh::vtable_hook(...));

// Address-based trampoline
g.hook_at(0x5D5DB0u, &det);
g.hook_at(0x5D5DB0u, &det, &orig, { .tag = "x" });

// HwBp
g.hook_hwbp(addr, cb);
g.hook_hwbp(fn_ptr, cb, { .dr_slot = 1 });

// CallSite — direct address
g.hook_callsite(0x12AB34u, &det, &orig);

// CallSite — pattern scan
g.hook_callsite_pattern("E8 ? ? ? ? 83 C4 04", 0,  &det, &orig);
g.hook_callsite_pattern("89 04 24 E8 ? ? ? ?",  3,  &det, &orig);
g.hook_callsite_pattern("E8 ? ? ? ? 85 C0",     0, 2, &det, &orig);  // Nth match

// Trampoline pattern scan
g.hook_pattern("E8 ? ? ? ? 83 C4 04", -5, &det);

// Memory patches
g.patch<uint8_t>(0x581E72, 32);
g.nop(0x14E738B, 2);

// Lifecycle
g.enable();    g.disable();    g.remove_all();
g.at("tag");   // → Hook& (throws std::out_of_range if not found)
for (auto& h : g) { ... }
g.queue_enable().apply();
```

**Engine access**
```cpp
auto& eng = vanhooks::global_engine();   // or vh::advanced::engine()
eng.queue_enable(h.handle());
eng.queue_disable(h.handle());
eng.apply_queued();
eng.hook_mid_return(ptr, 0, enter_cb, return_cb);  // x64 only
eng.chain(h.handle(), (void*)&det2, (void**)&orig2);
```

**Stealth subsystems**
```cpp
// Module unhooking
vh::unhook::restore_defaults();
vh::unhook::restore_module("ntdll.dll");
vh::unhook::diff_module("ntdll.dll");

// Syscall gate
auto stub = vh::syscalls::stub_for("NtProtectVirtualMemory");   // Indirect (default)
auto stub2 = vh::syscalls::stub_for("NtAlloc", vh::syscalls::StubKind::Direct);
vh::syscalls::resolve_ssn("NtWriteVirtualMemory");

// Call stack spoofing
VH_CALLSTACK_SPOOF();                     // in function body
vh::callstack_spoof::pick_gadget();

// PEB masking
vh::peb_mask::apply(vh::peb_mask::All);
vh::peb_mask::unlink_module("payload.dll");
vh::peb_mask::restore();

// Thread hiding
vh::thread_hide::hide_current_thread();
vh::thread_hide::install_dr_camouflage();

// Sleep obfuscation
vh::sleep_obf::sleep_encrypted(3000, ptr, size);
vh::sleep_obf::sleep_encrypted_main_text(3000);

// API hashing
constexpr auto H_K32 = vh::api_hash::module_djb2("kernel32.dll");
constexpr auto H_VP  = vh::api_hash::export_djb2("VirtualProtect");
auto fn_ptr = vh::api_hash::resolve(H_K32, H_VP);

// Module stomping
auto s = vh::module_stomp::stomp(payload_span);
vh::module_stomp::stomp_at(address, payload_span);
vh::module_stomp::restore(std::move(*s));

// VEH hook
vh::veh_hook::install(&target_fn, cb);
vh::veh_hook::remove(*h);
vh::veh_hook::remove_all();
```

**VanTrace**
```cpp
vh::Tracer tracer(cfg);
tracer.set_sink(sink);
tracer.set_filter(filter);
tracer.start();

// Cooperative attach
tracer.attach(h)
tracer.attach(h, "tag")

// Transparent attach (via inner tracer)
tracer.inner().attach(eng, handle, "tag", vanhooks::trace::AttachMode::Transparent)

// Inside cooperative detour
vh::CallScope scope(g_hook);
g_hook.capture_context(ptr, sz);

tracer.detach(g_hook.meta().handle);
auto s = tracer.stats();
tracer.stop();
```

**Pattern scanner**
```cpp
vanhooks::scanner::scan_process("48 8B 05 ? ? ? ?");
vanhooks::scanner::scan_module("game.exe", "48 89 5C 24 ?");
vanhooks::scanner::scan_pattern(base, size, "E8 ? ? ? ? 85 C0");
vanhooks::scanner::scan_bytes(base, size, needle_span);
auto pat = vanhooks::scanner::parse_pattern("48 8B 05 ? ? ? ?").value();
```

**Anti-debug**
```cpp
auto report = vanhooks::antidebug::check_all();
report.any_detected();    report.detection_count();    report.findings;
```

**Disassembler**
```cpp
vh::disasm::Disassembler dis;
dis.decode_one(span, va);
vh::disasm::decode_until_branch(fn, 128);
vh::disasm::decode_prologue(fn, 14);
vh::disasm::safe_copy_length(fn, 5);
vh::disasm::rewrite(insns, old_va, new_va);
vh::disasm::format_listing(insns);
```

**Injection (Windows)**
```cpp
vh::inject(pid, "payload.dll", { .method = vh::InjectMethod::ManualMap });
vh::inject_from_memory(pid, pe_bytes, { .method = vh::InjectMethod::ThreadHijack });
inj->eject();
vh::eject(*inj);
```

**Symbols**
```cpp
vh::symbols::initialize();
vh::symbols::resolve(address);
vh::symbols::resolve(&fn_ptr);
vh::symbols::find("CreateFileW", "KernelBase");
vh::symbols::source_location(address);
vh::symbols::load_module("ntdll.dll");
vh::symbols::current_stack();
vh::symbols::demangle(raw_name);
```

**PE (Windows)**
```cpp
auto pe = vh::pe::open("ntdll.dll");
auto pe = vh::pe::open_at(base_va);
auto pe = vh::pe::open_handle(hmod);
pe->sections();    pe->find_export("Fn");    pe->find_export_by_ordinal(42);
pe->imports_from("k32");    pe->find_import("k32", "VP");
pe->find_caves(32, true);
vh::pe::modules();
```

**Breakpoints**
```cpp
vh::breakpoint::set_software(addr, cb);
vh::breakpoint::set_hardware(addr, HwCondition::Write, HwSize::Dword, cb);
bp->remove();    bp->active();    bp->apply_to_new_thread(h);
```

**Call stack**
```cpp
vh::callstack::capture(2, 32);
vh::callstack::capture_annotated();
vh::callstack::format(frames);
```

**Network**
```cpp
vh::net::devices();
auto cap = vh::net::Capture::open("eth0").value();
auto cap = vh::net::Capture::open_by_ip("10.0.0.5").value();
cap.filter("tcp port 443").start([](vh::net::Packet p) { ... });
auto r = vh::net::PcapReader::open("in.pcap").value();
auto w = vh::net::PcapWriter::open("out.pcap").value();
```

---

<div align="center">
<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:0A0A0A,50:7A0C0C,100:0A0A0A&height=90&section=footer"/>
</div>
