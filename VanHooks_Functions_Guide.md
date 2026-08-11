<div align="center">
<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:0A0A0A,50:7A0C0C,100:0A0A0A&height=170&section=header&text=Functions%20Guide&fontSize=48&fontColor=FF4444&animation=fadeIn&fontAlignY=40&desc=Public%20API%20Reference%20%C2%B7%20v1.0.0&descAlignY=62&descSize=14&descColor=B8B8B8"/>

[![Standard](https://img.shields.io/badge/C%2B%2B-23-FF4444?style=flat-square&labelColor=0A0A0A)](https://en.cppreference.com/w/cpp/23)
[![Windows](https://img.shields.io/badge/Windows-x86%20%7C%20x64-FF4444?style=flat-square&labelColor=0A0A0A)](lib/)
[![Linux](https://img.shields.io/badge/Linux-x64%20%7C%20ARM64-FF4444?style=flat-square&labelColor=0A0A0A)](lib/)
[![macOS](https://img.shields.io/badge/macOS-x64%20%7C%20ARM64-FF4444?style=flat-square&labelColor=0A0A0A)](lib/)

</div>

<br/>

One include. Everything in this document lives in the `vh::` namespace unless stated otherwise.

```cpp
#include <vh/vh.hpp>
```

---

## Contents

[Glossary](#glossary) · [Result Type](#result-type) · [Level 1 API](#level-1-api) · [Level 2 API](#level-2-api) · [Hook Object](#hook-object) · [Group](#group) · [HookRegistry](#hookregistry) · [Config Structs](#config-structs) · [Error Codes](#error-codes) · [Pattern Scanner](#pattern-scanner) · [Anti-Debug Detection](#anti-debug-detection) · [Disassembler](#disassembler) · [Process Injection](#process-injection) · [Symbol Resolution](#symbol-resolution) · [PE Introspection](#pe-introspection) · [Breakpoints](#breakpoints) · [Call Stack Capture](#call-stack-capture) · [Network API](#network-api) · [Quick Reference](#quick-reference)

---

## Glossary

Seven terms used throughout this document.

| Term | Meaning |
|---|---|
| **Hook** | Both the act of interception and the RAII object representing it. Owns the interception for its lifetime; removes it automatically on destruction. |
| **Target** | The function or address being intercepted. Calls to it are redirected to the detour unless reached through the original pointer. |
| **Detour** | Your replacement function. Must match the target's calling convention and signature exactly. |
| **Original** | A function pointer VanHooks fills in so your detour can call through to the real function, bypassing the hook. |
| **Enable** | Activate a hook so calls to the target go to the detour. Default state when created. |
| **Disable** | Deactivate a hook without removing it. Target behaves as unhooked; the object remains valid and re-enableable. |
| **Remove** | Permanently uninstall a hook and release all resources. The `Hook` destructor does this automatically. |

---

## Result Type

Every hook creation function returns `Result<Hook>`. `Result<T>` is an alias for `std::expected<T, vh::Error>` — no exceptions, no global error state, zero overhead on the success path. The network API (see [Network API](#network-api)) reuses the same `Result<T>` and a `Status` alias (`Result<void>`) for its own fallible operations.

**Checking the result:**

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

Returns a human-readable name for any `Error` code as a `string_view` into static storage — do not free it.

---

## Level 1 API

The three overloads of `vh::hook()` cover the most common cases with no options struct required.

---

### `vh::hook(target, detour)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(Fn* target, Fn* detour);
```

Intercepts `target` so calls go to `detour`. Hook is enabled immediately. No call-through — use the three-argument form if you need the original.

| | |
|---|---|
| `target` | Pointer to the function to intercept. Must not be null. |
| `detour` | Replacement function. Same signature as `target`. |

```cpp
int detour_add(int a, int b) {
    printf("add intercepted\n");
    return a + b;
}

auto r = vh::hook(&add, &detour_add);
```

---

### `vh::hook(target, detour, original_out)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(Fn* target, Fn* detour, Fn** original_out);
```

Same as above, but writes the trampoline address into `*original_out` so your detour can call the real function.

| | |
|---|---|
| `target` | Pointer to the function to intercept. |
| `detour` | Replacement function. |
| `original_out` | Address of a matching function pointer variable. Declare as `static Fn* orig = nullptr;`. |

```cpp
static int (*orig_add)(int, int) = nullptr;

int detour_add(int a, int b) {
    printf("add(%d, %d)\n", a, b);
    return orig_add(a, b);
}

auto r = vh::hook(&add, &detour_add, &orig_add);
```

---

### `vh::hook(module, symbol, detour, original_out)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(std::string_view module,
                      std::string_view symbol,
                      Fn* detour,
                      Fn** original_out = nullptr);
```

Resolves `target` by module and symbol name, then installs an inline hook. Uses `GetProcAddress` on Windows and `dlsym` on Linux / macOS.

| | |
|---|---|
| `module` | Module name — `"user32"` or `"user32.dll"` on Windows; `"libm"` or `"libm.so.6"` on POSIX. |
| `symbol` | Exported symbol name, e.g. `"MessageBoxW"` or `"malloc"`. |
| `detour` | Replacement function. |
| `original_out` | Optional. Same as the three-argument form. |

```cpp
static decltype(&MessageBoxW) orig_mbw = nullptr;

BOOL WINAPI hk_mbw(HWND h, LPCWSTR t, LPCWSTR c, UINT f) {
    return orig_mbw(h, L"[Intercepted]", c, f);
}

auto r = vh::hook("user32", "MessageBoxW", &hk_mbw, &orig_mbw);
```

---

## Level 2 API

Explicit hook types — same `Result<Hook>` return, access to the full options struct.

---

### `vh::inline_hook`

```cpp
template<typename Fn>
Result<Hook> vh::inline_hook(Fn* target,
                             Fn* detour,
                             Fn** original_out = nullptr,
                             config::Trampoline opts = {});
```

Patches the first bytes of `target` with a jump and builds a trampoline. Works on any function whose prologue is long enough — 5 bytes on x86/x64, 16 bytes on ARM64. The template enforces that `target` and `detour` share the same type; mismatches are compile errors.

Options: [`config::Trampoline`](#configtrampoline)

```cpp
auto r = vh::inline_hook(&add, &detour_add, &orig_add,
                         { .tag = "Math.add" });
```

---

### `vh::api_hook`

```cpp
template<typename Fn>
Result<Hook> vh::api_hook(std::string_view module,
                          std::string_view symbol,
                          Fn* detour,
                          Fn** original_out = nullptr,
                          config::Trampoline opts = {});
```

Resolves the target by module and symbol name, then installs an inline hook. Equivalent to `vh::hook(module, symbol, …)` with access to the full options struct.

Options: [`config::Trampoline`](#configtrampoline)

```cpp
auto r = vh::api_hook("user32", "MessageBoxW",
                      &hk_mbw, &orig_mbw,
                      { .thread_safe = true, .tag = "User32.MessageBoxW" });
```

---

### `vh::vtable_hook`

```cpp
Result<Hook> vh::vtable_hook(void** vtable,
                             size_t slot,
                             void* detour,
                             void** original_out = nullptr,
                             config::VTable opts = {});
```

Patches a single slot in a C++ virtual function table. Obtain the vtable pointer from any object of the target class:

```cpp
void** vtbl = *reinterpret_cast<void***>(object_pointer);
```

Slots are zero-indexed in declaration order. Inherited virtual methods appear first; the derived class's own virtuals follow.

| | |
|---|---|
| `vtable` | Pointer to the vtable array. |
| `slot` | Zero-based index of the virtual method to replace. |
| `detour` | Replacement function matching the virtual method's signature, including the implicit `this` as the first argument. |
| `original_out` | Optional. Filled with a callable pointer to the original slot value. |

Options: [`config::VTable`](#configvtable)

```cpp
void** vtbl = *reinterpret_cast<void***>(swap_chain);

static HRESULT (STDMETHODCALLTYPE *orig_Present)
    (IDXGISwapChain*, UINT, UINT) = nullptr;

HRESULT STDMETHODCALLTYPE hk_Present(IDXGISwapChain* sc, UINT sync, UINT flags) {
    return orig_Present(sc, sync, flags);
}

auto r = vh::vtable_hook(vtbl, 8,
                         (void*)&hk_Present,
                         (void**)&orig_Present,
                         { .tag = "DXGI.Present" });
```

---

### `vh::iat_hook`

```cpp
Result<Hook> vh::iat_hook(std::string_view import_name,
                          void* detour,
                          config::IAT opts = {});
```

**Windows only.** Patches one Import Address Table entry so calls from a specific module to `import_name` go to `detour`. Does not modify the target function itself — patches the calling module's import pointer instead. Use this for functions too short to inline-hook, or when you want to intercept calls from one module only.

| | |
|---|---|
| `import_name` | Exported symbol name to redirect, e.g. `"MessageBoxW"`. |
| `detour` | Replacement function pointer (`void*`). |

Options: [`config::IAT`](#configiat)

```cpp
auto r = vh::iat_hook("MessageBoxW", (void*)&hk_mbw,
                      { .module_name = "my_app.exe",
                        .tag = "IAT.MessageBoxW" });
```

---

### `vh::iat_hook_all`

```cpp
Result<std::vector<Hook>> vh::iat_hook_all(std::string_view import_name,
                                           void* detour,
                                           config::IAT opts = {});
```

**Windows only.** Same as `iat_hook` but patches every IAT entry matching `import_name` across all currently-loaded modules. Returns a vector of `Hook` objects, one per patched slot. The `module_name` field in the options struct is ignored.

```cpp
auto hooks = vh::iat_hook_all("malloc", (void*)&hk_malloc);
if (hooks) {
    printf("patched %zu IAT slots\n", hooks->size());
}
```

---

### `vh::plt_hook`

```cpp
Result<Hook> vh::plt_hook(std::string_view library,
                          std::string_view symbol,
                          void* detour,
                          config::PLT opts = {});
```

**Linux and macOS only.** Patches a Procedure Linkage Table entry (Linux) or lazy pointer (macOS) so calls to `symbol` from `library` are redirected to `detour`. The POSIX equivalent of `iat_hook`.

| | |
|---|---|
| `library` | Shared library name, e.g. `"libc"` or `"libpthread"`. |
| `symbol` | Symbol name, e.g. `"malloc"` or `"pthread_create"`. |
| `detour` | Replacement function pointer (`void*`). |

Options: [`config::PLT`](#configplt)

```cpp
static void* (*orig_malloc)(size_t) = nullptr;

void* hk_malloc(size_t size) {
    void* p = orig_malloc(size);
    printf("malloc(%zu) = %p\n", size, p);
    return p;
}

auto r = vh::plt_hook("libc", "malloc", (void*)&hk_malloc,
                      { .tag = "libc.malloc" });
```

---

### `vh::mid_hook`

```cpp
Result<Hook> vh::mid_hook(void* target,
                          MidCallback callback,
                          config::Mid opts = {});
```

Installs a hook at a byte offset inside a function rather than at its entry point. Does not redirect control flow — exposes CPU register state at that instruction boundary via `MidContext*`, lets you read or write it, then continues original execution. The hook site is rounded to the nearest complete instruction boundary.

| | |
|---|---|
| `target` | Pointer to the start of the function containing the hook site. |
| `callback` | Called at the hook site. Receives a `MidContext*` with a snapshot of all general-purpose registers and flags. Must be `noexcept`. |

Options: [`config::Mid`](#configmid)

**`MidCallback` signature:**

```cpp
using MidCallback = void (*)(MidContext*) noexcept;
```

**`MidContext` register fields:**

<details open>
<summary>x64</summary>

| Field | Type |
|---|---|
| `rax` … `r15` | `uint64_t` |
| `rflags` | `uint64_t` |

</details>

<details>
<summary>x86</summary>

| Field | Type |
|---|---|
| `eax` … `edi` | `uint32_t` |
| `eflags` | `uint32_t` |

</details>

<details>
<summary>ARM64</summary>

| Field | Type |
|---|---|
| `x[8]` | `uint64_t[8]` — argument registers x0–x7 |
| `lr` | `uint64_t` — link register (x30) |

</details>

Writes to `MidContext` fields take effect when the callback returns.

```cpp
auto r = vh::mid_hook(game_update_ptr,
    [](vh::MidContext* ctx) noexcept {
        player_health = static_cast<int>(ctx->rax);
    },
    { .offset = 0x1C, .tag = "Game.HealthReadback" });
```

---

## Hook Object

Every creation function returns `Result<Hook>`. Dereference the result to get the `Hook`. Move-only — cannot be copied. The destructor calls `remove()` automatically.

### Lifecycle

| Method | Signature | Description |
|---|---|---|
| `enable` | `Hook& enable()` | Activates the hook. No-op if already enabled. Returns `*this`. |
| `disable` | `Hook& disable()` | Deactivates without removing. Returns `*this`. |
| `remove` | `void remove()` | Permanently uninstalls. `valid()` returns `false` afterward. The destructor calls this. |

### Chaining

A second detour inserted in front of an existing hook. Execution after chaining:

```
next_detour → original_detour → real_function
```

Chain links **must be removed before the base hook**. Removing the base first returns `Error::ChainOrderViolation`.

```cpp
Result<Hook> hook.chain(void* next_detour,
                        void** next_original_out = nullptr,
                        std::string tag = {})

Result<Hook> hook.chain(Fn* next_detour,
                        Fn** next_original_out = nullptr,
                        std::string tag = {})
```

```cpp
auto base = vh::inline_hook(&fn, &detour1, &orig1).value();

static decltype(&fn) next_orig = nullptr;
auto link = base.chain(&detour2, &next_orig).value();

// remove in reverse:
link.remove();
base.remove();
```

### Introspection

| Method | Return Type | Description |
|---|---|---|
| `valid()` | `bool` | Hook is installed and usable. |
| `enabled()` | `bool` | Hook is currently active. |
| `tag()` | `std::string` | Label set at creation, or empty. |
| `kind()` | `HookKind` | Which hook type this is. |
| `target()` | `void*` | Address of the original function. |
| `detour()` | `void*` | Address of the replacement function. |
| `trampoline()` | `void*` | Call-through trampoline address. `nullptr` for IAT, PLT, and VTable hooks. |
| `operator bool()` | `bool` | Equivalent to `valid()`. |

**`HookKind` values:**

| Value | Set by |
|---|---|
| `HookKind::Trampoline` | `inline_hook`, `api_hook` |
| `HookKind::IAT` | `iat_hook`, `iat_hook_all` |
| `HookKind::PLT` | `plt_hook` |
| `HookKind::VTable` | `vtable_hook` |
| `HookKind::Mid` | `mid_hook` |

---

## Group

Owns a collection of `Hook` objects and manages their lifecycle together. All enable/disable operations on a `Group` happen inside a single thread-suspension window — significantly cheaper than operating on each hook individually. The `Group` destructor removes all hooks automatically.

```cpp
auto grp = vh::group("GroupName");
```

### Adding hooks

```cpp
Group& grp.add(Hook hook)           // takes ownership
Group& grp.add(Result<Hook> result) // silently skips errors — safe for inline chaining
```

```cpp
grp.add(vh::vtable_hook(vtbl, 8,  (void*)&hk_Present))
   .add(vh::vtable_hook(vtbl, 16, (void*)&hk_Reset))
   .add(vh::iat_hook("CreateDevice", (void*)&hk_CreateDevice));
```

### Lifecycle

| Method | Signature | Description |
|---|---|---|
| `enable` | `Group& enable()` | Enables all hooks in one thread-suspension window. Returns `*this`. |
| `disable` | `Group& disable()` | Disables all hooks. Returns `*this`. |
| `remove_all` | `void remove_all()` | Removes and destroys all hooks. Group is empty afterward but still usable. |
| `clear` | `void clear()` | Alias for `remove_all()`. |

### Queued batch operations

Queue operations across multiple steps, then flush once for very large hook sets.

| Method | Description |
|---|---|
| `queue_enable()` | Queues enable for all hooks without flushing. Returns `*this`. |
| `queue_disable()` | Queues disable for all hooks without flushing. Returns `*this`. |
| `apply()` | Flushes all queued operations in one thread-suspension window. |

```cpp
for (auto& def : hook_defs)
    grp.add(vh::inline_hook(def.target, def.detour, def.orig));

grp.queue_enable().apply();
```

### Lookup and iteration

| Method | Return Type | Description |
|---|---|---|
| `size()` | `size_t` | Number of hooks in the group. |
| `empty()` | `bool` | True if the group contains no hooks. |
| `name()` | `std::string` | The name passed to `vh::group()`. |
| `operator[](size_t i)` | `Hook&` | Access by index. Throws `std::out_of_range` if out of bounds. |
| `at(string_view tag)` | `Hook&` | Find by tag. Throws `std::out_of_range` if not found. |

Range-based for is supported:

```cpp
for (auto& h : grp) {
    if (h.tag().starts_with("Network")) h.disable();
}
```

---

## HookRegistry

A process-wide singleton owning named `Group`s. Use it when multiple independently-compiled modules in one process each install hooks and need coordinated cleanup at shutdown. For a single DLL or executable with one owner, a `Group` alone is sufficient.

**Access:** `vh::HookRegistry::global()`

| Method | Signature | Description |
|---|---|---|
| `register_group` | `void register_group(Group group)` | Takes ownership. Looked up by the group's name. |
| `find_group` | `Group* find_group(string_view name)` | Returns a pointer to the named group, or `nullptr`. |
| `enable_all` | `void enable_all()` | Enables all hooks in all registered groups. |
| `disable_all` | `void disable_all()` | Disables all hooks in all registered groups. |
| `remove_all` | `void remove_all()` | Removes all hooks and clears all groups. |
| `total_hook_count` | `size_t total_hook_count()` | Total hook count across all registered groups. |

```cpp
// render.dll
auto render = vh::group("Render");
render.add(vh::vtable_hook(vtbl, 8, (void*)&hk_Present));
vh::HookRegistry::global().register_group(std::move(render));

// net.dll
auto net = vh::group("Network");
net.add(vh::api_hook("ws2_32", "send", &hk_send));
vh::HookRegistry::global().register_group(std::move(net));

// shutdown
vh::HookRegistry::global().remove_all();
```

---

## Config Structs

All structs live in `vh::config::`, defined in `<vh/config.hpp>` (included by `<vh/vh.hpp>`).

---

### `config::Trampoline`

Used by `inline_hook`, `api_hook`.

```cpp
struct Trampoline {
    bool        thread_safe = true;
    std::string tag;
};
```

| Field | Default | Description |
|---|---|---|
| `thread_safe` | `true` | Suspends all threads during hook install and removal so no thread can be executing inside the bytes being patched. Correct in almost every situation. Set `false` only if installing from within a callback already executing inside the target (rare). |
| `tag` | `""` | Label stored with the hook. Used for logging and `Group::at()` lookup. Recommended convention: `"Module.Function"`. |

---

### `config::IAT`

Used by `iat_hook`, `iat_hook_all`.

```cpp
struct IAT {
    std::string_view module_name;
    std::string_view import_name;
    std::string      tag;
};
```

| Field | Default | Description |
|---|---|---|
| `module_name` | `""` | The module whose import table to patch. Empty searches all loaded modules. On Windows: `"my_app.exe"` or `"plugin.dll"`. |
| `import_name` | `""` | Unused when calling `iat_hook()` directly — the import name is the first argument. Present for completeness. |
| `tag` | `""` | Label for this hook. |

---

### `config::PLT`

Used by `plt_hook`.

```cpp
struct PLT {
    std::string_view library_name;
    std::string_view symbol_name;
    std::string      tag;
};
```

| Field | Default | Description |
|---|---|---|
| `library_name` | `""` | Unused when calling `plt_hook()` directly — passed as the first argument. |
| `symbol_name` | `""` | Unused when calling `plt_hook()` directly — passed as the second argument. |
| `tag` | `""` | Label for this hook. |

---

### `config::VTable`

Used by `vtable_hook`.

```cpp
struct VTable {
    void**      vtable = nullptr;
    size_t      slot   = 0;
    std::string tag;
};
```

`vtable` and `slot` are passed as direct arguments to `vtable_hook()`. In practice, only `tag` is set via the opts parameter:

```cpp
vh::vtable_hook(vtbl, 8, detour, orig, { .tag = "DXGI.Present" });
```

---

### `config::Mid`

Used by `mid_hook`.

```cpp
struct Mid {
    size_t      offset      = 0;
    bool        thread_safe = true;
    std::string tag;
};
```

| Field | Default | Description |
|---|---|---|
| `offset` | `0` | Byte offset from the start of the target function. The actual patch site is rounded to the nearest complete instruction boundary. `0` hooks at the function entry. |
| `thread_safe` | `true` | Same meaning as `config::Trampoline::thread_safe`. |
| `tag` | `""` | Label for this hook. |

---

### `config::Inject`

Used by `vh::inject`, `vh::inject_from_memory`.

```cpp
struct Inject {
    InjectMethod method = InjectMethod::LoadLibrary;
    std::string  tag;
};
```

| Field | Default | Description |
|---|---|---|
| `method` | `LoadLibrary` | Injection method. See [Process Injection](#process-injection) for trade-offs. |
| `tag` | `""` | Optional label stored with the injection handle. |

---

### `Engine::Config`

Passed to `vanhooks::Engine` at construction to configure global engine behaviour. End users can construct a custom engine with stealth options enabled; the global engine uses defaults (all stealth off, no watchdog).

```cpp
vanhooks::Engine::Config cfg;
cfg.enable_integrity_watchdog = true;
cfg.watchdog_interval_ms      = 250;
cfg.suppress_etw              = true;
cfg.suppress_amsi             = true;

vanhooks::Engine eng(cfg);
```

| Field | Type | Default | Description |
|---|---|---|---|
| `allocator` | `shared_ptr<IAllocator>` | `nullptr` | Custom trampoline memory allocator. `nullptr` uses the default (near-target allocation). |
| `trampoline_pool_size` | `size_t` | `65536` | Bytes per trampoline pool slab. Increase if `TrampolineNoSpace` errors appear. |
| `auto_flush_icache` | `bool` | `true` | Flush the instruction cache after each patch. Disable only if you are managing cache coherency manually. |
| `enable_integrity_watchdog` | `bool` | `false` | Start the integrity watchdog thread. See [Watchdog](#watchdog) notes below. |
| `watchdog_interval_ms` | `uint32_t` | `500` | How often the watchdog polls hook integrity, in milliseconds. |
| `suppress_etw` | `bool` | `false` | Patch `ntdll!EtwEventWrite` and `EtwEventWriteFull` to return `STATUS_SUCCESS` immediately, silencing user-mode ETW telemetry. No-op on HVCI/VBS systems. **Windows only.** |
| `suppress_amsi` | `bool` | `false` | Patch `amsi.dll!AmsiScanBuffer` and `AmsiScanString` to return `AMSI_RESULT_CLEAN`. No-op if `amsi.dll` is not loaded. **Windows only.** |

#### Watchdog

When `enable_integrity_watchdog` is `true`, a background thread polls every installed hook at `watchdog_interval_ms` and reinstalls any that have been removed by a kernel driver or external process. The watchdog is spawned via `NtCreateThreadEx` so `CreateThread` does not appear in the IAT. It stops cleanly when the `Engine` is destroyed. RAII destructors and explicit `remove()` calls still work normally — the watchdog only reacts to *external* removal.

---

## Error Codes

All codes are values of `vh::Error` (`uint32_t` underlying type). Use `vh::error_to_string(e)` for the human-readable name.

### General

| Code | Meaning |
|---|---|
| `Ok` | Not an error. Returned by void operations on success. |
| `NotInitialized` | The engine has not been initialised. |
| `AlreadyInitialized` | Initialisation attempted twice. |
| `InvalidArgument` | A null pointer or nonsensical value was passed. |
| `Unsupported` | Operation not supported on this platform or architecture (e.g. IAT hooks on Linux). |
| `OutOfRange` | An index or offset was outside valid bounds. |
| `OsError` | An OS call failed. Check `GetLastError()` (Windows) or `errno` (POSIX). |

### Memory

| Code | Meaning |
|---|---|
| `MemoryAllocationFailed` | Could not allocate trampoline memory. May indicate the process is out of memory or no suitable region exists near the target for a near-jump. |
| `MemoryProtectFailed` | Could not change memory protection on the target page. |
| `MemoryReadFailed` | Could not read from the target address. |
| `MemoryWriteFailed` | Could not write patch bytes to the target. |
| `TrampolineNoSpace` | Target prologue too short to safely steal enough bytes. Consider `iat_hook` or `plt_hook` instead. |

### Hook lifecycle

| Code | Meaning |
|---|---|
| `HookNotFound` | The handle refers to a hook that does not exist or has already been removed. |
| `HookAlreadyExists` | Attempted to hook the same target address twice. |
| `HookInstallFailed` | Hook could not be installed. Usually preceded by a more specific memory error. |
| `HookRemoveFailed` | Hook could not be removed cleanly. |
| `HookAlreadyEnabled` | `enable()` called on an already-active hook. |
| `HookAlreadyDisabled` | `disable()` called on an already-inactive hook. |

### Disassembly

| Code | Meaning |
|---|---|
| `DisassemblyFailed` | The disassembler could not decode an instruction at the target address. Bytes may not be valid code for the current architecture. |
| `InstructionTooShort` | An instruction is shorter than the minimum needed for relocation. |
| `UnsupportedInstruction` | An instruction in the prologue cannot be safely relocated (e.g. a relative branch whose destination would be out of range after relocation). |

### Module and symbol

| Code | Meaning |
|---|---|
| `ModuleNotFound` | The named module is not present among loaded modules. |
| `SymbolNotFound` | The symbol name could not be resolved within the specified module. |
| `IATEntryNotFound` | No IAT entry for the requested import was found in the specified (or any) loaded module. |
| `PLTEntryNotFound` | No PLT / GOT entry for the requested symbol was found in the specified shared library. |

### Thread

| Code | Meaning |
|---|---|
| `ThreadSuspendFailed` | Could not suspend one or more threads. Hook was not installed. |
| `ThreadResumeFailed` | Could not resume a suspended thread after patching. Hook is installed but the process may be degraded. |
| `ThreadInPrologue` | A suspended thread's instruction pointer was inside the bytes being patched. VanHooks advances it past the patch automatically. Informational — not fatal. |

### Batch and chain

| Code | Meaning |
|---|---|
| `QueueEmpty` | `Group::apply()` called with nothing queued. |
| `ChainBaseNotFound` | The base hook passed to `chain()` is not known to the engine — likely already removed. |
| `ChainOrderViolation` | A chain link was removed before its base hook. Always remove in reverse creation order. |

### PE introspection

| Code | Meaning |
|---|---|
| `PeInvalidHeader` | DOS or NT signature mismatch, or offsets are corrupt. |
| `PeNoExportDirectory` | The module has no export directory (e.g. a data-only DLL). |
| `PeNoImportDirectory` | The module has no import directory. |
| `PeItemNotFound` | A named export, import, or section could not be found. |

### Breakpoints

| Code | Meaning |
|---|---|
| `BreakpointAlreadySet` | A breakpoint is already installed at this address. |
| `BreakpointNotFound` | No breakpoint exists at the given address. |
| `BreakpointSlotExhausted` | All four hardware debug registers (DR0–DR3) are occupied. Remove one before adding another. |
| `BreakpointInstallFailed` | The OS call to set or clear the thread context failed. |

### Call-stack capture

| Code | Meaning |
|---|---|
| `CallstackCaptureFailed` | `RtlCaptureStackBackTrace` / `backtrace` returned 0 frames. May occur in deeply optimised builds with no frame pointers. |

---

## Pattern Scanner

Scans memory for byte patterns using IDA-style wildcard syntax, accelerated with Boyer–Moore–Horspool. All functions are in `vanhooks::scanner::` and are available without any optional CMake flag.

```cpp
#include <vh/vh.hpp>  // scanner is always available
using namespace vanhooks::scanner;
```

---

### `scan_pattern` — range scan

```cpp
Result<std::vector<uintptr_t>> scan_pattern(
    const void*      base,
    size_t           size,
    std::string_view ida_pattern);
```

Scans `[base, base+size)` for all occurrences of `ida_pattern`. Returns a vector of matching virtual addresses (absolute, not offsets). `?` or `??` is a wildcard that matches any byte.

```cpp
auto hits = vanhooks::scanner::scan_pattern(
    module_base, module_size,
    "48 8B 05 ? ? ? ? 48 85 C0 74");

for (auto addr : hits.value_or({}))
    printf("match @ 0x%llx\n", addr);
```

---

### `scan_bytes` — exact byte scan

```cpp
std::vector<uintptr_t> scan_bytes(
    const void*              base,
    size_t                   size,
    std::span<const uint8_t> needle);
```

Finds all occurrences of `needle` in `[base, base+size)`. No wildcards. Never fails — returns an empty vector if there are no matches.

```cpp
std::vector<uint8_t> sig = { 0x48, 0x8B, 0x05, 0xDE, 0xAD };
auto hits = vanhooks::scanner::scan_bytes(base, size, sig);
```

---

### `scan_process` — process-wide scan (Windows)

```cpp
Result<std::vector<uintptr_t>> scan_process(std::string_view ida_pattern);
```

Walks every committed, accessible memory region in the process (`VirtualQuery`) and returns all matches. Useful when you don't know which module contains a pattern.

```cpp
auto hits = vanhooks::scanner::scan_process("E8 ? ? ? ? 85 C0 74 ?");
```

---

### `scan_module` — named module scan (Windows)

```cpp
Result<std::vector<uintptr_t>> scan_module(
    std::string_view module_name,
    std::string_view ida_pattern);
```

Resolves `module_name` via `GetModuleHandle`, then scans its entire image range.

```cpp
auto hits = vanhooks::scanner::scan_module("game.exe", "48 89 5C 24 ? 57 48 83 EC ?");
```

---

### `parse_pattern`

```cpp
Result<Pattern> parse_pattern(std::string_view input);
```

Compiles an IDA-style pattern string into a reusable `Pattern`. Use this when you scan the same pattern many times; avoids re-parsing on every call.

```cpp
auto pat = vanhooks::scanner::parse_pattern("48 8B 05 ? ? ? ?").value();

// Reuse across multiple ranges
for (auto& region : regions)
    auto hits = vanhooks::scanner::scan_pattern(region.base, region.size, pat);
```

**`Pattern` members:**

| Member | Type | Description |
|---|---|---|
| `bytes` | `vector<PatternByte>` | Compiled pattern bytes. Each has a `value` and a `wildcard` flag. |
| `raw` | `string` | Original input string, for diagnostics. |
| `size()` | `size_t` | Pattern length in bytes. |
| `empty()` | `bool` | True if the pattern has no bytes. |

---

## Anti-Debug Detection

`vanhooks::antidebug::check_all()` runs eight independent techniques and returns a structured `Report`. Available on all platforms without any optional CMake flag; technique coverage varies by OS.

```cpp
#include <vh/vh.hpp>   // antidebug is always included
```

---

### `check_all`

```cpp
vanhooks::antidebug::Report check_all();
```

Runs all available detection techniques and aggregates results into a `Report`. Safe to call at any time; techniques are independent and non-destructive.

```cpp
auto report = vanhooks::antidebug::check_all();

if (report.any_detected()) {
    printf("%d technique(s) triggered\n", report.detection_count());
}

for (auto& f : report.findings) {
    printf("[%s] %-45s %s\n",
        f.detected ? "DETECTED" : "clean   ",
        f.technique.c_str(),
        f.detail.c_str());
}
```

---

### `Report`

```cpp
struct Report {
    std::vector<Finding> findings;

    bool any_detected()    const noexcept;
    int  detection_count() const noexcept;
};
```

| Method | Description |
|---|---|
| `any_detected()` | Returns `true` if any technique detected a debugger indicator. |
| `detection_count()` | Returns the number of techniques that fired. |

---

### `Finding`

```cpp
struct Finding {
    std::string technique;  // human-readable technique name
    bool        detected;   // true = indicator found
    std::string detail;     // extra context (e.g. flag values, process name)
};
```

---

### Techniques

#### Windows — full suite (8 techniques)

| Technique name | Method | What it checks |
|---|---|---|
| `IsDebuggerPresent` | Win32 API | `PEB.BeingDebugged` flag |
| `CheckRemoteDebuggerPresent` | Win32 API | Cross-process debugger handle |
| `NtQueryInformationProcess(DebugPort)` | ntdll direct | `ProcessDebugPort` is non-null |
| `HeapFlags` | PEB walk | Heap `Flags` / `ForceFlags` differ from clean-process defaults (x86 and x64 offsets handled separately) |
| `NtGlobalFlag` | PEB walk | Bits `0x70` set in `PEB.NtGlobalFlag` |
| `CloseHandle(invalid)` | Exception test | `EXCEPTION_INVALID_HANDLE` is raised only under a debugger |
| `TimingCheck` | `QueryPerformanceCounter` | 1 000-iteration loop takes >50 ms — consistent with debugger stepping overhead |
| `DebuggerProcessList` | `CreateToolhelp32Snapshot` | Known debugger process names running (x64dbg, OllyDbg, IDA, Cheat Engine, Wireshark, Fiddler, etc.) |

#### Linux — stub (1 technique)

| Technique name | Method | What it checks |
|---|---|---|
| `ptrace(TRACEME)` | `ptrace(2)` | Returns `-1` / `EPERM` if the process is already being traced |

#### Individual checks (Windows only)

Each technique is also available as a standalone function if you want to run a subset:

```cpp
vanhooks::antidebug::Finding f = vanhooks::antidebug::check_is_debugger_present();
vanhooks::antidebug::Finding f = vanhooks::antidebug::check_remote_debugger();
vanhooks::antidebug::Finding f = vanhooks::antidebug::check_debug_port();
vanhooks::antidebug::Finding f = vanhooks::antidebug::check_heap_flags();
vanhooks::antidebug::Finding f = vanhooks::antidebug::check_nt_global_flag();
vanhooks::antidebug::Finding f = vanhooks::antidebug::check_close_handle_exception();
vanhooks::antidebug::Finding f = vanhooks::antidebug::check_timing();
vanhooks::antidebug::Finding f = vanhooks::antidebug::check_debugger_processes();
```

---

## Disassembler

Zydis-backed instruction decoder and length disassembler. Available always — no optional CMake flag required. Types live in `vh::disasm::`.

```cpp
#include <vh/disasm.hpp>  // or just <vh/vh.hpp>
```

---

### `Arch`

```cpp
enum class Arch : uint8_t { X86, X64, ARM64, Unknown };

Arch vh::disasm::detect_arch() noexcept;
```

Auto-detects the architecture of the running process. Pass an explicit `Arch` to `Disassembler` to override (e.g. to decode a foreign binary's bytes).

---

### `Instruction`

```cpp
struct Instruction {
    uint64_t    address;         // virtual address where this instruction lives
    uint8_t     length;          // byte size (1–15 on x86/x64, always 4 on ARM64)
    InsnKind    kind;            // classification (see below)
    uint8_t     bytes[16];       // raw bytes

    std::optional<uint64_t> absolute_target;  // resolved target for RIP/PC-relative insns
    std::string             mnemonic;          // human-readable (debug / logging)

    bool is_branch()   const noexcept;  // Call, Jump, JumpConditional
    bool is_terminal() const noexcept;  // Jump, Return
    bool is_relative() const noexcept;  // RipRelative, PcRelative
};
```

**`InsnKind` values:**

| Value | Description |
|---|---|
| `Generic` | Any instruction not matched below |
| `Call` | Direct or indirect call |
| `Jump` | Unconditional jump |
| `JumpConditional` | Conditional jump (Jcc) |
| `Return` | Function return |
| `Nop` | No-op |
| `RipRelative` | x64 instruction that references memory via RIP |
| `PcRelative` | ARM64 instruction that references memory via PC |
| `Privileged` | Privileged or trap instruction (`syscall`, `int3`, `hlt`, etc.) |

---

### `Disassembler`

```cpp
class vh::disasm::Disassembler {
public:
    explicit Disassembler(Arch arch = detect_arch());

    Result<Instruction> decode_one(
        std::span<const uint8_t> code,
        uint64_t                 runtime_address) const;

    Result<std::vector<Instruction>> decode_min_bytes(
        std::span<const uint8_t> code,
        uint64_t                 runtime_address,
        size_t                   min_bytes) const;

    static size_t total_length(const std::vector<Instruction>& insns) noexcept;

    Arch arch() const noexcept;
};
```

| Method | Description |
|---|---|
| `decode_one(code, addr)` | Decode one instruction. `runtime_address` is used for RIP-relative resolution — pass the VA where `code` actually lives. |
| `decode_min_bytes(code, addr, n)` | Decode as many complete instructions as needed to cover at least `n` bytes. Used by the trampoline builder for prologue stealing. |
| `total_length(insns)` | Sum of `length` across all instructions in a decoded sequence. |

```cpp
vh::disasm::Disassembler dis;

auto span = std::span<const uint8_t>(
    reinterpret_cast<const uint8_t*>(fn_ptr), 64);

auto insn = dis.decode_one(span, reinterpret_cast<uint64_t>(fn_ptr));
if (insn)
    printf("%s  (%u bytes)\n", insn->mnemonic.c_str(), insn->length);
```

---

### Free functions

#### `decode_until_branch`

```cpp
std::vector<Instruction> vh::disasm::decode_until_branch(
    const void* code_ptr,
    size_t      count_bytes,
    uint64_t    runtime_address = 0,
    Arch        arch = detect_arch());
```

Decodes instructions from `code_ptr` up to `count_bytes`, stopping at the first terminal (unconditional jump or return) instruction. Returns all decoded instructions including the terminal. Never fails — returns an empty vector on decode error.

```cpp
auto insns = vh::disasm::decode_until_branch(fn_ptr, 128);
printf("%s\n", vh::disasm::format_listing(insns).c_str());
```

---

#### `decode_prologue`

```cpp
Result<std::vector<Instruction>> vh::disasm::decode_prologue(
    const void* code_ptr,
    size_t      min_bytes,
    uint64_t    runtime_address = 0,
    Arch        arch = detect_arch());
```

Decodes at least `min_bytes` of prologue instructions without splitting an instruction boundary. The minimal safe trampoline copy length for hand-built trampolines.

---

#### `safe_copy_length`

```cpp
Result<size_t> vh::disasm::safe_copy_length(
    const void* code_ptr,
    size_t      min_bytes,
    uint64_t    runtime_address = 0,
    Arch        arch = detect_arch());
```

Returns the byte count at the next instruction boundary at or after `min_bytes`. Never splits an instruction. Used internally by `hook_mid` to locate the safe patch site.

---

#### `rewrite`

```cpp
Result<RewriteResult> vh::disasm::rewrite(
    const std::vector<Instruction>& insns,
    uint64_t original_base,
    uint64_t new_base,
    Arch     arch = detect_arch());
```

Rewrites `insns` so that all RIP/PC-relative references remain valid after the bytes are placed at `new_base` instead of `original_base`. Returns a `RewriteResult`:

```cpp
struct RewriteResult {
    std::vector<uint8_t> code;      // patched bytes ready to write
    bool                 clean;     // true if every instruction was relocatable
    std::vector<size_t>  patched;   // indices of instructions that needed rewriting
};
```

If `clean` is `false`, one or more instructions had a relative reference that could not be fixed up (e.g. an ARM64 `B` to an address outside ±128 MB of `new_base`).

---

#### `format_insn` / `format_listing`

```cpp
std::string vh::disasm::format_insn(const Instruction& insn);
std::string vh::disasm::format_listing(const std::vector<Instruction>& insns);
```

Format one instruction or a sequence as a human-readable string.

`format_insn` output: `0x00007ff812345678: 48 89 5c 24 08   mov qword ptr [rsp+0x8], rbx`

`format_listing` returns one `format_insn` line per instruction, joined by newlines.

---

## Process Injection

Injects a DLL (by path or in-memory PE bytes) into a remote process using one of four methods. Requires `VH_INJECT_ENABLED`. **Windows only** — all functions return `Error::Unsupported` on other platforms.

```cpp
#include <vh/inject.hpp>  // or just <vh/vh.hpp> with VH_INJECT_ENABLED
```

---

### `vh::inject`

```cpp
Result<Injection> vh::inject(uint32_t         pid,
                              std::string_view dll_path,
                              config::Inject   opts = {});
```

Injects `dll_path` into process `pid` using the method specified in `opts`. Returns a move-only RAII `Injection` that ejects automatically when it goes out of scope.

| | |
|---|---|
| `pid` | Target process ID. |
| `dll_path` | Fully-qualified DLL path, accessible from the target process's file system context. |
| `opts` | Method and optional tag. See [`config::Inject`](#configinject). |

```cpp
auto inj = vh::inject(target_pid, "C:\\payloads\\research.dll",
                      { .method = vh::InjectMethod::ManualMap,
                        .tag    = "research" });
if (!inj)
    printf("failed: %s\n", vh::error_to_string(inj.error()).data());
```

---

### `vh::inject_from_memory`

```cpp
Result<Injection> vh::inject_from_memory(uint32_t                 pid,
                                          std::span<const uint8_t> pe_bytes,
                                          config::Inject           opts = {});
```

Injects a PE image from a memory buffer — no file on disk required. For `ManualMap`, the image is mapped directly from `pe_bytes`. For other methods, it is written to a temp file and deleted immediately after injection.

```cpp
std::vector<uint8_t> pe = load_pe_from_resource();
auto inj = vh::inject_from_memory(target_pid, pe,
                                   { .method = vh::InjectMethod::ManualMap });
```

---

### `vh::eject`

```cpp
Result<void> vh::eject(Injection& inj);
```

Convenience free function equivalent to `inj.eject()`. Provided for API symmetry.

---

### `vh::Injection`

RAII handle returned by `inject` / `inject_from_memory`. Move-only; destructor calls eject automatically.

| Method | Return Type | Description |
|---|---|---|
| `eject()` | `Result<void>` | Explicitly unload and invalidate. Idempotent — safe to call multiple times. |
| `valid()` | `bool` | Handle is live. |
| `operator bool()` | `bool` | Equivalent to `valid()`. |
| `pid()` | `uint32_t` | Target process ID. |
| `method()` | `InjectMethod` | Which method was used. |
| `tag()` | `std::string` | Tag from `config::Inject`. |
| `handle()` | `InjHandle` | Escape hatch to the internal handle. |

---

### `vh::InjectMethod`

```cpp
enum class InjectMethod : uint8_t {
    LoadLibrary,  // CreateRemoteThread + LoadLibraryA
    ManualMap,    // Manual PE mapping — no module-list entry
    ThreadHijack, // Context-redirect an existing thread — no remote thread
    ApcQueue,     // Queue APC to alertable threads — timing non-deterministic
};
```

| Method | Module-list entry | Remote thread | Stealth |
|---|:---:|:---:|:---:|
| `LoadLibrary` | ✓ (visible) | ✓ | Low |
| `ManualMap` | ✗ | ✓ (shellcode) | Medium |
| `ThreadHijack` | Configurable | ✗ | High |
| `ApcQueue` | Configurable | ✗ | High |

**LoadLibrary** — `CreateRemoteThread` + `LoadLibraryA`. Simple and compatible, but leaves a module-list entry and is trivially detectable by any `EnumProcessModules` scan.

**ManualMap** — Parses the PE in-process, maps sections into the target without calling `LoadLibraryA`. No module-list entry. The PE header is withheld from the remote allocation; shellcode is zeroed after execution; no IAT trampolines are left behind.

**ThreadHijack** — Suspends an existing thread, redirects its `RIP` to a compact shellcode stub that loads the payload, restores all volatile registers and the original IP via a RIP-relative jump, then resumes. No remote thread created; `CreateThread` does not appear in any trace for this operation.

**ApcQueue** — Queues a `LoadLibraryA` APC to every alertable thread. Loads the next time any thread enters an alertable wait (`SleepEx`, `WaitForSingleObjectEx`, etc.). No remote thread; no visible injection event until the APC fires.

---

## Symbol Resolution

Resolves virtual addresses to demangled function names, module names, source file paths, and line numbers. Requires `VH_SYMBOLS_ENABLED`. Backend is DbgHelp on Windows and `dladdr` / libbacktrace on POSIX.

```cpp
#include <vh/symbols.hpp>  // or <vh/vh.hpp> with VH_SYMBOLS_ENABLED
```

---

### `vh::symbols::resolve`

```cpp
Result<Symbol> vh::symbols::resolve(uintptr_t address);

template<typename Fn>
Result<Symbol> vh::symbols::resolve(Fn* fn_ptr);
```

Resolves `address` to its nearest symbol. `Symbol::address` is the symbol's base — compute the offset as `address - sym.address`. The function-pointer overload avoids the `reinterpret_cast` at the call site.

```cpp
if (auto sym = vh::symbols::resolve(some_address)) {
    printf("%s + 0x%zx  [%s]\n",
           sym->name.c_str(),
           some_address - sym->address,
           sym->module.c_str());
}
```

---

### `vh::symbols::find`

```cpp
Result<uintptr_t> vh::symbols::find(std::string_view name,
                                     std::string_view module = {});
```

Finds the VA of a named symbol. `module` narrows the search to one image; empty searches all loaded modules. Tries both demangled and raw names on Windows.

```cpp
auto addr = vh::symbols::find("NtQuerySystemInformation", "ntdll.dll");
```

---

### `vh::symbols::source_location`

```cpp
Result<SourceLocation> vh::symbols::source_location(uintptr_t address);
```

Returns the source file path and line number for `address`. Requires PDB (Windows) or DWARF sections (Linux / macOS with libbacktrace).

```cpp
struct SourceLocation {
    std::string file;
    uint32_t    line   = 0;
    uint32_t    column = 0;
};
```

---

### `vh::symbols::load_module`

```cpp
Result<void> vh::symbols::load_module(std::string_view module_path);
```

Pre-warms the symbol table for `module_path`. Symbols are normally loaded lazily on first `resolve` — call this explicitly before entering a hot path or before spawning worker threads.

---

### `vh::symbols::initialize`

```cpp
Result<void> vh::symbols::initialize();
```

Initialises the debug-info backend. Idempotent — safe to call multiple times. Called automatically by all other functions; call it early if you want to control when the initialisation cost is incurred.

---

### Stack helpers

```cpp
// Capture raw return addresses into a caller-supplied buffer
int vh::symbols::capture_stack(void** frames, int count, int skip = 1) noexcept;

// Format a list of raw addresses into human-readable lines
std::vector<std::string> vh::symbols::format_stack(std::span<void* const> frames);

// Convenience: capture and format in one call
std::vector<std::string> vh::symbols::current_stack(int depth = 32, int skip = 2);

// Demangle a C++ symbol name
std::string vh::symbols::demangle(std::string_view mangled);
```

Each formatted line has the form: `#N  0xADDRESS  symbol_name + 0xOFFSET  [module.dll]`

```cpp
for (auto& line : vh::symbols::current_stack())
    puts(line.c_str());
```

`demangle` uses `UnDecorateSymbolName` (DbgHelp) on Windows and `__cxa_demangle` (cxxabi.h) on GCC/Clang. Falls back to the input string unchanged if demangling fails.

---

### `Symbol`

```cpp
struct Symbol {
    std::string name;       // demangled symbol name (best effort)
    std::string raw_name;   // raw / mangled name as stored in debug info
    uintptr_t   address;    // base VA of the symbol
    size_t      size;       // function size in bytes (0 = unknown)
    std::string module;     // owning module base name (e.g. "ntdll.dll")
    std::string file;       // source file path (empty if unavailable)
    uint32_t    line;       // source line (0 if unavailable)
};
```

---

## PE Introspection

Zero-copy in-process PE reader. Requires `VH_PE_ENABLED`. **Full support on Windows (PE32 / PE32+, x86 / x64).** Returns `Error::Unsupported` on Linux and macOS.

```cpp
#include <vh/pe.hpp>  // or <vh/vh.hpp> with VH_PE_ENABLED
```

---

### Factories

#### `vh::pe::open`

```cpp
Result<PeView> vh::pe::open(std::string_view name = {});
```

Opens a module already loaded in the current process by name. Accepts a base name (`"ntdll.dll"`, `"ntdll"`), a full path, or an empty string to open the main executable.

```cpp
auto pe = vh::pe::open("ntdll.dll");
```

---

#### `vh::pe::open_at`

```cpp
Result<PeView> vh::pe::open_at(uintptr_t        base,
                                size_t           image_size = 0,
                                std::string_view name       = {});
```

Opens a PE image at a known base address. `image_size` is derived from PE headers if zero.

---

#### `vh::pe::open_handle` (Windows)

```cpp
Result<PeView> vh::pe::open_handle(HMODULE hmod);
```

Opens a module by its `HMODULE`.

---

#### `vh::pe::modules` (Windows)

```cpp
Result<std::vector<PeView>> vh::pe::modules();
```

Enumerates all modules currently loaded in the process, in load order.

---

### `PeView` — query methods

All query methods return `Result<T>` except `find_caves`, which always returns an empty vector on error.

#### Sections

```cpp
Result<std::vector<Section>> pv.sections();
Result<Section>              pv.find_section(std::string_view name);
```

**`Section`:**

```cpp
struct Section {
    std::string name;               // e.g. ".text", ".rdata"
    uintptr_t   virtual_address;    // RVA from image base
    size_t      virtual_size;
    uint32_t    characteristics;

    bool executable()       const noexcept;  // IMAGE_SCN_MEM_EXECUTE
    bool readable()         const noexcept;  // IMAGE_SCN_MEM_READ
    bool writable()         const noexcept;  // IMAGE_SCN_MEM_WRITE
    bool contains_code()    const noexcept;  // IMAGE_SCN_CNT_CODE
};
```

---

#### Exports

```cpp
Result<std::vector<Export>> pv.exports();
Result<Export>              pv.find_export(std::string_view name);
Result<Export>              pv.find_export_by_ordinal(uint16_t ordinal);
```

**`Export`:**

```cpp
struct Export {
    std::string name;        // empty for ordinal-only exports
    uint16_t    ordinal;
    uintptr_t   address;     // absolute VA of the exported symbol

    std::string forwarder;   // e.g. "NTDLL.RtlAllocateHeap" (non-empty = forwarder)

    bool is_forwarder() const noexcept;
    bool by_name()      const noexcept;
};
```

```cpp
auto exp = pe->find_export("NtQuerySystemInformation");
if (exp)
    printf("found @ 0x%llx\n", (unsigned long long)exp->address);
```

---

#### Imports

```cpp
Result<std::vector<Import>>  pv.imports();
Result<std::vector<Import>>  pv.imports_from(std::string_view module_name);
Result<Import>               pv.find_import(std::string_view module_name,
                                             std::string_view symbol_name);
```

**`Import`:**

```cpp
struct Import {
    std::string module_name;    // e.g. "KERNEL32.DLL"
    std::string name;           // empty for ordinal imports
    uint16_t    ordinal;        // valid only when name is empty
    uintptr_t   iat_address;    // VA of the IAT slot (pointer-to-pointer)

    bool by_ordinal() const noexcept;

    // Dereference the IAT slot to get the current resolved address
    uintptr_t resolved() const noexcept;
};
```

```cpp
auto imp = pe->find_import("kernel32.dll", "VirtualProtect");
if (imp) {
    auto* slot = reinterpret_cast<void**>(imp->iat_address);
    printf("VirtualProtect IAT slot → %p\n", *slot);
}
```

---

#### Code caves

```cpp
std::vector<CodeCave> pv.find_caves(size_t min_size = 16,
                                     bool   executable_only = false);
```

Finds runs of zero-padding bytes within sections that are large enough to hold a short stub. `executable_only` restricts results to sections marked executable.

**`CodeCave`:**

```cpp
struct CodeCave {
    uintptr_t   address;       // VA of the first zero byte
    size_t      size;          // length of the run
    std::string section_name;  // section containing this cave
};
```

```cpp
for (auto& cave : pe->find_caves(32, true))
    printf("[%s] 0x%llx  %zu bytes\n",
           cave.section_name.c_str(), (unsigned long long)cave.address, cave.size);
```

---

#### Accessors

| Method | Return Type | Description |
|---|---|---|
| `base()` | `uintptr_t` | Image load base address. |
| `image_size()` | `size_t` | Total mapped image size. |
| `name()` | `string_view` | Display name (module base name or path). |
| `valid()` | `bool` | View is open and has a valid PE header. |

---

## Breakpoints

Software (INT3 / VEH) and hardware (DR0–DR3 via `SetThreadContext`) breakpoints with RAII lifetime. Requires `VH_BREAKPOINT_ENABLED`.

```cpp
#include <vh/breakpoint.hpp>  // or <vh/vh.hpp> with VH_BREAKPOINT_ENABLED
```

---

### `vh::breakpoint::set_software`

```cpp
Result<Breakpoint> vh::breakpoint::set_software(uintptr_t address, Callback cb);
```

Installs a software breakpoint at `address`. On Windows, patches one byte to `0xCC` and installs a VEH handler. On Linux, installs a `SIGTRAP` handler via `sigaction`. The original byte is restored before `cb` is called and re-patched afterwards if `cb` returns `Action::Continue`.

| | |
|---|---|
| `address` | Target virtual address. Must point to executable memory. |
| `cb` | Called on each hit. Must match `Callback = std::function<Action(uintptr_t)>`. |

```cpp
auto bp = vh::breakpoint::set_software(target_address,
    [](uintptr_t addr) {
        printf("SW BP hit @ 0x%llx\n", addr);
        return vh::breakpoint::Action::Continue;
    });
```

---

### `vh::breakpoint::set_hardware`

```cpp
Result<Breakpoint> vh::breakpoint::set_hardware(uintptr_t   address,
                                                  HwCondition condition,
                                                  HwSize      size,
                                                  Callback    cb);
```

Installs a hardware breakpoint using DR0–DR3 on all currently-running threads. x86-64 only; returns `Error::Unsupported` on ARM64 and x86-32. Returns `Error::BreakpointSlotExhausted` if all four slots are occupied.

```cpp
auto hw = vh::breakpoint::set_hardware(
    watch_address,
    vh::breakpoint::HwCondition::Write,
    vh::breakpoint::HwSize::Dword,
    [](uintptr_t addr) {
        printf("write detected @ 0x%llx\n", addr);
        return vh::breakpoint::Action::Continue;
    });
```

---

### `Action`

```cpp
enum class Action : uint8_t {
    Continue,  // resume execution (software BP is re-armed automatically)
    Remove,    // remove this breakpoint and resume — one-shot behaviour
};
```

---

### `HwCondition`

```cpp
enum class HwCondition : uint8_t {
    Execute  = 0,   // break on instruction fetch (size must be Byte)
    Write    = 1,   // break on memory write
    ReadWrite = 3,  // break on read or write (not execute)
};
```

---

### `HwSize`

```cpp
enum class HwSize : uint8_t {
    Byte  = 0,  // 1-byte range
    Word  = 1,  // 2-byte range
    Qword = 2,  // 8-byte range (x64 only)
    Dword = 3,  // 4-byte range
};
```

`Execute` condition requires `Byte` size. All other combinations of condition and size are valid.

---

### `Breakpoint` — RAII guard

| Method | Return Type | Description |
|---|---|---|
| `remove()` | `void` | Remove the breakpoint early. Idempotent. The destructor also calls this. |
| `active()` | `bool` | True if the breakpoint is still installed. |
| `address()` | `uintptr_t` | The address this breakpoint watches. |
| `apply_to_new_thread(HANDLE)` | `Status` | **(Windows, hardware BPs only)** Apply the debug register settings to a newly-created thread. |

The destructor calls `remove()` automatically:

```cpp
{
    auto bp = vh::breakpoint::set_software(addr, cb).value();
    // breakpoint active
} // removed here
```

---

### New-thread propagation (Windows, hardware breakpoints)

Hardware breakpoints are applied per-thread at install time. Threads created *after* the install call are not automatically covered. Handle this from `DLL_THREAD_ATTACH`:

```cpp
// Store the Breakpoint at file or class scope:
vh::breakpoint::Breakpoint g_hw_bp = /* ... */;

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_THREAD_ATTACH && g_hw_bp.active())
        g_hw_bp.apply_to_new_thread(GetCurrentThread());
    return TRUE;
}
```

---

## Call Stack Capture

Thin wrapper around `RtlCaptureStackBackTrace` (Windows) / `backtrace()` (POSIX). Requires `VH_CALLSTACK_ENABLED`.

```cpp
#include <vh/callstack.hpp>  // or <vh/vh.hpp> with VH_CALLSTACK_ENABLED
```

---

### `vh::callstack::capture`

```cpp
Result<std::vector<uintptr_t>> vh::callstack::capture(
    size_t skip      = 1,
    size_t max_depth = kMaxDepth);
```

Captures the raw return-address stack of the current thread. `skip = 1` omits `capture()` itself; `skip = 2` inside a detour omits both `capture()` and the VanHooks dispatch frame. `kMaxDepth` is 64. Frames are ordered innermost first.

No heap allocation occurs on the Windows capture path (fixed stack buffer, then move into the returned vector).

```cpp
auto frames = vh::callstack::capture(/*skip=*/2, /*max_depth=*/32);
for (auto addr : frames.value_or({}))
    printf("  0x%016llx\n", addr);
```

---

### `vh::callstack::capture_annotated`

```cpp
// Available only when VH_SYMBOLS_ENABLED is also defined
Result<std::vector<Frame>> vh::callstack::capture_annotated(
    size_t skip      = 1,
    size_t max_depth = kMaxDepth);
```

Captures the stack and resolves each frame through the symbols layer. Frames that cannot be resolved still appear in the output; their `name`, `file`, and `line` fields are empty / zero.

```cpp
struct Frame {
    uintptr_t   address;
    std::string name;    // demangled symbol name
    std::string file;    // source file
    uint32_t    line;    // source line (0 if unavailable)
};
```

---

### `vh::callstack::format`

```cpp
// Available only when VH_SYMBOLS_ENABLED is also defined
std::string vh::callstack::format(const std::vector<Frame>& frames);
```

Formats an annotated stack as a multi-line human-readable string.

```
#0  0x00007ffe12345678  MyFunc    src/game.cpp:42
#1  0x00007ffe12344000  Dispatch  src/engine.cpp:17
```

---

### Usage inside a hook

```cpp
int WINAPI hk_MessageBoxW(HWND h, LPCWSTR t, LPCWSTR c, UINT f) {
    // skip=2: skip capture() + this detour frame
    auto frames = vh::callstack::capture(2, 16);
    for (auto addr : frames.value_or({}))
        printf("  called from 0x%llx\n", addr);

    return orig_MessageBoxW(h, t, c, f);
}
```

---

## Network API

`vh::net` is VanHooks' packet-capture and protocol-parsing layer: live interface capture, offline `.pcap` / `.pcapng` read and write, BPF filtering, and full layer-by-layer protocol parsing (Ethernet up through application-layer text protocols). It's compiled directly into `libvanhooks` — no external runtime dependencies.

```cpp
#include <vh/vh.hpp>   // pulls <vh/net.hpp> in automatically
```

`<vh/net.hpp>` is only available when the library was configured with `-DVH_ENABLE_NET=ON` (default off). Including it without net support enabled is a compile error with a message pointing at that CMake option.

Fallible operations reuse the same [Result Type](#result-type) as the hooking API: `Result<T>` for factories that return an object, `Status` (an alias for `Result<void>`) for operations that just succeed or fail.

```cpp
auto cap = vh::net::Capture::open("eth0");
if (!cap) {
    printf("open failed: %s\n", vh::error_to_string(cap.error()).data());
    return;
}

cap->filter("tcp port 443");
cap->start([](vh::net::Packet pkt) {
    auto parsed = pkt.parse();
    if (auto* ip = parsed->getLayerOfType<vanhooks::net::IPv4Layer>())
        printf("%s -> %s\n",
               ip->getSrcIPv4Address().toString().c_str(),
               ip->getDstIPv4Address().toString().c_str());
});
```

---

### `vh::net::devices()`

```cpp
[[nodiscard]] std::vector<DeviceInfo> vh::net::devices();
```

Lists every interface capable of live capture on the current machine.

**`DeviceInfo`:**

```cpp
struct DeviceInfo {
    std::string name;        // e.g. "eth0", "en0", "\Device\NPF_{…}"
    std::string description; // human-readable label (may be empty on Linux)
    std::string ip4;         // primary IPv4 address as dotted-decimal, or ""
    bool        loopback = false;
};
```

```cpp
for (const auto& d : vh::net::devices())
    printf("%-20s %s%s\n", d.name.c_str(), d.ip4.c_str(),
           d.loopback ? " (loopback)" : "");
```

---

### `vh::net::Filter`

```cpp
class Filter {
public:
    Filter() = default;
    explicit Filter(std::string_view bpf);

    Filter& expr(std::string_view e);
    [[nodiscard]] std::string_view expr() const noexcept;
};
```

A small builder around a BPF (Berkeley Packet Filter) expression string. Mainly useful when a filter is assembled programmatically; for a literal expression, pass the string straight to `Capture::filter()` or `PcapReader::filter()` instead of constructing a `Filter`.

```cpp
vh::net::Filter f;
f.expr("udp port 53");

cap->filter(f);
```

---

### `vh::net::Capture`

RAII wrapper around a live-interface capture session. Move-only; the destructor stops the capture if still running.

```cpp
auto cap = vh::net::Capture::open("eth0");
cap->filter("udp port 53");
cap->start([](vh::net::Packet p) { … });
cap->stop();   // or let it destruct
```

**Factory:**

| Method | Signature | Description |
|---|---|---|
| `open` | `static Result<Capture> open(std::string_view device_name)` | Opens a device by name, e.g. `"eth0"`, `"en0"`, or a Windows NPF device path. |
| `open_by_ip` | `static Result<Capture> open_by_ip(std::string_view ipv4)` | Opens the device that owns the given IPv4 address. |

**Configuration** (call before `start()`):

| Method | Signature | Description |
|---|---|---|
| `filter` | `Capture& filter(std::string_view bpf_expr)` | Sets a BPF filter expression, e.g. `"tcp port 443"`. |
| `filter` | `Capture& filter(const Filter& f)` | Overload taking a `Filter` builder. |
| `snap_len` | `Capture& snap_len(int bytes) noexcept` | Maximum bytes captured per packet. Default `65535`. |
| `promiscuous` | `Capture& promiscuous(bool on) noexcept` | Enables or disables promiscuous mode. Default `true`. |

All configuration setters return `*this` and can be chained.

**Lifecycle:**

| Method | Signature | Description |
|---|---|---|
| `start` | `Status start(PacketCallback cb)` | Begins capture on a background thread; `cb` is invoked once per packet. `using PacketCallback = std::function<void(Packet)>;` |
| `stop` | `void stop()` | Stops capture. Safe to call even if not running. |
| `running` | `bool running() const noexcept` | Whether capture is currently active. |

**Stats:**

```cpp
struct Stats {
    uint32_t received   = 0;
    uint32_t dropped    = 0;
    uint32_t if_dropped = 0;
};
[[nodiscard]] std::optional<Stats> stats() const;
```

Returns `std::nullopt` if the underlying device doesn't expose statistics.

**Escape hatch:**

| Method | Signature | Description |
|---|---|---|
| `device` | `vanhooks::net::PcapLiveDevice* device() const noexcept` | Access to the underlying device object for functionality not wrapped by `Capture`. |

> ⚠️ The `Packet` passed to `PacketCallback` is a non-owning view — valid only for the duration of that invocation. Copy `raw_data()` (see [`Packet`](#vhnetpacket) below) if you need to keep the bytes past the callback.

---

### `vh::net::PcapReader`

Offline `.pcap` / `.pcapng` file reader. Move-only; the destructor closes the file.

```cpp
auto r = vh::net::PcapReader::open("dump.pcap");
while (auto pkt = r->next()) { … }
```

| Method | Signature | Description |
|---|---|---|
| `open` | `static Result<PcapReader> open(std::string_view path)` | Opens a capture file. Format (`.pcap` vs `.pcapng`) is auto-detected. |
| `next` | `std::optional<vanhooks::net::RawPacket> next()` | Reads the next packet, or `std::nullopt` at end of file. |
| `filter` | `PcapReader& filter(std::string_view bpf_expr)` | Restricts subsequent `next()` calls to packets matching the BPF expression. |
| `packets_read` | `uint64_t packets_read() const noexcept` | Running count of packets returned by `next()` so far. |

---

### `vh::net::PcapWriter`

Writes raw or parsed packets to a `.pcap` file. Move-only; the destructor closes the file.

```cpp
auto w = vh::net::PcapWriter::open("out.pcap");
w->write(pkt);
```

| Method | Signature | Description |
|---|---|---|
| `open` | `static Result<PcapWriter> open(std::string_view path)` | Creates (or truncates) a `.pcap` file for writing. |
| `write` | `Status write(const vanhooks::net::RawPacket& pkt)` | Writes a raw packet. |
| `write` | `Status write(const vanhooks::net::Packet& pkt)` | Writes a parsed packet (its current layers, serialized). |
| `close` | `void close()` | Flushes and closes the file early. Called automatically by the destructor. |
| `packets_written` | `uint64_t packets_written() const noexcept` | Running count of packets written so far. |

---

### `vh::net::Packet`

A non-owning view over one raw captured packet, as delivered to a `Capture::PacketCallback`. Valid only for the duration of that callback invocation.

| Method | Return Type | Description |
|---|---|---|
| `raw_data()` | `const uint8_t*` | Pointer to the raw packet bytes. Copy out if you need to retain them. |
| `raw_len()` | `std::size_t` | Length of the raw packet in bytes. |
| `parse()` | `std::unique_ptr<vanhooks::net::Packet>` | Parses the raw bytes into a full protocol-layer stack (see below). |
| `raw()` | `vanhooks::net::RawPacket*` | Escape hatch to the underlying raw-packet object. |

```cpp
cap->start([](vh::net::Packet p) {
    auto parsed = p.parse();
    for (auto* l = parsed->getFirstLayer(); l; l = l->getNextLayer())
        printf("layer: protocol %d\n", static_cast<int>(l->getProtocol()));
});
```

---

### Parsed packets and layers

`Packet::parse()` returns a `vanhooks::net::Packet` — a linked list of `Layer` objects, ordered from lowest (Ethernet) to highest. For a typical HTTP request the chain looks like `EthLayer → IPv4Layer → TcpLayer → HttpRequestLayer`.

| Method | Return Type | Description |
|---|---|---|
| `getFirstLayer()` | `Layer*` | The lowest layer in the packet (usually Ethernet). |
| `getLastLayer()` | `Layer*` | The highest (innermost / most application-specific) layer. |
| `getLayerOfType<TLayer>()` | `TLayer*` | First layer matching a specific type, or `nullptr` if none. |
| `getNextLayerOfType<TLayer>(start)` | `TLayer*` | First matching layer at or after `start`. |
| `getPrevLayerOfType<TLayer>(start)` | `TLayer*` | First matching layer at or before `start`, searching backward. |

Every `Layer` also exposes `getNextLayer()`, `getPrevLayer()`, `getProtocol()`, `getData()`, and `getDataLen()`.

```cpp
auto parsed = pkt.parse();

if (auto* tcp = parsed->getLayerOfType<vanhooks::net::TcpLayer>()) {
    printf("port %u -> %u\n", tcp->getSrcPort(), tcp->getDstPort());
}
```

**Commonly used layer classes** (all in `vanhooks::net::`, headers `vanhooks/net/L2Layers.h`, `L3Layers.h`, `L4Layers.h`):

| Class | OSI layer | Header | Key accessors |
|---|---|---|---|
| `EthLayer` | L2 | `L2Layers.h` | `getSourceMac()`, `getDestMac()`, `getEthHeader()` |
| `VlanLayer` | L2 | `L2Layers.h` | 802.1Q tagging fields |
| `ArpLayer` | L2 | `L2Layers.h` | `getArpHeader()` |
| `IPv4Layer` | L3 | `L3Layers.h` | `getSrcIPv4Address()`, `getDstIPv4Address()`, `getIPv4Header()` |
| `IPv6Layer` | L3 | `L3Layers.h` | `getSrcIPAddress()`, `getDstIPAddress()` |
| `IcmpLayer` | L3 | `L3Layers.h` | `getIcmpHeader()` |
| `VxlanLayer` | L3 (tunnel) | `L3Layers.h` | VXLAN VNI and inner-frame access |
| `TcpLayer` | L4 | `L4Layers.h` | `getSrcPort()`, `getDstPort()`, `getTcpHeader()`, TCP options via `TcpOption` |
| `UdpLayer` | L4 | `L4Layers.h` | `getSrcPort()`, `getDstPort()`, `getUdpHeader()` |

All layer, address (`MacAddress`, `IPv4Address`, `IPv6Address`, `IPAddress`), and device (`PcapLiveDevice`, `PcapLiveDeviceList`) types are declared in the `vanhooks::net` namespace (distinct from `vh::net`, which is the thin RAII/`Result`-based wrapper documented above) and are reached through the escape hatches on `Capture`, `Packet`, `PcapReader`, and `PcapWriter`.

---

## Quick Reference

```cpp
#include <vh/vh.hpp>
```

**Level 1**

```cpp
vh::hook(&fn, &det)
vh::hook(&fn, &det, &orig)
vh::hook("module", "Symbol", &det, &orig)
```

**Level 2**

```cpp
vh::inline_hook (&fn,   &det, &orig,  { .tag = "x" })
vh::api_hook    ("mod", "sym", &det, &orig, { .tag = "x" })
vh::vtable_hook (vtbl,  slot,  det,   orig,  { .tag = "x" })
vh::iat_hook    ("Sym", det,  { .module_name = "m.exe" })
vh::iat_hook_all("Sym", det)
vh::plt_hook    ("lib", "sym", det,   { .tag = "x" })
vh::mid_hook    (ptr,   cb,   { .offset = 0x1C })
```

**Hook methods**

```cpp
h.enable()    h.disable()    h.remove()
h.valid()     h.enabled()    h.tag()
h.kind()      h.target()     h.detour()     h.trampoline()
h.chain(&det2, &orig2)
```

**Group**

```cpp
auto g = vh::group("Name");
g.add(vh::hook(...)).add(vh::vtable_hook(...));
g.enable();    g.disable();    g.remove_all();
g.at("tag").disable();
for (auto& h : g) { ... }
g.queue_enable().apply();
```

**HookRegistry**

```cpp
vh::HookRegistry::global().register_group(std::move(g));
vh::HookRegistry::global().remove_all();
```

**Errors**

```cpp
if (!r) printf("%s\n", vh::error_to_string(r.error()).data());
```

**Pattern scanner**

```cpp
// Range scan
vanhooks::scanner::scan_pattern(base, size, "48 8B 05 ? ? ? ?");
// Process-wide (Windows)
vanhooks::scanner::scan_process("E8 ? ? ? ? 85 C0");
// Named module (Windows)
vanhooks::scanner::scan_module("game.exe", "48 89 5C 24 ?");
// Exact bytes (no wildcards)
vanhooks::scanner::scan_bytes(base, size, needle_span);
// Pre-compiled pattern for reuse
auto pat = vanhooks::scanner::parse_pattern("48 8B 05 ? ? ? ?").value();
```

**Anti-debug**

```cpp
auto report = vanhooks::antidebug::check_all();
report.any_detected();       // bool
report.detection_count();    // int
report.findings;             // vector<Finding> — each has .technique, .detected, .detail
```

**Disassembler**

```cpp
vh::disasm::Disassembler dis;
dis.decode_one(code_span, runtime_va);
dis.decode_min_bytes(code_span, runtime_va, min_bytes);
vh::disasm::decode_until_branch(fn_ptr, 128);
vh::disasm::decode_prologue(fn_ptr, 5);
vh::disasm::safe_copy_length(fn_ptr, 5);
vh::disasm::rewrite(insns, original_va, new_va);
vh::disasm::format_insn(insn);
vh::disasm::format_listing(insns);
```

**Process injection (Windows, VH_INJECT_ENABLED)**

```cpp
vh::inject(pid, "payload.dll", { .method = vh::InjectMethod::ManualMap });
vh::inject_from_memory(pid, pe_bytes, { .method = vh::InjectMethod::ThreadHijack });
inj.eject();    inj.valid();    inj.method();    inj.pid();
```

**Symbol resolution (VH_SYMBOLS_ENABLED)**

```cpp
vh::symbols::resolve(address);           // → Result<Symbol>
vh::symbols::find("CreateFileW", "ntdll");
vh::symbols::source_location(address);   // → Result<SourceLocation>
vh::symbols::load_module("path/to.pdb");
vh::symbols::current_stack();            // → vector<string> (formatted)
vh::symbols::demangle(raw_name);
```

**PE introspection (Windows, VH_PE_ENABLED)**

```cpp
auto pe = vh::pe::open("ntdll.dll");
pe->sections();                          // Result<vector<Section>>
pe->find_export("NtQuerySystemInformation");
pe->find_import("kernel32.dll", "VirtualProtect");
pe->find_caves(/*min_size=*/32, /*exec_only=*/true);
vh::pe::modules();                       // all loaded modules
```

**Breakpoints (VH_BREAKPOINT_ENABLED)**

```cpp
// Software (INT3 / VEH / SIGTRAP)
vh::breakpoint::set_software(addr, [](uintptr_t a) { return Action::Continue; });
// Hardware (DR0–DR3, x86-64 only)
vh::breakpoint::set_hardware(addr, HwCondition::Write, HwSize::Dword, cb);
bp.remove();    bp.active();    bp.address();
bp.apply_to_new_thread(hthread);   // Windows, hardware only
```

**Call stack (VH_CALLSTACK_ENABLED)**

```cpp
vh::callstack::capture(/*skip=*/2, /*max=*/32);    // Result<vector<uintptr_t>>
vh::callstack::capture_annotated();                // Result<vector<Frame>> (needs VH_SYMBOLS_ENABLED)
vh::callstack::format(frames);                     // string
```

**Network — devices & filters**

```cpp
vh::net::devices()                       // std::vector<DeviceInfo>
vh::net::Filter{}.expr("tcp port 443")
```

**Network — capture**

```cpp
auto cap = vh::net::Capture::open("eth0");        // or open_by_ip("10.0.0.5")
cap->filter("udp port 53").snap_len(65535).promiscuous(true);
cap->start([](vh::net::Packet p) { ... });
cap->stop();       cap->running();       cap->stats();
```

**Network — pcap / pcapng files**

```cpp
auto r = vh::net::PcapReader::open("in.pcap");
while (auto pkt = r->next()) { ... }

auto w = vh::net::PcapWriter::open("out.pcap");
w->write(pkt);
```

**Network — parsing**

```cpp
auto parsed = pkt.parse();
parsed->getFirstLayer();   parsed->getLastLayer();
parsed->getLayerOfType<vanhooks::net::TcpLayer>();
```

---

<div align="center">
<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:0A0A0A,50:7A0C0C,100:0A0A0A&height=90&section=footer"/>
</div>
