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

[Glossary](#glossary) · [Result Type](#result-type) · [Level 1 API](#level-1-api) · [Level 2 API](#level-2-api) · [Hook Object](#hook-object) · [Group](#group) · [HookRegistry](#hookregistry) · [Config Structs](#config-structs) · [Error Codes](#error-codes) · [Network API](#network-api) · [Quick Reference](#quick-reference)

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
