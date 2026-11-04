<div align="center">

<img src="vh-logo.png" width="400" alt="VanHooks"/>

# VanHooks — Functions Guide

**Public API Reference · v0.1.0**  
C++23 · Windows / Linux / macOS · x86 / x64 / ARM64

[![License: MIT](https://img.shields.io/badge/License-MIT-DC2626?style=for-the-badge&labelColor=0D0D0D)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-DC2626?style=for-the-badge&labelColor=0D0D0D&logo=cplusplus&logoColor=DC2626)](https://en.cppreference.com/w/cpp/23)
[![TeamVanilla](https://img.shields.io/badge/Team-TeamVanilla-DC2626?style=for-the-badge&labelColor=0D0D0D)](https://www.teamvanilla.org/)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

One include is all you need:

```cpp
#include <vh/vh.vh>
```

Everything in this document lives in the `vh::` namespace unless stated otherwise.

<div align="center">

### 📑 Contents

[Legend](#-part-i--legend) · [Result Type](#-part-ii--result-type-and-error-handling) · [Level 1 API](#-part-iii--level-1-api) · [Level 2 API](#-part-iv--level-2-api)

[Hook Object](#-part-v--hook-object-methods) · [Group](#-part-vi--group) · [HookRegistry](#-part-vii--hookregistry) · [Configuration](#%EF%B8%8F-part-viii--configuration-structs)

[Error Codes](#-part-ix--error-codes) · [Quick Reference](#-part-x--quick-reference-card) · [Process Injection](#-part-xi--process-injection) · [Stealth Helpers](#-part-xii--stealth-helpers-vhinject_stealth)

[Phase 10 — Hardening](#-part-xiii--phase-10-hardening) · [Shared Library ABI](#-part-xiv--shared-library-abi) · [Hook Engine v2](#-part-xv--hook-engine-v2) · [Cross-Platform Parity](#-part-xvi--cross-platform-hook-parity)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📖 Part I — Legend

Seven words. Everything else is detail.

### HOOK

Both the act of interception and the object that represents it. When you "hook a function" you are redirecting it so that your code runs instead of (or before) the original. The `vh::Hook` object is what you get back — it owns the interception for as long as it lives, and removes it automatically when it is destroyed.

### TARGET

The function or address being intercepted. You point VanHooks at the target and it installs the redirection. The target keeps working normally if you call it through the Original (see below); otherwise calls to it go to your Detour instead.

### DETOUR

Your replacement function. It must have the same calling convention and signature as the target. When the target is called, execution jumps to your detour first. You decide what happens from there: call the original, modify arguments, block the call entirely, log it, or anything else.

### ORIGINAL

A pointer through which you can call the target as if the hook were not there. VanHooks sets this up automatically. You declare a function pointer of the same type as the target, pass its address when creating the hook, and VanHooks fills it in. After that, calling through that pointer bypasses the detour and reaches the real function.

### ENABLE

Activate a hook so that calls to the target go to your detour. Hooks are enabled by default when created. You can disable and re-enable a hook without removing it, which is useful for temporarily restoring original behaviour.

### DISABLE

Deactivate a hook without removing it. The target function behaves as if the hook were never installed. The hook object still exists and can be re-enabled. Resources are retained. This is cheaper than remove followed by reinstall.

### REMOVE

Permanently uninstall a hook and release all resources associated with it. The `Hook` object becomes invalid after `remove()`. In normal use you do not call this manually — the `Hook` destructor calls it for you (RAII).

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ❌ Part II — Result Type and Error Handling

Every hook creation function returns `Result<Hook>`, not `Hook` directly. `Result<T>` is an alias for `std::expected<T, vh::Error>`.

### Checking for success

```cpp
auto r = vh::hook(&my_fn, &my_detour);

if (!r) {
    // r.error() is a vh::Error code
    printf("failed: %s\n", vh::error_to_string(r.error()).data());
    return;
}

// r.value() or *r is the Hook
vh::Hook h = std::move(*r);
```

### Checking validity after the fact

```cpp
auto r = vh::hook(&fn, &detour);
if (r && r->valid()) { /* use it */ }
```

### Chaining with `.and_then()` / `.transform()`

```cpp
auto r = vh::hook(&fn, &detour, &orig)
    .and_then([](vh::Hook h) -> vh::Result<vh::Hook> {
        h.disable();
        return h;
    });
```

### `error_to_string`

```cpp
std::string_view vh::error_to_string(vh::Error e) noexcept;
```

Returns a human-readable name for any `Error` code. Useful for logging. The returned `string_view` points to static storage — do not free it.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚡ Part III — Level 1 API

*Beginner — one line, zero concepts required.*

These three overloads of `vh::hook()` cover the most common cases. No options struct needed.

---

### `vh::hook(target, detour)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(Fn* target, Fn* detour);
```

The simplest form. Intercept `target` so that every call goes to `detour` instead. The hook is enabled immediately. No original pointer — if you need to call through to the real function, use the three-argument form below.

| Parameter | Description |
|---|---|
| `target` | Pointer to the function to intercept. Must not be null. |
| `detour` | Pointer to your replacement function. Same signature as `target`. |

**Returns:** `Result<Hook>`. On success, the Hook is valid and the interception is live. On failure, check `.error()` for the reason.

```cpp
int detour_add(int a, int b) {
    printf("add intercepted\n");
    return a + b;
}

auto h = vh::hook(&add, &detour_add);
```

---

### `vh::hook(target, detour, original_out)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(Fn* target, Fn* detour, Fn** original_out);
```

Same as above, but also sets up a call-through pointer so your detour can invoke the real function. VanHooks writes the trampoline address into `*original_out` when the hook is successfully installed.

| Parameter | Description |
|---|---|
| `target` | Pointer to the function to intercept. |
| `detour` | Pointer to your replacement function. |
| `original_out` | Address of a function pointer variable. Declare as `static Fn* orig = nullptr;`. VanHooks fills this in on success. |

```cpp
static int (*orig_add)(int, int) = nullptr;

int detour_add(int a, int b) {
    printf("add(%d, %d)\n", a, b);
    return orig_add(a, b);   // call through to the real function
}

auto h = vh::hook(&add, &detour_add, &orig_add);
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

Hook a function by name instead of by pointer. VanHooks resolves the address using `GetModuleHandle` + `GetProcAddress` on Windows, or `dlsym` on Linux and macOS. Useful when you cannot take the address of the function at compile time — system functions, functions in loaded DLLs, and so on.

| Parameter | Description |
|---|---|
| `module` | Module name. On Windows: `"user32"` or `"user32.dll"` (either form works). On Linux/macOS: the shared library name, e.g. `"libm.so.6"` or `"libm"`. |
| `symbol` | Exported function name, e.g. `"MessageBoxW"` or `"malloc"`. |
| `detour` | Pointer to your replacement function. |
| `original_out` | Optional. Same as the three-argument form above. |

```cpp
static decltype(&MessageBoxW) orig_mbw = nullptr;

BOOL WINAPI hk_mbw(HWND h, LPCWSTR t, LPCWSTR c, UINT f) {
    return orig_mbw(h, L"[Intercepted]", c, f);
}

auto hook = vh::hook("user32", "MessageBoxW", &hk_mbw, &orig_mbw);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🪝 Part IV — Level 2 API

*Explicit hook types — same `Hook` object, more control.*

These functions name the hook kind explicitly and accept an options struct for configuration. They all return the same `Result<Hook>` type. Use these when you need a tag, need to control thread suspension, or when the hook kind matters to your code's clarity.

---

### `vh::inline_hook`

```cpp
template<typename Fn>
Result<Hook> vh::inline_hook(Fn* target,
                             Fn* detour,
                             Fn** original_out = nullptr,
                             config::Trampoline opts = {});
```

Patches the first bytes of `target` with a jump to `detour`, and builds a trampoline so the original can still be called. This is the most common hook type and works on any function whose prologue is long enough to hold a jump instruction (5 bytes on x86/x64, 16 bytes on ARM64).

The compiler-enforced template means `target` and `detour` must have the same function type. Mismatches are compile errors, not runtime crashes.

**Options:** [`vh::config::Trampoline`](#vhconfigtrampoline)

```cpp
auto h = vh::inline_hook(&add, &detour_add, &orig_add,
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

Resolves `target` by module and symbol name, then installs an inline hook. Equivalent to `vh::hook(module, symbol, detour, original_out)` but accepts the full options struct.

**Options:** [`vh::config::Trampoline`](#vhconfigtrampoline)

```cpp
auto h = vh::api_hook("user32", "MessageBoxW",
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

Patches a single slot in a C++ virtual function table. Use this when the function you want to intercept is a virtual method and you have a pointer to an object of that class (or to the vtable directly).

A vtable is an array of function pointers that C++ uses to dispatch virtual calls. Each slot corresponds to one virtual method in declaration order. Slot 0 is the first virtual method, slot 1 the second, and so on. Inherited virtual methods appear first; the derived class's own virtuals follow.

| Parameter | Description |
|---|---|
| `vtable` | Pointer to the vtable array. Obtain with: `void** vtbl = *reinterpret_cast<void***>(object_pointer);` |
| `slot` | Zero-based index of the virtual method to replace. |
| `detour` | Replacement function. Must match the virtual method's signature, including the implicit `this` pointer as the first argument. |
| `original_out` | Optional. Filled with a callable pointer to the original slot value. |

**Options:** [`vh::config::VTable`](#vhconfigvtable)

```cpp
// Hook IDXGISwapChain::Present (slot 8 in the DXGI vtable)
void** vtbl = *reinterpret_cast<void***>(swap_chain);

static HRESULT (STDMETHODCALLTYPE *orig_Present)
    (IDXGISwapChain*, UINT, UINT) = nullptr;

HRESULT STDMETHODCALLTYPE hk_Present(IDXGISwapChain* sc, UINT sync, UINT flags) {
    // render overlay here
    return orig_Present(sc, sync, flags);
}

auto h = vh::vtable_hook(vtbl, 8,
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

**Windows only.** Patches an Import Address Table entry so that calls from a specific module to `import_name` go to your `detour` instead. Unlike an inline hook, this does not modify the target function itself — it modifies the pointer that the calling module uses to reach it.

Use this when you want to intercept calls from one specific module without affecting every other caller of the same function, or when the target function is too short to inline-hook safely.

| Parameter | Description |
|---|---|
| `import_name` | The exported symbol name to redirect, e.g. `"MessageBoxW"`. |
| `detour` | Replacement function pointer (`void*`). |

**Options:** [`vh::config::IAT`](#vhconfigiat)

```cpp
auto h = vh::iat_hook("MessageBoxW", (void*)&hk_mbw,
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

**Windows only.** Same as `iat_hook`, but patches every IAT entry matching `import_name` across all loaded modules simultaneously. Returns a vector of `Hook` objects, one per patched slot. Useful for functions like `malloc` or `VirtualAlloc` whose IAT entry appears in many DLLs.

`module_name` in the options struct is ignored here — all modules are searched.

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

**Linux and macOS only.** Patches a Procedure Linkage Table (Linux) or lazy pointer (macOS) entry in the dynamic linker so calls to `symbol` from the specified library are redirected to your detour.

This is the POSIX equivalent of `iat_hook`. It intercepts dynamic linker indirection rather than the function itself, making it safe for functions whose prologues are too short to inline-hook.

| Parameter | Description |
|---|---|
| `library` | The shared library name, e.g. `"libc"` or `"libpthread"`. |
| `symbol` | The symbol name, e.g. `"malloc"` or `"pthread_create"`. |
| `detour` | Replacement function pointer (`void*`). |

**Options:** [`vh::config::PLT`](#vhconfigplt)

```cpp
static void* (*orig_malloc)(size_t) = nullptr;

void* hk_malloc(size_t size) {
    void* p = orig_malloc(size);
    printf("malloc(%zu) = %p\n", size, p);
    return p;
}

auto h = vh::plt_hook("libc", "malloc", (void*)&hk_malloc,
                      { .tag = "libc.malloc" });
```

---

### `vh::mid_hook`

```cpp
Result<Hook> vh::mid_hook(void* target,
                          MidCallback callback,
                          config::Mid opts = {});
```

Installs a hook at a specific byte offset inside a function rather than at its entry point. Unlike all other hook types, a mid-function hook does not redirect control flow — it observes and optionally modifies CPU register state at the chosen instruction boundary, then lets the original instructions continue executing.

The hook site is rounded up to the nearest complete instruction boundary so that no instruction is split.

| Parameter | Description |
|---|---|
| `target` | Pointer to the start of the function containing the hook site. |
| `callback` | Function called at the hook site. Receives a `MidContext*` holding a snapshot of all general-purpose registers and flags. Must be `noexcept`. Must not throw. |

**Options:** [`vh::config::Mid`](#vhconfigmid)

**`MidCallback` signature:**

```cpp
using MidCallback = void (*)(MidContext*) noexcept;
```

**`MidContext` fields — x64:**

| Field | Type | Description |
|---|---|---|
| `rax` … `r15` | `uint64_t` | General-purpose registers |
| `rflags` | `uint64_t` | CPU flags |

**`MidContext` fields — ARM64:**

| Field | Type | Description |
|---|---|---|
| `x[8]` | `uint64_t[8]` | Argument registers x0–x7 |
| `lr` | `uint64_t` | Link register (x30) |

**`MidContext` fields — x86:**

| Field | Type | Description |
|---|---|---|
| `eax` … `edi` | `uint32_t` | General-purpose registers |
| `eflags` | `uint32_t` | CPU flags |

Read a register: `ctx->rax`  
Write a register: `ctx->rax = new_value` — takes effect when the callback returns.

```cpp
auto h = vh::mid_hook(game_update_ptr,
    [](vh::MidContext* ctx) noexcept {
        player_health = static_cast<int>(ctx->rax);
    },
    { .offset = 0x1C, .tag = "Game.HealthReadback" });
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔒 Part V — Hook Object Methods

Every creation function returns `Result<Hook>`. Dereference the result to get the `Hook`. The `Hook` is move-only — it cannot be copied.

The `Hook` calls `remove()` in its destructor. You do not need to clean up manually unless you want to remove the hook before the `Hook` object goes out of scope.

### Lifecycle

| Method | Signature | Description |
|---|---|---|
| `enable` | `Hook& enable()` | Activates the hook so calls to the target go to the detour. Returns `*this` for chaining. No-op if already enabled. |
| `disable` | `Hook& disable()` | Deactivates the hook. The target behaves as if unhooked. Hook remains valid and can be re-enabled. Returns `*this`. |
| `remove` | `void remove()` | Permanently removes the hook and releases all resources. After `remove()`, `valid()` returns `false`. The destructor calls this automatically. |

### Chaining

```cpp
Result<Hook> hook.chain(void* next_detour,
                        void** next_original_out = nullptr,
                        std::string tag = {})

Result<Hook> hook.chain(Fn* next_detour,
                        Fn** next_original_out = nullptr,
                        std::string tag = {})
```

Adds a second detour onto an already-hooked target. The new detour is inserted in front of the existing one. Execution order after chaining:

```
next_detour → original_detour → real_function
```

The chain link is itself a `Hook` object and **must be removed before the base hook**. Removing the base first returns `Error::ChainOrderViolation`.

```cpp
auto base = vh::inline_hook(&fn, &detour1, &orig1).value();

static decltype(&fn) next_orig = nullptr;
auto link = base.chain(&detour2, &next_orig).value();

// Later, in reverse order:
link.remove();
base.remove();
```

### Introspection

| Method | Return Type | Description |
|---|---|---|
| `valid()` | `bool` | Is this hook installed and usable? |
| `enabled()` | `bool` | Is the hook currently active? |
| `tag()` | `std::string` | The tag string set at creation, or empty. |
| `kind()` | `HookKind` | Which hook type this is. |
| `target()` | `void*` | Address of the original function. |
| `detour()` | `void*` | Address of your replacement function. |
| `trampoline()` | `void*` | Address of the call-through trampoline. `nullptr` for IAT, PLT, and VTable hooks. |
| `operator bool()` | `bool` | Equivalent to `valid()`. |

**`HookKind` values:**

| Value | Installed by |
|---|---|
| `HookKind::Trampoline` | `inline_hook`, `api_hook` |
| `HookKind::IAT` | `iat_hook`, `iat_hook_all` |
| `HookKind::PLT` | `plt_hook` |
| `HookKind::VTable` | `vtable_hook` |
| `HookKind::Mid` | `mid_hook` |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📦 Part VI — Group

A `Group` owns a collection of `Hook` objects and manages their lifecycle together. All enable/disable operations on a `Group` happen inside a single thread-suspension window, making batch operations significantly cheaper than calling `enable()` on each hook individually.

Create a Group with:

```cpp
auto grp = vh::group("GroupName");
```

The name is optional but recommended for logging and registry lookup. The `Group` removes all its hooks when it goes out of scope (RAII).

### Adding Hooks

```cpp
Group& grp.add(Hook hook)
```
Moves a `Hook` into the group. Takes ownership. Returns `*this`.

```cpp
Group& grp.add(Result<Hook> result)
```
Adds a `Hook` from a `Result`. If the `Result` holds an error, the add is silently skipped. Returns `*this`. Use this to add hooks inline without checking each one individually:

```cpp
grp.add(vh::vtable_hook(vtbl, 8, (void*)&hk_Present))
   .add(vh::vtable_hook(vtbl, 16, (void*)&hk_Reset))
   .add(vh::iat_hook("CreateDevice", (void*)&hk_CreateDevice));
```

### Lifecycle

| Method | Signature | Description |
|---|---|---|
| `enable` | `Group& enable()` | Enables all hooks. One thread-suspension window for all. Returns `*this`. |
| `disable` | `Group& disable()` | Disables all hooks. One thread-suspension window. Returns `*this`. |
| `remove_all` | `void remove_all()` | Removes and destroys all hooks. One thread-suspension window. Group is empty afterward but still usable. |
| `clear` | `void clear()` | Alias for `remove_all()`. |

### Queued Batch Operations

For very large hook sets, queue operations across multiple steps then flush once.

| Method | Signature | Description |
|---|---|---|
| `queue_enable` | `Group& queue_enable()` | Queues enable for all hooks without flushing. Returns `*this`. |
| `queue_disable` | `Group& queue_disable()` | Queues disable for all hooks without flushing. Returns `*this`. |
| `apply` | `Status apply()` | Flushes all queued operations in one thread-suspension window. |

```cpp
// Enable 200 hooks in one suspension window
auto grp = vh::group("AllHooks");
for (auto& def : hook_defs)
    grp.add(vh::inline_hook(def.target, def.detour, def.orig));

grp.queue_enable().apply();
```

### Lookup and Iteration

| Method | Return Type | Description |
|---|---|---|
| `size()` | `size_t` | Number of hooks currently in the group. |
| `empty()` | `bool` | True if the group contains no hooks. |
| `name()` | `std::string` | The name passed to `vh::group()`. |
| `operator[](size_t i)` | `Hook&` | Access hook by index. Throws `std::out_of_range` if `i >= size()`. |
| `at(string_view tag)` | `Hook&` | Find a hook by its tag string. Throws `std::out_of_range` if not found. |

Range-based for loop is supported:

```cpp
for (auto& h : grp) {
    if (h.tag().starts_with("Network")) h.disable();
}
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🏭 Part VII — HookRegistry

`HookRegistry` is a process-wide singleton that owns named `Group`s. Use it when multiple modules (DLLs) in the same process need to register hooks independently and a single shutdown call should clean all of them up.

**When to use `HookRegistry` vs `Group` alone:**  
If your project is a single DLL or executable with one logical hook owner, a `Group` is sufficient. Use `HookRegistry` when two or more independently-compiled modules each install hooks and need coordinated cleanup at process or plugin shutdown.

**Access:** `vh::HookRegistry::global()`

### Methods

| Method | Signature | Description |
|---|---|---|
| `register_group` | `void register_group(Group group)` | Takes ownership of a `Group`. The group is looked up by its name. |
| `find_group` | `Group* find_group(string_view name)` | Returns a pointer to the named group, or `nullptr` if not found. |
| `enable_all` | `void enable_all()` | Enable all hooks in all registered groups. |
| `disable_all` | `void disable_all()` | Disable all hooks in all registered groups. |
| `remove_all` | `void remove_all()` | Remove all hooks and clear all groups. |
| `total_hook_count` | `size_t total_hook_count()` | Total number of hooks across all registered groups. |

```cpp
// Module A (render):
auto render = vh::group("Render");
render.add(vh::vtable_hook(vtbl, 8, (void*)&hk_Present));
vh::HookRegistry::global().register_group(std::move(render));

// Module B (network):
auto net = vh::group("Network");
net.add(vh::api_hook("ws2_32", "send", &hk_send));
vh::HookRegistry::global().register_group(std::move(net));

// Shutdown — one call removes everything from both modules:
vh::HookRegistry::global().remove_all();
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚙️ Part VIII — Configuration Structs

All config structs live in the `vh::config::` namespace and are defined in `<vh/config.vh>`, which is included automatically by `<vh/vh.vh>`.

---

### `vh::config::Trampoline`

Used by: `inline_hook`, `api_hook`

```cpp
struct Trampoline {
    bool        thread_safe = true;
    std::string tag;
};
```

| Field | Type | Default | Description |
|---|---|---|---|
| `thread_safe` | `bool` | `true` | When `true`, all threads in the process are suspended during hook installation and removal so no thread can be executing inside the bytes being patched. This is safe and correct in almost every situation. Set to `false` only if you are installing the hook from within a callback that is already executing inside the target function (rare). |
| `tag` | `std::string` | `""` | A label stored with the hook. Used for debugging, logging, and `Group::at()` lookup. No constraints on content. Recommended convention: `"Module.Function"` or `"Category.Name"`. |

---

### `vh::config::IAT`

Used by: `iat_hook`, `iat_hook_all`

```cpp
struct IAT {
    std::string_view module_name;
    std::string_view import_name;
    std::string      tag;
};
```

| Field | Type | Default | Description |
|---|---|---|---|
| `module_name` | `string_view` | `""` | The module whose import table to patch. If empty, VanHooks searches all loaded modules and patches the first match. On Windows: `"my_app.exe"` or `"some_plugin.dll"`. |
| `import_name` | `string_view` | `""` | Unused when calling `iat_hook()` — the import name is passed as the first argument to the function instead. Present in the struct for completeness. |
| `tag` | `std::string` | `""` | Label for this hook. |

---

### `vh::config::PLT`

Used by: `plt_hook`

```cpp
struct PLT {
    std::string_view library_name;
    std::string_view symbol_name;
    std::string      tag;
};
```

| Field | Type | Default | Description |
|---|---|---|---|
| `library_name` | `string_view` | `""` | Unused when calling `plt_hook()` — passed as the first argument instead. |
| `symbol_name` | `string_view` | `""` | Unused when calling `plt_hook()` — passed as the second argument instead. |
| `tag` | `std::string` | `""` | Label for this hook. |

---

### `vh::config::VTable`

Used by: `vtable_hook`

```cpp
struct VTable {
    void**      vtable = nullptr;
    size_t      slot   = 0;
    std::string tag;
};
```

| Field | Type | Default | Description |
|---|---|---|---|
| `vtable` | `void**` | `nullptr` | Unused when calling `vtable_hook()` — passed as the first argument instead. |
| `slot` | `size_t` | `0` | Unused when calling `vtable_hook()` — passed as the second argument instead. |
| `tag` | `std::string` | `""` | Label for this hook. In practice, `tag` is the only field set via the opts parameter. |

```cpp
vh::vtable_hook(vtbl, 8, detour, orig, { .tag = "DXGI.Present" });
```

---

### `vh::config::Mid`

Used by: `mid_hook`

```cpp
struct Mid {
    size_t      offset      = 0;
    bool        thread_safe = true;
    std::string tag;
};
```

| Field | Type | Default | Description |
|---|---|---|---|
| `offset` | `size_t` | `0` | Byte offset from the start of the target function where the hook is installed. The actual patch site is rounded up to the nearest complete instruction boundary. Default `0` hooks the function entry. |
| `thread_safe` | `bool` | `true` | Same meaning as `config::Trampoline::thread_safe`. |
| `tag` | `std::string` | `""` | Label for this hook. |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🚨 Part IX — Error Codes

All error codes are values of the `vh::Error` enum (`uint32_t` underlying type). Use `vh::error_to_string(e)` to get the name as a `string_view`.

### General

| Code | Value | Meaning |
|---|---|---|
| `Ok` | 0 | Not an error. Returned on success by void operations. |
| `NotInitialized` | 1 | The engine has not been initialised yet. |
| `AlreadyInitialized` | 2 | Initialisation attempted twice. |
| `InvalidArgument` | 3 | A null pointer or nonsensical value was passed. |
| `Unsupported` | 4 | The operation is not supported on this platform or architecture (e.g. IAT hooks on Linux). |
| `OutOfRange` | 5 | An index or offset was outside valid bounds. |
| `OsError` | 6 | An OS call failed. Check `GetLastError()` (Windows) or `errno` (POSIX). |

### Memory

| Code | Value | Meaning |
|---|---|---|
| `MemoryAllocationFailed` | 100 | Could not allocate memory for the trampoline or hook infrastructure. May indicate the process is out of memory or that no suitable region was found near the target for a near-jump trampoline. |
| `MemoryProtectFailed` | 101 | Could not change memory protection on the target function's page (e.g. `VirtualProtect` failed). |
| `MemoryReadFailed` | 102 | Could not read from the target address. |
| `MemoryWriteFailed` | 103 | Could not write the patch bytes to the target. |
| `TrampolineNoSpace` | 104 | The target function's prologue was too short to safely steal enough bytes for the hook jump. The function may be too small to hook by inline patching. Consider `iat_hook` or `plt_hook` instead. |

### Hook Lifecycle

| Code | Value | Meaning |
|---|---|---|
| `HookNotFound` | 200 | The handle refers to a hook that does not exist or has already been removed. |
| `HookAlreadyExists` | 201 | Attempted to hook the same target address twice. |
| `HookInstallFailed` | 202 | The hook could not be installed for an unspecified internal reason. Usually preceded by a more specific memory error. |
| `HookRemoveFailed` | 203 | The hook could not be removed cleanly. |
| `HookAlreadyEnabled` | 204 | `enable()` was called on a hook that was already active. |
| `HookAlreadyDisabled` | 205 | `disable()` was called on a hook that was already inactive. |

### Disassembly

| Code | Value | Meaning |
|---|---|---|
| `DisassemblyFailed` | 300 | The disassembler could not decode an instruction at the target address. The bytes may not be valid code for the current architecture. |
| `InstructionTooShort` | 301 | An instruction was encountered that is shorter than the minimum needed for relocation. |
| `UnsupportedInstruction` | 302 | The target prologue contains an instruction that cannot be safely relocated into the trampoline (e.g. a relative branch whose destination would be out of range after relocation). On x64 this is rare. On ARM64 it may occur with certain conditional branches very close to the function entry. |

### Module and Symbol

| Code | Value | Meaning |
|---|---|---|
| `ModuleNotFound` | 400 | The module named in an `api_hook` or `iat_hook` call could not be found among the loaded modules. |
| `SymbolNotFound` | 401 | The symbol name could not be resolved within the specified module. |
| `IATEntryNotFound` | 402 | No IAT entry for the requested import was found in the specified (or any) loaded module. |
| `PLTEntryNotFound` | 403 | No PLT/GOT entry for the requested symbol was found in the specified shared library. |

### Thread

| Code | Value | Meaning |
|---|---|---|
| `ThreadSuspendFailed` | 500 | VanHooks could not suspend one or more threads during hook installation. The hook was not installed. |
| `ThreadResumeFailed` | 501 | After patching, VanHooks could not resume a suspended thread. The hook is installed but the process may be in a degraded state. |
| `ThreadInPrologue` | 502 | A suspended thread's instruction pointer was found inside the bytes being patched. VanHooks advances it past the patch automatically. This code appearing in logs is informational, not fatal. |

### Batch and Chain

| Code | Value | Meaning |
|---|---|---|
| `QueueEmpty` | 600 | `Group::apply` was called with nothing in the queue. Treat as a warning if unexpected. |
| `ChainBaseNotFound` | 601 | The base hook passed to `hook.chain()` is not known to the engine, likely because it was already removed. |
| `ChainOrderViolation` | 602 | A chain link was removed before its base hook. Always remove chain links in reverse order of creation. |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📋 Part X — Quick Reference Card

### Include

```cpp
#include <vh/vh.vh>
```

### Level 1 — One line

```cpp
auto h = vh::hook(&fn, &det);                          // no original
auto h = vh::hook(&fn, &det, &orig);                   // with original
auto h = vh::hook("user32", "MessageBoxW", &det, &o);  // by name
```

### Level 2 — Explicit type

```cpp
vh::inline_hook (&fn,   &det, &orig, { .tag = "x" })        // trampoline
vh::api_hook    ("mod", "sym", &det, &orig, { .tag = "x" })  // by name
vh::vtable_hook (vtbl,  slot,  det,  orig,  { .tag = "x" })  // virtual
vh::iat_hook    ("Sym", det, { .module_name = "m.exe" })      // Windows IAT
vh::iat_hook_all("Sym", det, {})                              // all modules
vh::plt_hook    ("lib", "sym", det, { .tag = "x" })           // Linux / macOS
vh::mid_hook    (ptr,   cb,   { .offset = 0x1C })             // mid-function
```

### Hook methods

```cpp
h.enable()    h.disable()    h.remove()
h.valid()     h.enabled()    h.tag()
h.kind()      h.target()     h.detour()    h.trampoline()
h.chain(&det2, &orig2)
```

### Group

```cpp
auto g = vh::group("Name");
g.add(vh::hook(...)).add(vh::vtable_hook(...));
g.enable();    g.disable();    g.remove_all();
g.at("tag").disable();
for (auto& h : g) { ... }
g.queue_enable().apply();
```

### HookRegistry

```cpp
vh::HookRegistry::global().register_group(std::move(g));
vh::HookRegistry::global().remove_all();
```

### Error handling

```cpp
if (!r) printf("%s\n", vh::error_to_string(r.error()).data());
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 💉 Part XI — Process Injection

```cpp
#include <vh/inject/inject.vh>
```

VanHooks provides a complete process injection subsystem. All injection paths are hardened with indirect syscalls — no direct Win32 API calls that EDR can hook. The RAII `Injection` object ejects automatically on scope exit, following the same ownership model as `Hook`.

### `vh::InjectMethod`

```cpp
enum class InjectMethod : uint8_t {
    LoadLibrary,   // CreateRemoteThread + LoadLibraryA — simple, detected
    ManualMap,     // Manual PE mapping — no module-list entry
    ThreadHijack,  // Context-redirect existing thread — no remote thread
    ApcQueue,      // Queue APC to alertable threads — timing non-deterministic
};
```

### `vh::config::Inject`

```cpp
struct Inject {
    InjectMethod method = InjectMethod::LoadLibrary;
    std::string  tag;
};
```

| Field | Type | Default | Description |
|---|---|---|---|
| `method` | `InjectMethod` | `LoadLibrary` | Which injection technique to use. |
| `tag` | `std::string` | `""` | Label for identification and logging. |

---

### `vh::inject`

```cpp
Result<Injection> vh::inject(uint32_t pid,
                              std::string_view dll_path,
                              config::Inject opts = {});
```

Inject a DLL by file path into process `pid`. The DLL path must be fully qualified and accessible from the target process.

| Parameter | Description |
|---|---|
| `pid` | Target process ID. |
| `dll_path` | Fully-qualified DLL path. |
| `opts` | Method and optional tag. |

**Returns:** `Result<Injection>`. On success, the `Injection` RAII handle is valid and the DLL is loaded in the target process. On failure, check `.error()`.

```cpp
auto inj = vh::inject(pid, "C:\\payloads\\research.dll",
    { .method = vh::InjectMethod::ManualMap, .tag = "research" });
```

---

### `vh::inject_from_memory`

```cpp
Result<Injection> vh::inject_from_memory(uint32_t pid,
                                          std::span<const uint8_t> pe_bytes,
                                          config::Inject opts = {});
```

Inject from an in-memory PE image. If `opts.method` is `ManualMap`, the image is mapped directly into the target without touching disk. For other methods, the image is written to a temp file, loaded via the chosen method, and the file is deleted immediately after.

| Parameter | Description |
|---|---|
| `pid` | Target process ID. |
| `pe_bytes` | Raw PE bytes. Must be a valid x64 DLL for ManualMap. |
| `opts` | Method and optional tag. |

```cpp
std::vector<uint8_t> pe = load_from_resource();
auto inj = vh::inject_from_memory(pid, pe,
    { .method = vh::InjectMethod::ManualMap, .tag = "stealth" });
```

---

### `vh::eject`

```cpp
Result<void> vh::eject(Injection& inj);
```

Explicitly eject an injection. Equivalent to `inj.eject()`. Provided for API symmetry.

---

### `Injection` Object Methods

The `Injection` class is move-only and ejects automatically on destruction (RAII).

| Method | Return Type | Description |
|---|---|---|
| `eject()` | `Result<void>` | Explicitly eject and invalidate. Idempotent. |
| `valid()` | `bool` | Is this injection handle still active? |
| `pid()` | `uint32_t` | Target process ID. |
| `method()` | `InjectMethod` | Which injection technique was used. |
| `tag()` | `std::string` | The tag string set at creation. |
| `operator bool()` | `bool` | Equivalent to `valid()`. |
| `handle()` | `InjHandle` | Escape hatch — internal handle for power users. |

---

### Extended Catalogue (24 techniques)

```cpp
#include <vh/inject/inject_unified.vh>
```

The unified API provides `vh::InjectMethodEx` (24 values) and `vh::inject_by_method(request)` — a single-call dispatcher to any technique. The first 4 values numerically match `vh::InjectMethod`.

**Technique groups:**

| Group | Techniques |
|---|---|
| **Core (4)** | LoadLibrary, ManualMap, ThreadHijack, ApcQueue |
| **Process-birth (4)** | EarlyBird APC, Herpaderping, Ghosting, Doppelgänging |
| **Remote-thread (4)** | NtCreateThreadEx, RtlCreateUserThread, Reflective, SetWindowsHookEx |
| **APC-modern (2)** | QueueApcEx2, Waiting-thread hijack |
| **Callback-hijack (3)** | KernelCallbackTable, Threadless callback, Module-stomp |
| **Window-message (2)** | PROP_PROPAGATE, Extra Window Memory |
| **Process-manip (3)** | Process Hollowing, PoolParty, NtMapViewOfSection |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🛡️ Part XII — Stealth Helpers (`vh::inject_stealth`)

```cpp
#include <vh/inject/inject_stealth.vh>
```

**Windows only.** These are the indirect-syscall helpers used internally by all injection techniques. They are exposed publicly so that users building custom injection flows or extending VanHooks can route their own process-manipulation calls through the same stealth layer.

All functions route through `vh::syscalls::stub_for()` in indirect mode — the `syscall` instruction executes at an ntdll gadget address, so kernel stack walks see a legitimate ntdll return address. Stubs are resolved once per process lifetime and cached.

**Namespace:** `vh::inject_stealth`

---

### `vh_open_process`

```cpp
HANDLE vh_open_process(DWORD pid,
                       ACCESS_MASK access = PROCESS_ALL_ACCESS) noexcept;
```

Open a process via `NtOpenProcess` (indirect syscall). Drop-in replacement for `OpenProcess()`.

---

### `vh_alloc_remote`

```cpp
void* vh_alloc_remote(HANDLE proc, void* preferred, SIZE_T size,
                      DWORD type = MEM_COMMIT | MEM_RESERVE,
                      DWORD protect = PAGE_READWRITE) noexcept;
```

Allocate memory in a remote process via `NtAllocateVirtualMemory` (indirect). Drop-in replacement for `VirtualAllocEx()`.

---

### `vh_write_remote`

```cpp
bool vh_write_remote(HANDLE proc, void* remote, const void* local,
                     SIZE_T size, SIZE_T* written = nullptr) noexcept;
```

Write to remote process memory via `NtWriteVirtualMemory` (indirect). Drop-in replacement for `WriteProcessMemory()`.

---

### `vh_read_remote`

```cpp
bool vh_read_remote(HANDLE proc, const void* remote, void* local,
                    SIZE_T size, SIZE_T* read_count = nullptr) noexcept;
```

Read from remote process memory via `NtReadVirtualMemory` (indirect). Drop-in replacement for `ReadProcessMemory()`.

---

### `vh_free_remote`

```cpp
bool vh_free_remote(HANDLE proc, void* base, SIZE_T size = 0,
                    DWORD type = MEM_RELEASE) noexcept;
```

Free remote memory via `NtFreeVirtualMemory` (indirect). Drop-in replacement for `VirtualFreeEx()`.

---

### `vh_protect_remote`

```cpp
bool vh_protect_remote(HANDLE proc, void* base, SIZE_T size,
                       DWORD new_prot, DWORD* old_prot) noexcept;
```

Change remote memory protection via `NtProtectVirtualMemory` (indirect). Drop-in replacement for `VirtualProtectEx()`.

---

### `vh_create_thread`

```cpp
HANDLE vh_create_thread(HANDLE proc, void* start, void* param = nullptr,
                        bool suspended = false) noexcept;
```

Create a remote thread via `NtCreateThreadEx` (indirect). Drop-in replacement for `CreateRemoteThread()`.

---

### `vh_open_thread`

```cpp
HANDLE vh_open_thread(DWORD tid, ACCESS_MASK access) noexcept;
```

Open a thread via `NtOpenThread` (indirect). Drop-in replacement for `OpenThread()`.

---

### `vh_close`

```cpp
void vh_close(HANDLE h) noexcept;
```

Close a handle via `NtClose` (indirect). Drop-in replacement for `CloseHandle()`. Safe to call with `nullptr` or `INVALID_HANDLE_VALUE`.

---

### `vh_find_thread`

```cpp
DWORD vh_find_thread(DWORD pid) noexcept;
```

Find the first thread in a process via `NtQuerySystemInformation` (indirect). Drop-in replacement for `CreateToolhelp32Snapshot` + `Thread32First`. Returns the thread ID, or 0 on failure.

---

### `vh_queue_apc`

```cpp
bool vh_queue_apc(HANDLE thread, void* apc_routine,
                  void* arg1 = nullptr, void* arg2 = nullptr,
                  void* arg3 = nullptr) noexcept;
```

Queue an APC to a thread via `NtQueueApcThread` (indirect).

---

### `vh_write_shellcode`

```cpp
struct RemoteAlloc {
    void*  base = nullptr;
    SIZE_T size = 0;
};

RemoteAlloc vh_write_shellcode(HANDLE proc,
                               std::span<const std::uint8_t> code) noexcept;
```

Atomic shellcode deployment: allocates `PAGE_READWRITE`, writes the code, then flips to `PAGE_EXECUTE_READ`. No `PAGE_EXECUTE_READWRITE` memory ever exists. Returns the remote allocation address and size. The caller is responsible for freeing via `vh_free_remote` after the shellcode has executed.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

### Quick Reference — Injection

```cpp
#include <vh/inject/inject.vh>
using namespace vh;

// Inject
auto inj = inject(pid, dll, { .method = InjectMethod::ManualMap });
auto inj = inject_from_memory(pid, pe, { .method = InjectMethod::ManualMap });

// Eject
inj.eject();   // or let RAII handle it

// Introspection
inj.valid()    inj.pid()    inj.method()    inj.tag()
```

### Quick Reference — Stealth Helpers

```cpp
#include <vh/inject/inject_stealth.vh>
using namespace vh::inject_stealth;

HANDLE p = vh_open_process(pid);
void*  m = vh_alloc_remote(p, nullptr, 4096);
bool   w = vh_write_remote(p, m, data, sz);
bool   r = vh_read_remote(p, m, buf, sz);
bool   f = vh_free_remote(p, m);
bool   v = vh_protect_remote(p, m, 4096, PAGE_EXECUTE_READ, &old);
HANDLE t = vh_create_thread(p, start);
HANDLE o = vh_open_thread(tid, access);
DWORD  d = vh_find_thread(pid);
bool   q = vh_queue_apc(thread, routine);
auto  sc = vh_write_shellcode(p, code_span);
vh_close(p);
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔒 Part XIII — Phase 10 Hardening

Phase 10 introduces 19 new modules covering core hardening, anti-cheat evasion on Windows and Linux, extended injection, and hypervisor-assisted hooks. All modules are optional — include only what you need.

---

### Core — Polymorphic Trampolines `<vh/core/polymorphic.vh>`

**Namespace:** `vh::poly`

Every generated trampoline is unique: randomised register selection, junk instruction insertion, and instruction-order shuffling. Defeats static signature scanning across processes.

#### `PolyConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `junk_density` | `uint8_t` | `3` | Number of junk instructions per block |
| `randomise_regs` | `bool` | `true` | Shuffle register selection |
| `shuffle_order` | `bool` | `true` | Randomise instruction ordering |
| `insert_nop_sled` | `bool` | `false` | Add NOP sled before each trampoline |
| `seed` | `uint32_t` | `0` | RNG seed (0 = random) |

#### `PolyTrampoline`

| Field | Type | Description |
|---|---|---|
| `code` | `void*` | Pointer to generated code |
| `code_size` | `size_t` | Size in bytes |
| `original` | `void*` | Pointer to call original function |
| `signature` | `uint64_t` | Unique hash of this trampoline instance |

#### Functions

| Signature | Description |
|---|---|
| `Result<PolyTrampoline> generate(void* target, void* detour, const PolyConfig& cfg = {})` | Generate a unique trampoline redirecting `target` to `detour` |
| `void destroy(PolyTrampoline& tramp)` | Free trampoline memory and invalidate the handle |
| `void reseed(uint32_t new_seed)` | Reset the global RNG seed for future generation |
| `size_t estimate_size(size_t stolen_bytes, const PolyConfig& cfg)` | Estimate buffer size needed for the trampoline |

```cpp
#include <vh/core/polymorphic.vh>

vh::poly::PolyConfig cfg{ .junk_density = 5, .seed = 0xDEAD };
auto result = vh::poly::generate(target_fn, my_detour, cfg);
if (result) {
    auto& tramp = *result;
    // tramp.original points to the real function
    vh::poly::destroy(tramp);
}
```

---

### Core — Encrypted Engine State `<vh/core/engine_crypt.vh>`

**Namespace:** `vh::crypt`

Hook metadata, trampoline addresses, and the internal hook list are held encrypted in memory. Decrypted on access, re-encrypted after. Defeats memory scanners that pattern-match on VanHooks data structures.

#### `CryptConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `encrypt_metadata` | `bool` | `true` | Encrypt hook metadata in memory |
| `encrypt_trampolines` | `bool` | `false` | Encrypt trampoline code pages (higher overhead) |
| `rotate_keys` | `bool` | `true` | Periodically rotate encryption keys |
| `rotation_interval_ms` | `uint32_t` | `5000` | Key rotation interval in ms |

#### Functions

| Signature | Description |
|---|---|
| `Status init(const CryptConfig& cfg = {})` | Initialise the encryption subsystem |
| `Status shutdown()` | Shut down and scrub all keys |
| `void encrypt_region(void* base, size_t size)` | Encrypt a memory region in place |
| `void decrypt_region(void* base, size_t size)` | Decrypt a memory region in place |
| `void rotate_key()` | Force an immediate key rotation |
| `bool is_active()` | Returns `true` if encryption is initialised |

#### `ScopedDecrypt`

RAII guard that decrypts a region on construction and re-encrypts on destruction.

```cpp
#include <vh/core/engine_crypt.vh>

vh::crypt::init({ .rotate_keys = true, .rotation_interval_ms = 3000 });

{
    vh::crypt::ScopedDecrypt lock(trampoline_ptr, trampoline_size);
    // ... read/modify decrypted memory ...
}  // re-encrypted here
```

---

### Core — Tamper Detection `<vh/core/tamper_detect.vh>`

**Namespace:** `vh::tamper`

Integrity canaries on trampoline pages and engine allocations. If an anti-cheat patches a trampoline or dumps engine memory, the system detects it and can scrub, relocate, or alert.

#### `TamperAction` enum

| Value | Description |
|---|---|
| `Alert` | Log/callback only |
| `Scrub` | Zero the tampered region |
| `Relocate` | Move the allocation to a new address |
| `Rehook` | Automatically reinstall the affected hook |
| `Silent` | Ignore the tamper event |

#### `TamperConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `enable_canaries` | `bool` | `true` | Place canary values around allocations |
| `enable_guard_pages` | `bool` | `true` | Guard pages that trap external reads |
| `enable_crc_check` | `bool` | `true` | CRC integrity checks on trampolines |
| `check_interval_ms` | `uint32_t` | `250` | Background check interval |
| `default_action` | `TamperAction` | `Rehook` | Default response to detected tampering |
| `on_tamper` | `TamperCallback` | `{}` | `void(void* address, TamperAction suggested)` |

#### Functions

| Signature | Description |
|---|---|
| `Status init(const TamperConfig& cfg = {})` | Start the tamper detection engine |
| `Status shutdown()` | Stop monitoring and release resources |
| `Status protect_region(void* base, size_t size)` | Add a memory region to monitoring |
| `Status unprotect_region(void* base, size_t size)` | Remove a region from monitoring |
| `Status place_canary(void* page, size_t page_size)` | Place an integrity canary on a page |
| `bool verify_canary(void* page)` | Check a single canary |
| `bool verify_all()` | Check all canaries at once |
| `Status enable_guard(void* base, size_t size)` | Arm guard pages on a region |
| `Status disable_guard(void* base, size_t size)` | Disarm guard pages |
| `uint32_t compute_crc(const void* base, size_t size)` | Compute CRC-32 of a region |
| `bool verify_crc(const void* base, size_t size, uint32_t expected)` | Verify a CRC against an expected value |
| `size_t tamper_count()` | Number of tamper events detected since init |

```cpp
#include <vh/core/tamper_detect.vh>

vh::tamper::init({
    .default_action = vh::tamper::TamperAction::Rehook,
    .on_tamper = [](void* addr, vh::tamper::TamperAction action) {
        log("Tamper detected at %p, action=%d", addr, (int)action);
    }
});
vh::tamper::protect_region(trampoline_page, 4096);
```

---

### Core — Automatic Re-hooking `<vh/core/auto_rehook.vh>`

**Namespace:** `vh::rehook`

If a hook is detected and removed by an anti-cheat, the engine transparently reinstalls from a cold backup — relocating to a different code cave each time. Combined with polymorphic trampolines, each reinstallation looks unique.

#### `RehookConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `check_interval_ms` | `uint32_t` | `100` | How often to verify hooks are intact |
| `max_reinstall_count` | `uint32_t` | `10` | Maximum reinstallation attempts per hook |
| `use_polymorphic` | `bool` | `true` | Generate a new unique trampoline on each reinstall |
| `relocate_trampoline` | `bool` | `true` | Move trampoline to a new address on reinstall |
| `silent` | `bool` | `true` | Suppress logging |

#### `WatchStatus`

| Field | Type | Description |
|---|---|---|
| `target` | `void*` | Watched function address |
| `hook_intact` | `bool` | `true` if the hook is currently installed |
| `reinstall_count` | `uint32_t` | Number of times the hook has been reinstalled |
| `last_check_ms` | `uint64_t` | Timestamp of last integrity check |

#### Functions

| Signature | Description |
|---|---|
| `Status init(const RehookConfig& cfg = {})` | Start the re-hook monitoring engine |
| `Status shutdown()` | Stop monitoring |
| `Status watch(void* target, void* detour, void** original_out, RehookCallback on_rehook = {})` | Watch a hook for removal and automatically reinstall |
| `Status unwatch(void* target)` | Stop watching a specific hook |
| `Status unwatch_all()` | Stop watching all hooks |
| `WatchStatus query(void* target)` | Query the status of a watched hook |
| `size_t watched_count()` | Number of hooks currently being watched |
| `size_t total_reinstalls()` | Total reinstallation events across all hooks |

```cpp
#include <vh/core/auto_rehook.vh>

vh::rehook::init({ .use_polymorphic = true });

OriginalFn original = nullptr;
vh::rehook::watch(target_fn, my_detour, reinterpret_cast<void**>(&original),
    [](void* target, uint32_t attempt) {
        log("Hook at %p reinstalled (attempt %u)", target, attempt);
    });
```

---

### Windows — Shadow Page Integrity `<vh/vigil/shadow_page.vh>`

**Namespace:** `vh::shadow` · **Platform:** Windows / Linux

Maps a second `SEC_IMAGE` view of a module so hash-scan checks read the original bytes while the executable view runs hooked code. On Linux uses a clean `mmap` from disk for the same effect.

#### `ShadowMapping`

| Field | Type | Description |
|---|---|---|
| `module_base` | `void*` | Base address of the original module |
| `shadow_base` | `void*` | Base address of the shadow mapping |
| `text_offset` | `size_t` | Offset to `.text` section |
| `text_size` | `size_t` | Size of `.text` section |
| `module_name` | `string_view` | Name of the mapped module |

#### Functions

| Signature | Description |
|---|---|
| `Result<ShadowMapping> create(string_view module_name)` | Create a shadow mapping by module name |
| `Result<ShadowMapping> create(void* module_base)` | Create a shadow mapping by base address |
| `Status destroy(ShadowMapping& mapping)` | Unmap the shadow and release resources |
| `bool verify_integrity(const ShadowMapping& mapping)` | Compare shadow against live `.text` |
| `Status redirect_reads(const ShadowMapping& mapping)` | Redirect integrity scans to the shadow |
| `Status restore_reads(const ShadowMapping& mapping)` | Undo the read redirection |

```cpp
#include <vh/vigil/shadow_page.vh>

auto mapping = vh::shadow::create("game.exe");
if (mapping) {
    vh::shadow::redirect_reads(*mapping);
    // integrity scanners now see the clean shadow
}
```

---

### Windows — CFG / XFG Bypass `<vh/vigil/cfg_bypass.vh>`

**Namespace:** `vh::cfg` · **Platform:** Windows 10+

Registers trampoline addresses as valid Control Flow Guard call targets so indirect calls through hooked functions pass CFG bitmap validation.

#### Functions

| Signature | Description |
|---|---|
| `bool is_cfg_enabled()` | Check if CFG is active for the current process |
| `bool is_xfg_enabled()` | Check if XFG (eXtended Flow Guard) is active |
| `Status register_valid_target(void* address)` | Register a single address as a valid call target |
| `Status register_valid_targets(void** addresses, size_t count)` | Register multiple addresses |
| `Status unregister_valid_target(void* address)` | Remove an address from the valid target list |
| `bool is_valid_target(void* address)` | Check if an address is registered as valid |

```cpp
#include <vh/vigil/cfg_bypass.vh>

if (vh::cfg::is_cfg_enabled()) {
    void* trampoline = /* your trampoline address */;
    vh::cfg::register_valid_target(trampoline);
}
```

---

### Windows — CIG / ACG Awareness `<vh/vigil/cig_aware.vh>`

**Namespace:** `vh::cig` · **Platform:** Windows 10+

Detects Code Integrity Guard and Arbitrary Code Guard policies. When CIG is active, dynamic code generation is blocked. The engine falls back to signed-code-reuse paths.

#### `Policy` enum

| Value | Description |
|---|---|
| `None` | No code integrity policy active |
| `CIG` | Code Integrity Guard only |
| `ACG` | Arbitrary Code Guard only |
| `CIG_and_ACG` | Both active |
| `CIG_Strict` | Strict-mode CIG |

#### `FallbackStrategy` enum

| Value | Description |
|---|---|
| `ModuleStomp` | Overwrite a signed module's code section |
| `RopChain` | Build a ROP chain instead of JIT code |
| `SignedCave` | Find a code cave inside a signed module |
| `Fail` | No viable strategy available |

#### Functions

| Signature | Description |
|---|---|
| `Policy query_policy()` | Return the active CIG/ACG policy |
| `bool is_cig_active()` | Check if CIG is enforced |
| `bool is_acg_active()` | Check if ACG is enforced |
| `bool is_dynamic_code_blocked()` | Check if JIT / dynamic code allocation is blocked |
| `FallbackStrategy recommended_strategy()` | Return the best hooking strategy given active policies |

```cpp
#include <vh/vigil/cig_aware.vh>

if (vh::cig::is_dynamic_code_blocked()) {
    auto strategy = vh::cig::recommended_strategy();
    // choose hook method based on strategy
}
```

---

### Windows — Instrumentation Callback `<vh/vigil/instrumentation_cb.vh>`

**Namespace:** `vh::instrumentation` · **Platform:** Windows 10+

Detects and neutralises `NtSetInformationProcess(ProcessInstrumentationCallback)`, a usermode telemetry vector used by EAC and other anti-cheats.

#### `CallbackInfo`

| Field | Type | Description |
|---|---|---|
| `callback_address` | `void*` | Address of the installed callback |
| `is_active` | `bool` | Whether a callback is currently installed |
| `version` | `uint64_t` | Callback version/revision |

#### Functions

| Signature | Description |
|---|---|
| `CallbackInfo query()` | Query the current instrumentation callback state |
| `Status neutralise()` | Clear the instrumentation callback pointer |
| `Status redirect(void* replacement_callback)` | Replace the callback with a no-op or custom handler |
| `Status restore()` | Restore the original callback |
| `bool is_monitored()` | Check if a callback is currently installed |

```cpp
#include <vh/vigil/instrumentation_cb.vh>

auto info = vh::instrumentation::query();
if (info.is_active) {
    vh::instrumentation::neutralise();
}
```

---

### Windows — Timing Normalisation `<vh/vigil/timing_normal.vh>`

**Namespace:** `vh::timing` · **Platform:** All

Inserts configurable jitter at hook call sites to match baseline timing profiles. Defeats ML-based detection that flags anomalous call-frequency patterns from hooked functions.

#### `TimingConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `min_jitter_ns` | `uint32_t` | `0` | Minimum jitter in nanoseconds |
| `max_jitter_ns` | `uint32_t` | `500` | Maximum jitter in nanoseconds |
| `match_baseline` | `bool` | `true` | Calibrate jitter to match the unhooked timing profile |
| `baseline_samples` | `uint32_t` | `100` | Number of samples for baseline calibration |

#### `TimingStats`

| Field | Type | Description |
|---|---|---|
| `total_calls` | `uint64_t` | Total hooked calls processed |
| `total_jitter_ns` | `uint64_t` | Cumulative jitter applied |
| `avg_jitter_ns` | `double` | Average jitter per call |

#### Functions

| Signature | Description |
|---|---|
| `Status init(const TimingConfig& cfg = {})` | Initialise timing normalisation |
| `Status shutdown()` | Stop timing normalisation |
| `void calibrate_baseline(void* target)` | Sample the unhooked function to build a timing profile |
| `void apply_jitter()` | Apply jitter based on the current config |
| `void apply_jitter_ns(uint32_t min_ns, uint32_t max_ns)` | Apply jitter with explicit bounds |
| `uint64_t last_jitter_ns()` | Return the jitter applied to the last call |
| `TimingStats stats()` | Return cumulative timing statistics |

```cpp
#include <vh/vigil/timing_normal.vh>

vh::timing::init({ .match_baseline = true });
vh::timing::calibrate_baseline(target_fn);

// Inside your detour:
vh::timing::apply_jitter();
return original_fn(args...);
```

---

### Windows — Stack Spoofing v2 `<vh/vigil/stack_spoof.vh>`

**Namespace:** `vh::stack_spoof` · **Platform:** Windows x64

Return-address spoofing for call-stack camouflage. Modern EDRs walk the user-mode call stack and flag frames from non-image-backed memory. This module spoofs return addresses with gadgets from legitimate modules.

#### `SpoofGuard`

RAII guard that replaces the current frame's return address with a gadget inside a legitimate module. Destructor restores the original. **Stack-local — do NOT heap-allocate or move across threads.**

#### `SyntheticFrame`

| Field | Type | Default | Description |
|---|---|---|---|
| `return_addr` | `void*` | `nullptr` | Points into a real module's `.text` |
| `rbp_value` | `void*` | `nullptr` | Synthetic frame pointer |
| `depth` | `uint8_t` | `3` | How many fake frames to fabricate |

#### `SyntheticGuard`

RAII guard that installs a full synthetic call chain of `depth` frames rooted in real modules. Up to 8 frames.

#### Functions

| Signature | Description |
|---|---|
| `void init()` | Scan loaded modules for usable JMP-register gadgets |
| `bool ready()` | Returns `true` after a successful `init()` |
| `void* gadget_addr()` | Get the address of a JMP RBX gadget inside ntdll's `.text` |
| `void* spoof_caller_ret(void* fake_ret)` | Spoof the return address; returns the original |
| `void restore_caller_ret(void* original_ret)` | Restore a previously spoofed return address |
| `SyntheticFrame build_synthetic_stack(uint8_t depth = 3)` | Build a believable multi-frame call stack |

```cpp
#include <vh/vigil/stack_spoof.vh>

vh::stack_spoof::init();

{
    vh::stack_spoof::SpoofGuard guard;
    NtAllocateVirtualMemory(...);  // stack walk sees ntdll frames
}

// Or full synthetic chain:
{
    vh::stack_spoof::SyntheticGuard synth(4);  // 4 fake frames
    SensitiveApi(...);
}
```

---

### Windows — ETW-TI Evasion v2 `<vh/vigil/etwti_blind.vh>`

**Namespace:** `vh::etwti` · **Platform:** Windows x64

Blinds the ETW Threat Intelligence provider — the kernel-level telemetry source that reports memory allocation, image loads, thread creation, and other sensitive operations to EDR drivers.

#### Functions

| Signature | Description |
|---|---|
| `bool suppress()` | Suppress ETW-TI (refcounted — each call needs a matching `restore`) |
| `bool restore()` | Restore ETW-TI provider registration |
| `bool is_suppressed()` | Query whether TI is currently suppressed |
| `bool patch_ti_provider()` | Persistently patch EtwEventWrite to drop TI events (idempotent) |
| `bool unpatch_ti_provider()` | Undo the persistent TI patch |
| `bool install_provider_filter()` | v2 — Hook EtwEventWrite with a selective filter that only drops TI-GUID events |
| `bool remove_provider_filter()` | Remove the v2 provider filter hook |

#### `SuppressGuard`

RAII guard that suppresses ETW-TI for its lifetime. Move-only.

```cpp
#include <vh/vigil/etwti_blind.vh>

{
    vh::etwti::SuppressGuard guard;
    // injection code here runs without TI telemetry
}  // TI restored automatically

// Or persistent:
vh::etwti::install_provider_filter();  // selective — only TI events dropped
```

---

### Linux — Direct Syscalls `<vh/vigil/linux_syscalls.vh>`

**Namespace:** `vh::linux_sys` · **Platform:** Linux x64

Direct syscall invocation via inline assembly, bypassing libc. Prevents `LD_PRELOAD` and GOT/PLT hooks from intercepting VanHooks' own calls.

#### Functions

| Signature | Description |
|---|---|
| `long raw_syscall(long nr, long a0..a5)` | Issue an arbitrary syscall by number |
| `long sys_mmap(void*, size_t, int, int, int, long)` | Direct `mmap` |
| `long sys_munmap(void*, size_t)` | Direct `munmap` |
| `long sys_mprotect(void*, size_t, int)` | Direct `mprotect` |
| `long sys_getpid()` | Direct `getpid` |
| `long sys_gettid()` | Direct `gettid` |
| `long sys_kill(int pid, int sig)` | Direct `kill` |
| `long sys_tgkill(int tgid, int tid, int sig)` | Direct `tgkill` |
| `long sys_open(const char*, int, int)` | Direct `open` |
| `long sys_close(int fd)` | Direct `close` |
| `long sys_read(int fd, void*, size_t)` | Direct `read` |
| `long sys_write(int fd, const void*, size_t)` | Direct `write` |
| `long sys_ptrace(int, int, void*, void*)` | Direct `ptrace` |
| `long sys_process_vm_readv(...)` | Direct `process_vm_readv` |
| `long sys_process_vm_writev(...)` | Direct `process_vm_writev` |

```cpp
#include <vh/vigil/linux_syscalls.vh>

void* mem = (void*)vh::linux_sys::sys_mmap(
    nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```

---

### Linux — Maps Scrubbing `<vh/vigil/maps_scrub.vh>`

**Namespace:** `vh::maps_scrub` · **Platform:** Linux

Hides VanHooks memory regions from `/proc/self/maps` by hooking `open`/`read` on the maps file and filtering entries for tracked regions.

#### Functions

| Signature | Description |
|---|---|
| `Status init()` | Initialise the maps filter |
| `Status shutdown()` | Remove the filter and clean up |
| `Status register_region(void* addr, size_t size)` | Track a region to hide |
| `Status unregister_region(void* addr)` | Stop hiding a region |
| `Status enable_filter()` | Activate the maps filter |
| `Status disable_filter()` | Deactivate without removing tracked regions |
| `bool is_active()` | Check if the filter is currently active |
| `size_t hidden_region_count()` | Number of regions currently hidden |

```cpp
#include <vh/vigil/maps_scrub.vh>

vh::maps_scrub::init();
vh::maps_scrub::register_region(trampoline_pool, pool_size);
vh::maps_scrub::enable_filter();
// /proc/self/maps no longer shows the trampoline pool
```

---

### Linux — ptrace Hardening `<vh/vigil/ptrace_harden.vh>`

**Namespace:** `vh::ptrace_harden` · **Platform:** Linux

Prevents debugger attachment and ptrace-based inspection. Self-traces to block external attachments, monitors `TracerPid`, and scans for breakpoints.

#### Functions

| Signature | Description |
|---|---|
| `Status init()` | Initialise ptrace hardening |
| `Status shutdown()` | Clean up |
| `bool is_traced()` | Check if the process is being traced |
| `Status self_trace()` | Call `PTRACE_TRACEME` to block external attachments |
| `Status enable_monitor()` | Start background monitoring of `TracerPid` |
| `Status disable_monitor()` | Stop background monitoring |
| `Status set_callback(DebugCallback cb)` | Set a callback: `void(int tracer_pid) noexcept` |
| `bool scan_breakpoints(void* addr, size_t size)` | Scan a region for INT3 / BRK instructions |

```cpp
#include <vh/vigil/ptrace_harden.vh>

vh::ptrace_harden::init();
vh::ptrace_harden::self_trace();
vh::ptrace_harden::enable_monitor();
vh::ptrace_harden::set_callback([](int pid) noexcept {
    // debugger detected — take evasive action
});
```

---

### Linux — link_map Unlinking `<vh/vigil/link_map_hide.vh>`

**Namespace:** `vh::link_map_hide` · **Platform:** Linux

Removes a loaded shared object from the dynamic linker's `link_map` chain so `dl_iterate_phdr`, `dlsym`, and `/proc/self/maps` enumerations cannot find it.

#### Functions

| Signature | Description |
|---|---|
| `Status hide_module(const char* module_name)` | Unlink a module from the `link_map` |
| `Status unhide_module(const char* module_name)` | Re-link a previously hidden module |
| `bool is_hidden(const char* module_name)` | Check if a module is currently hidden |
| `size_t hidden_count()` | Number of currently hidden modules |
| `Status hide_self()` | Hide the VanHooks library itself |

```cpp
#include <vh/vigil/link_map_hide.vh>

vh::link_map_hide::hide_self();  // VanHooks disappears from link_map
vh::link_map_hide::hide_module("libpayload.so");
```

---

### Linux — seccomp Awareness `<vh/vigil/seccomp_aware.vh>`

**Namespace:** `vh::seccomp_aware` · **Platform:** Linux

Detects active seccomp-bpf filters and determines which syscalls are permitted before attempting direct invocation. Falls back to libc wrappers when seccomp blocks raw syscalls.

#### `SeccompMode` enum

| Value | Description |
|---|---|
| `Disabled` | No seccomp active |
| `Strict` | Strict mode (only `read`, `write`, `exit`, `sigreturn` allowed) |
| `Filter` | BPF filter mode (custom whitelist) |

#### Functions

| Signature | Description |
|---|---|
| `SeccompMode query_mode()` | Return the current seccomp mode |
| `bool is_seccomp_active()` | Check if any seccomp policy is active |
| `bool is_syscall_allowed(long syscall_nr)` | Test if a specific syscall number is permitted |
| `bool can_use_direct_syscalls()` | Check if direct syscall invocation is safe |
| `bool can_use_ptrace()` | Check if `ptrace` is permitted |
| `bool can_use_process_vm()` | Check if `process_vm_readv`/`writev` is permitted |

```cpp
#include <vh/vigil/seccomp_aware.vh>

if (vh::seccomp_aware::can_use_direct_syscalls()) {
    // safe to use vh::linux_sys:: functions
} else {
    // fall back to libc wrappers
}
```

---

### Linux — ELF Integrity `<vh/vigil/elf_integrity.vh>`

**Namespace:** `vh::elf_integrity` · **Platform:** Linux

Maintains a CRC snapshot of a module's `.text` section from the on-disk ELF binary. Background thread periodically verifies the in-memory `.text` matches (minus known hook patches), detecting external tampering.

#### `IntegrityConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `check_interval_ms` | `uint32_t` | `1000` | Background check interval |
| `auto_repair` | `bool` | `false` | Restore tampered bytes from disk automatically |
| `alert_on_tamper` | `bool` | `true` | Invoke callback on tamper detection |

#### Functions

| Signature | Description |
|---|---|
| `Status init(const IntegrityConfig& cfg = {})` | Start the integrity monitor |
| `Status shutdown()` | Stop monitoring |
| `Status watch_module(void* module_base)` | Watch a module by base address |
| `Status watch_module(const char* module_name)` | Watch a module by name |
| `Status unwatch_module(void* module_base)` | Stop watching a module |
| `Status register_known_patch(void* addr, size_t size)` | Whitelist a known hook patch |
| `Status unregister_known_patch(void* addr)` | Remove a whitelisted patch |
| `Status set_callback(TamperCallback cb)` | `void(void* module_base, size_t offset, size_t size) noexcept` |
| `bool verify_now(void* module_base)` | Immediate one-shot integrity check |
| `uint32_t tamper_count()` | Number of tamper events detected |

```cpp
#include <vh/vigil/elf_integrity.vh>

vh::elf_integrity::init({ .auto_repair = true });
vh::elf_integrity::watch_module("libgame.so");
vh::elf_integrity::register_known_patch(my_hook_addr, 14);  // our hook
```

---

### Injection — Thread Pool `<vh/inject/inject_tp.vh>`

**Namespace:** `vh::inject_tp` · **Platform:** Windows

Injects code by submitting a `TP_WORK` callback to the target process's default thread pool. The callback executes in a system-managed worker thread, avoiding `CreateRemoteThread` which is heavily monitored.

#### `TpConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `process_id` | `uint32_t` | `0` | Target process ID |
| `shellcode` | `void*` | `nullptr` | Pointer to shellcode buffer |
| `shellcode_size` | `size_t` | `0` | Size of shellcode in bytes |
| `parameter` | `void*` | `nullptr` | Parameter passed to the shellcode |
| `wait_complete` | `bool` | `false` | Block until the work item completes |
| `timeout_ms` | `uint32_t` | `5000` | Timeout when `wait_complete` is `true` |

#### Functions

| Signature | Description |
|---|---|
| `Result<void*> inject(const TpConfig& cfg)` | Inject shellcode via thread pool; returns the remote allocation address |

```cpp
#include <vh/inject/inject_tp.vh>

vh::inject_tp::TpConfig cfg{
    .process_id     = target_pid,
    .shellcode      = sc_buf,
    .shellcode_size = sc_size,
    .wait_complete  = true,
};
auto result = vh::inject_tp::inject(cfg);
```

---

### Injection — process_vm_writev `<vh/inject/inject_vm.vh>`

**Namespace:** `vh::inject_vm` · **Platform:** Linux

Uses `process_vm_writev` to write shellcode directly into a remote process without ptrace. Requires same UID or `CAP_SYS_PTRACE`.

#### `VmConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `target_pid` | `int` | `0` | Target process ID |
| `shellcode` | `void*` | `nullptr` | Pointer to shellcode |
| `shellcode_size` | `size_t` | `0` | Shellcode size |
| `use_direct_syscalls` | `bool` | `true` | Use `vh::linux_sys` instead of libc |

#### Functions

| Signature | Description |
|---|---|
| `Result<void*> inject(const VmConfig& cfg)` | Inject shellcode via `process_vm_writev` |
| `Result<void*> write_memory(int pid, void* remote, const void* local, size_t size)` | Write arbitrary data to a remote process |
| `Result<void*> allocate_remote(int pid, size_t size, int prot)` | Allocate memory in the remote process |

```cpp
#include <vh/inject/inject_vm.vh>

vh::inject_vm::VmConfig cfg{
    .target_pid         = pid,
    .shellcode          = sc_buf,
    .shellcode_size     = sc_size,
    .use_direct_syscalls = true,
};
auto result = vh::inject_vm::inject(cfg);
```

---

### Hooks — EPT / Hypervisor-Assisted `<vh/hooks/ept_hook.vh>`

**Namespace:** `vh::ept` · **Platform:** Windows / Linux (requires compatible hypervisor driver)

Splits a page's execute and read permissions at the EPT (Extended Page Table) level. Read/write accesses see the original bytes; execute accesses see the hooked bytes. Completely invisible to usermode memory scanners.

#### `EptConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `auto_detect_hypervisor` | `bool` | `true` | Probe for compatible hypervisor driver |
| `max_split_pages` | `uint32_t` | `256` | Maximum number of split pages |

#### `EptHook`

| Field | Type | Description |
|---|---|---|
| `target_page` | `void*` | Page containing the hook target |
| `hooked_page` | `void*` | Copy with patched code (execute view) |
| `original_page` | `void*` | Copy with original code (read view) |
| `page_pfn` | `uint64_t` | Physical frame number |
| `active` | `bool` | Whether the hook is currently active |

#### Functions

| Signature | Description |
|---|---|
| `Status init(const EptConfig& cfg = {})` | Connect to the hypervisor driver |
| `Status shutdown()` | Remove all EPT hooks and disconnect |
| `bool is_available()` | Check if a compatible hypervisor is loaded |
| `Result<EptHook> install(void* target, const void* patch, size_t patch_size)` | Install an EPT-split hook |
| `Status remove(EptHook& hook)` | Remove an EPT hook |
| `Status enable(EptHook& hook)` | Activate an EPT hook |
| `Status disable(EptHook& hook)` | Deactivate without removing |
| `size_t active_hook_count()` | Number of active EPT hooks |
| `bool verify_split(const EptHook& hook)` | Verify the EPT split is intact |

```cpp
#include <vh/hooks/ept_hook.vh>

vh::ept::init();
if (vh::ept::is_available()) {
    uint8_t patch[] = { 0xE9, /* ... */ };
    auto hook = vh::ept::install(target_addr, patch, sizeof(patch));
    if (hook) {
        // memory scanners see the original bytes
        // CPU executes the patched code
    }
}
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📤 Part XIV — Shared Library ABI

**Header:** `<vh/export.vh>`

All public API functions and key classes are annotated with `VH_API`. This macro controls symbol visibility when VanHooks is built as a shared library (`.dll`/`.so`/`.dylib`).

### Macros

| Macro | Context | Expansion |
|---|---|---|
| `VH_API` | Static build (default SDK) | *(empty)* |
| `VH_API` | Shared build, consuming | `__declspec(dllimport)` (MSVC) / `visibility("default")` (GCC/Clang) |
| `VH_API` | Shared build, building the library | `__declspec(dllexport)` (MSVC) / `visibility("default")` (GCC/Clang) |

### Compile definitions (set by CMake)

| Definition | When |
|---|---|
| `VH_SHARED` | Building or consuming a shared VanHooks library |
| `VH_EXPORTS` | Building the shared library itself (not set for consumers) |

### Usage

The precompiled `.lib` files in the SDK are **static libraries**. `VH_API` resolves to nothing — no import/export annotation is needed and symbols link directly.

Shared library builds require the VanHooks source license. When building shared (`-DVH_BUILD_SHARED=ON`), CMake sets `VH_SHARED` and `VH_EXPORTS` automatically, applies `-fvisibility=hidden` on GCC/Clang, and sets `SOVERSION 0`.

```cpp
#include <vh/export.vh>

// All public API functions use VH_API:
VH_API Result<PolyTrampoline> generate(void* target, void* detour,
                                       const PolyConfig& cfg = {}) noexcept;
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚡ Part XV — Hook Engine v2

Phase 21 adds advanced hook primitives to `vanhooks::Engine` and `vh::Hook`.

### Conditional hooks

```cpp
Result<HookHandle> Engine::hook_conditional(
    void* target, void* detour, void** original_out = nullptr,
    ConditionalOptions opts = {});
```

Installs a trampoline hook that fires only when `opts.condition(target, opts.user_data)` returns `true`. The `ConditionFn` signature is `bool (*)(void* target, void* user_data) noexcept`.

**Options** (`ConditionalOptions`):

| Field | Type | Default | Description |
|---|---|---|---|
| `condition` | `ConditionFn` | — | Predicate called before each detour invocation |
| `user_data` | `void*` | `nullptr` | Passed to `condition()` |
| `priority` | `int32_t` | `0` | Hook ordering (higher fires first) |
| `thread_safe` | `bool` | `true` | Suspend threads during patch |
| `stats` | `bool` | `false` | Enable per-hook statistics |
| `tag` | `std::string` | `""` | Human-readable label |

**Errors**: `InvalidArgument` (null target/detour/condition), plus all trampoline errors.

---

### Lazy hooks

```cpp
Result<HookHandle> Engine::hook_lazy(
    void* target, void* detour, void** original_out = nullptr,
    LazyOptions opts = {});
```

Defers trampoline installation until the target function is first called. An INT3/SoftBp at the target captures the first hit, installs the real trampoline, removes the breakpoint, and replays the call.

**Errors**: `InvalidArgument`, plus trampoline errors on resolution.

---

### Function-exit hook

```cpp
Result<HookHandle> Engine::hook_exit(
    void* target, ReturnCallback callback,
    ExitHookOptions opts = {});
```

Scans the function body for RET/RETN instructions (up to `opts.max_scan_bytes` bytes) and patches every return path so the callback fires on function exit. Uses `disasm::Disassembler` for the control-flow scan.

**Errors**: `InvalidArgument`, `ExitScanFailed` (no RET found in scan range).

---

### Atomic detour swap

```cpp
Status Engine::swap_detour(HookHandle handle,
                           void* new_detour,
                           void** old_detour_out = nullptr);

// Also available on vh::Hook:
Status Hook::swap_detour(void* new_detour, void** old_detour_out = nullptr);
```

Replaces a hook's detour function in-place under a `ThreadFence`. The trampoline is rebuilt with the new target; the caller never sees an unhook window. Supported for `Trampoline`, `CallSite`, and `ThreadLocal` hook kinds.

**Errors**: `InvalidArgument`, `HookNotFound`, `SwapNotSupported` (unsupported hook kind).

---

### Hook priority

```cpp
Status Engine::set_priority(HookHandle handle, int32_t priority);

// Also on vh::Hook:
Status Hook::set_priority(int32_t p);
int32_t Hook::priority() const noexcept;
```

Sets numeric priority for ordering multiple hooks on the same target. Higher priority hooks fire first in the chain. Readable via `HookDesc::priority`.

---

### Per-hook statistics

```cpp
std::optional<HookStatsSnapshot> Engine::stats(HookHandle handle) const;
Status Engine::enable_stats(HookHandle handle);
Status Engine::disable_stats(HookHandle handle);
Status Engine::reset_stats(HookHandle handle);
```

`HookStatsSnapshot` fields:

| Field | Type | Description |
|---|---|---|
| `call_count` | `uint64_t` | Total invocations |
| `total_duration_ns` | `uint64_t` | Cumulative wall time |
| `average_duration_ns` | `uint64_t` | `total / count` |
| `max_duration_ns` | `uint64_t` | Worst-case latency |
| `last_call_timestamp` | `int64_t` | TSC of most recent call |

Statistics are only collected when installed with `stats = true` or after `enable_stats()`.

---

### Thread-targeted hooks (expanded)

```cpp
void Engine::thread_local_enable_set (HookHandle h, std::span<const uint32_t> thread_ids);
void Engine::thread_local_disable_set(HookHandle h, std::span<const uint32_t> thread_ids);
void Engine::thread_local_disable_all(HookHandle h) noexcept;
```

Enable or disable a thread-local hook for a set of thread IDs at once. Complements the existing single-thread `thread_local_enable()` / `thread_local_disable()`.

---

### Type-safe hooks

```cpp
template<typename Sig>
Result<HookHandle> Engine::hook_typed(
    Sig target, Sig detour, Sig* original_out = nullptr,
    TrampolineOptions opts = {});
```

Compile-time signature match: `static_assert` verifies `Sig` is a function pointer type, preventing silent calling-convention mismatches. Delegates to `hook_trampoline`.

---

### ReturnContext duration tracking

`ReturnContext` now includes TSC-based duration fields populated by the return-hook machinery:

**x64 / ARM64:**
| Field | Type | Description |
|---|---|---|
| `entry_tsc` | `uint64_t` | RDTSC at function entry |
| `duration_ns` | `uint64_t` | Wall time in nanoseconds |

**x86:**
| Field | Type | Description |
|---|---|---|
| `entry_tsc_lo` / `entry_tsc_hi` | `uint32_t` | RDTSC split (low / high) |
| `duration_ns_lo` / `duration_ns_hi` | `uint32_t` | Duration split (low / high) |

---

### Error codes (Phase 21)

| Code | Value | Description |
|---|---|---|
| `ConditionNotMet` | 1000 | Condition predicate returned false |
| `LazyNotResolved` | 1001 | Lazy hook not yet resolved |
| `SwapNotSupported` | 1002 | Hook kind does not support detour swap |
| `PriorityConflict` | 1003 | Priority collision on same target |
| `ExitScanFailed` | 1004 | No RET/RETN found in scan range |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🌍 Part XVI — Cross-Platform Hook Parity

Phase 22 extends hook coverage to macOS and Linux-specific mechanisms. All functions return `Error::Unsupported` on platforms where they are not applicable.

### macOS dyld interpose

```cpp
Result<HookHandle> Engine::hook_dyld_interpose(void* detour, DyldInterposeOptions opts);
```

Registers a DYLD_INSERT_LIBRARIES-style interposition at runtime. Resolves the original symbol via `dlsym(RTLD_DEFAULT, ...)` and patches GOT entries.

**Options** (`DyldInterposeOptions`):

| Field | Type | Description |
|---|---|---|
| `original_symbol` | `std::string` | Symbol name to interpose (e.g. `"malloc"`) |
| `tag` | `std::string` | Human-readable label |

**Errors**: `InvalidArgument`, `SymbolNotFound`, `DyldInterposeFailed`.

---

### macOS Mach-O import hook

```cpp
Result<HookHandle> Engine::hook_macho_import(void* detour, MachOImportOptions opts);
```

Patches lazy/non-lazy symbol pointers in Mach-O `__DATA` segments.

**Options** (`MachOImportOptions`):

| Field | Type | Description |
|---|---|---|
| `library_name` | `std::string` | Target library (e.g. `"libSystem.B.dylib"`) |
| `symbol_name` | `std::string` | Symbol to redirect |
| `tag` | `std::string` | Human-readable label |

**Errors**: `InvalidArgument`, `ModuleNotFound`, `MachOImportNotFound`.

---

### Hardware breakpoint hooks (Linux / macOS)

```cpp
Result<HookHandle> Engine::hook_hwbp_linux(void* target, MidCallback callback,
                                            HwBpOptions opts = {});

Result<HookHandle> Engine::hook_hwbp_macos(void* target, MidCallback callback,
                                            HwBpOptions opts = {});
```

Platform-specific hardware breakpoint hooks. Currently delegate to the SoftBp fallback mechanism; native DR register access via `ptrace` (Linux) and `thread_set_state` (macOS) is reserved for a future revision.

---

### ARM64 veneer stubs

`VeneerOptions` struct is defined for B/BL range extension via ADR+LDR veneer stubs:

| Field | Type | Default | Description |
|---|---|---|---|
| `prefer_adrp_ldr` | `bool` | `true` | Use ADRP+LDR pair (larger range) vs ADR+BR |
| `tag` | `std::string` | `""` | Human-readable label |

---

### Error codes (Phase 22)

| Code | Value | Description |
|---|---|---|
| `DyldInterposeFailed` | 1100 | dyld interpose registration failed |
| `MachOImportNotFound` | 1101 | Symbol not found in Mach-O imports |
| `PtraceSetFailed` | 1102 | ptrace DR register write failed |
| `MachThreadSetFailed` | 1103 | thread_set_state failed |
| `VeneerAllocFailed` | 1104 | Veneer stub allocation failed |
| `RiscVUnsupported` | 1105 | RISC-V not yet implemented |

### Configuration structs (vh::config)

Phase 21/22 add these to `vh::config::`:

| Struct | Phase | Description |
|---|---|---|
| `Conditional` | 21 | Predicate-gated hook options |
| `Lazy` | 21 | Deferred hook options |
| `ExitHook` | 21 | Multi-ret exit hook options |
| `DyldInterpose` | 22 | macOS dyld interpose options |
| `MachOImport` | 22 | macOS Mach-O import options |
| `Veneer` | 22 | ARM64 veneer stub options |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 💉 Part XVII — Injection Engine v2

Phase 23 expands the injection catalogue from 24 to 33 techniques, adds cross-platform injection, a shellcode generator, and an injection recommendation engine.

---

### inject_recommend

```cpp
std::vector<InjectRecommendResult> Engine::inject_recommend(
    uint32_t pid,
    InjectPlatform platform = InjectPlatform::Auto);
```

Surveys the target process and returns a ranked list of recommended injection techniques. Each result contains a stealth score, reliability score, and rationale.

**Return type:** `InjectRecommendResult`

| Field | Type | Description |
|---|---|---|
| `method_id` | `uint32_t` | `InjectMethodEx` numeric value |
| `technique_name` | `std::string` | Human-readable name |
| `stealth_score` | `int32_t` | 0–100; higher = less detectable |
| `reliability_score` | `int32_t` | 0–100; higher = more reliable |
| `rationale` | `std::string` | Why this technique ranks here |

**InjectPlatform enum:**

| Value | Meaning |
|---|---|
| `Auto` | Detect from current platform |
| `WindowsX64` | Windows x86-64 techniques |
| `WindowsX86` | Windows x86 techniques |
| `WindowsARM64` | Windows ARM64 techniques |
| `LinuxX64` | Linux x86-64 techniques |
| `LinuxARM64` | Linux ARM64 techniques |
| `MacosX64` | macOS x86-64 techniques |
| `MacosARM64` | macOS ARM64 techniques |
| `Android` | Android techniques |

---

### shellcode_generate

```cpp
Result<std::vector<uint8_t>> Engine::shellcode_generate(
    std::span<const uint8_t> code,
    ShellcodeGenOptions opts = {});
```

Generates position-independent shellcode from a raw code buffer. Supports null-byte elimination via XOR encoding with an auto-generated decoder stub.

**ShellcodeGenOptions:**

| Field | Type | Default | Description |
|---|---|---|---|
| `arch` | `ShellcodeArch` | `X64` | Target architecture (`X86`, `X64`, `ARM64`) |
| `null_free` | `bool` | `false` | Eliminate null bytes via XOR encoding |
| `max_size` | `size_t` | `65536` | Maximum output size; returns `ShellcodeGenFailed` if exceeded |

**Errors:** `InvalidArgument` (empty input), `ShellcodeGenFailed` (no valid XOR key or size exceeded).

---

### Linux injection functions

All return `Result<inject_ex::RemoteHandle>`. On non-Linux platforms they return `Error::Unsupported`.

#### inject_ptrace

```cpp
vh::Result<RemoteHandle> inject_ex::inject_ptrace(
    uint32_t pid, std::span<const uint8_t> shellcode);
```

ptrace-attach + PTRACE_POKETEXT shellcode injection. Writes a dlopen shellcode stub into the target's instruction pointer and single-steps it. Linux x86-64 only.

#### inject_process_vm_writev

```cpp
vh::Result<RemoteHandle> inject_ex::inject_process_vm_writev(
    uint32_t pid, std::span<const uint8_t> shellcode);
```

Cross-process write without ptrace-attach. Requires `CAP_SYS_PTRACE` or same-user non-SUID target.

#### inject_ld_preload

```cpp
vh::Result<RemoteHandle> inject_ex::inject_ld_preload(
    std::wstring_view target_exe, std::string_view so_path);
```

Spawns the target with `LD_PRELOAD` set. Only works at process creation time.

#### inject_proc_mem

```cpp
vh::Result<RemoteHandle> inject_ex::inject_proc_mem(
    uint32_t pid, std::string_view so_path);
```

Injects dlopen shellcode by writing directly to `/proc/<pid>/mem`. No ptrace needed on permissive kernel configs.

---

### macOS injection functions

#### inject_task_for_pid

```cpp
vh::Result<RemoteHandle> inject_ex::inject_task_for_pid(
    uint32_t pid, std::span<const uint8_t> shellcode);
```

`task_for_pid` + `mach_vm_write` + `thread_create_running`. Requires `com.apple.security.cs.debugger` entitlement or SIP disabled.

#### inject_dyld_insert

```cpp
vh::Result<RemoteHandle> inject_ex::inject_dyld_insert(
    std::wstring_view target_exe, std::string_view dylib_path);
```

Spawns the target with `DYLD_INSERT_LIBRARIES` set. macOS only.

---

### Android injection

#### inject_android_ptrace

```cpp
vh::Result<RemoteHandle> inject_ex::inject_android_ptrace(
    uint32_t pid, std::string_view so_path);
```

ptrace + dlopen via linker namespace. Requires root or debuggable target. SELinux context matters.

---

### Enhanced injection (Windows)

#### inject_reflective_v2

```cpp
vh::Result<RemoteHandle> inject_ex::inject_reflective_v2(
    uint32_t pid, std::span<const uint8_t> pe_bytes,
    vanhooks::ReflectiveV2Options opts = {});
```

Enhanced reflective DLL injection with TLS callback support, exception directory registration, and delay-import resolution.

**ReflectiveV2Options:**

| Field | Type | Default | Description |
|---|---|---|---|
| `resolve_tls` | `bool` | `true` | Process TLS callbacks |
| `resolve_exceptions` | `bool` | `true` | Register exception tables |
| `resolve_delay_imports` | `bool` | `true` | Resolve delay-loaded DLLs |

#### inject_manual_map_v2

```cpp
vh::Result<RemoteHandle> inject_ex::inject_manual_map_v2(
    uint32_t pid, std::span<const uint8_t> pe_bytes,
    vanhooks::ManualMapV2Options opts = {});
```

Full PE loader v2: SEH exception tables, TLS callbacks, static CRT initializers, delay-import resolution, and API set redirection.

**ManualMapV2Options:**

| Field | Type | Default | Description |
|---|---|---|---|
| `resolve_seh` | `bool` | `true` | Register structured exception handlers |
| `resolve_tls` | `bool` | `true` | Process TLS callbacks |
| `run_crt_init` | `bool` | `true` | Execute static CRT initializers |
| `resolve_delay_imports` | `bool` | `true` | Resolve delay-loaded DLLs |
| `resolve_api_sets` | `bool` | `true` | Follow ApiSetSchema redirection |

---

### Unified dispatcher update

`InjectMethodEx` now has 33 values (0–32). Phase 23 adds:

| Value | Name | Platform |
|---|---|---|
| 24 | `Ptrace` | Linux |
| 25 | `ProcessVmWritev` | Linux |
| 26 | `LdPreload` | Linux |
| 27 | `ProcMem` | Linux |
| 28 | `TaskForPid` | macOS |
| 29 | `DyldInsert` | macOS |
| 30 | `AndroidPtrace` | Android |
| 31 | `ReflectiveV2` | Windows |
| 32 | `ManualMapV2` | Windows |

`InjectRequest` gains a `so_path` field (`std::string_view`) for POSIX shared-object paths.

---

### Error codes (Phase 23)

| Code | Value | Description |
|---|---|---|
| `InjectRecommendFailed` | 1200 | Recommendation engine failure |
| `ShellcodeGenFailed` | 1201 | Shellcode generation failed |
| `PtraceFailed` | 1202 | ptrace attach/write failed |
| `ProcessVmWriteFailed` | 1203 | process_vm_writev failed |
| `TaskForPidFailed` | 1204 | task_for_pid denied |
| `ManualMapV2Failed` | 1205 | PE loader v2 failure |
| `ReflectiveV2Failed` | 1206 | Reflective v2 failure |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚡ Part XVIII — Advanced Hook Techniques

Phase 24 adds five new hook primitives for specialised use cases: relay hooks, copy-on-write hooks, signal-based hooks, exception-port hooks, and JIT hooks.

---

### hook_relay

```cpp
Result<HookHandle> Engine::hook_relay(
    void* target, void* detour, void** original_out,
    RelayOptions opts = {});
```

Installs a hook using a shared trampoline pool with direct jmp relay. Saves one indirection per call compared to standard trampoline hooks — useful for performance-critical hot paths.

**RelayOptions:**

| Field | Type | Default | Description |
|---|---|---|---|
| `pool_size` | `size_t` | `64` | Relay pool capacity |
| `thread_safe` | `bool` | `true` | Suspend threads during patch |
| `tag` | `std::string` | `""` | Human-readable label |

---

### hook_cow

```cpp
Result<HookHandle> Engine::hook_cow(
    void* target, void* detour, void** original_out,
    CowHookOptions opts = {});
```

Creates a private copy-on-write mapping of the target's code page, patches only the private copy. The original shared mapping is untouched, making the hook invisible to same-process integrity scans that read the original pages.

**Platforms:** Windows (VirtualAlloc + remap), Linux (mmap MAP_PRIVATE).

**CowHookOptions:**

| Field | Type | Default | Description |
|---|---|---|---|
| `thread_safe` | `bool` | `true` | Suspend threads during patch |
| `tag` | `std::string` | `""` | Human-readable label |

---

### hook_signal

```cpp
Result<HookHandle> Engine::hook_signal(
    void* target, MidCallback callback,
    SignalHookOptions opts = {});
```

Linux-only signal-based hook. Installs a SIGTRAP/SIGILL handler that dispatches to the user callback — the Linux equivalent of Windows VEH hooking.

**SignalHookOptions:**

| Field | Type | Default | Description |
|---|---|---|---|
| `signal_num` | `int` | `5` (SIGTRAP) | Signal to intercept |
| `tag` | `std::string` | `""` | Human-readable label |

Returns `Error::Unsupported` on non-Linux platforms.

---

### hook_exception_port

```cpp
Result<HookHandle> Engine::hook_exception_port(
    void* target, MidCallback callback,
    ExceptionPortOptions opts = {});
```

macOS-only Mach exception port hook. Registers a task-level exception port that catches `EXC_BREAKPOINT` — breakpoint-free hooking equivalent to VEH on Windows.

**ExceptionPortOptions:**

| Field | Type | Default | Description |
|---|---|---|---|
| `port_type` | `uint32_t` | `0` | Exception port type (0 = task-level) |
| `tag` | `std::string` | `""` | Human-readable label |

Returns `Error::Unsupported` on non-macOS platforms.

---

### hook_jit

```cpp
Result<HookHandle> Engine::hook_jit(
    void* target, void* detour, void** original_out,
    JitHookOptions opts = {});
```

Hooks dynamically generated code (V8, LuaJIT, .NET JIT). Installs a standard trampoline on the JIT'd code and optionally monitors for JIT recompilation to auto-repatch.

**JitHookOptions:**

| Field | Type | Default | Description |
|---|---|---|---|
| `monitor_interval_ms` | `size_t` | `100` | Polling interval for JIT recompile detection |
| `auto_repatch` | `bool` | `true` | Re-apply hook when JIT recompiles the target |
| `tag` | `std::string` | `""` | Human-readable label |

---

### Error codes (Phase 24)

| Code | Value | Description |
|---|---|---|
| `RelayPoolExhausted` | 1300 | Relay trampoline pool full |
| `CowRemapFailed` | 1301 | CoW page remap failed |
| `SignalInstallFailed` | 1302 | Signal handler registration failed |
| `ExceptionPortFailed` | 1303 | Mach exception port setup failed |
| `JitMonitorFailed` | 1304 | JIT code-cache monitor thread failed |
| `IdtPatchFailed` | 1305 | IDT entry patch failed (ring-0) |
| `MsrWriteFailed` | 1306 | MSR write failed (ring-0) |

---

### Configuration structs (vh::config) — Phase 24

| Struct | Description |
|---|---|
| `Relay` | Shared trampoline pool options |
| `Cow` | Copy-on-write hook options |
| `Signal` | Signal-based hook options (Linux) |
| `Jit` | JIT hook monitoring options |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔬 Part XIX — Analysis Subsystem v2

Phase 25 extends the analysis pipeline with cross-platform binary format parsers (ELF, Mach-O), control flow graph construction, binary diffing, advanced pattern scanning, string extraction, RTTI recovery, and function boundary detection.

---

### ELF parser

Parse in-memory ELF images (32-bit and 64-bit) without platform-specific headers. All four methods accept a raw ELF image as `std::span<const uint8_t>`.

| Method | Return | Description |
|---|---|---|
| `elf_sections(elf_image)` | `Result<std::vector<ElfSection>>` | Parse all section headers |
| `elf_symbols(elf_image)` | `Result<std::vector<ElfSymbol>>` | Parse symbols from `SHT_SYMTAB` and `SHT_DYNSYM` |
| `elf_dynamic(elf_image)` | `Result<std::vector<ElfDynEntry>>` | Parse the `SHT_DYNAMIC` section |
| `elf_relocations(elf_image)` | `Result<std::vector<ElfRelocation>>` | Parse `SHT_RELA` and `SHT_REL` entries |

#### ELF types

```cpp
struct ElfSection {
    std::string name;
    uint32_t    type;         // SHT_PROGBITS, SHT_SYMTAB, …
    uint64_t    flags;        // SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, …
    uint64_t    address;
    uint64_t    offset;
    uint64_t    size;
    uint32_t    link;
    uint32_t    info;
    uint64_t    addralign;
    uint64_t    entsize;
};

struct ElfSymbol {
    std::string  name;
    uint64_t     value;
    uint64_t     size;
    uint8_t      bind;         // STB_LOCAL / STB_GLOBAL / STB_WEAK
    uint8_t      type;         // STT_FUNC / STT_OBJECT / …
    uint16_t     section_idx;
};

struct ElfDynEntry {
    int64_t  tag;              // DT_NEEDED, DT_STRTAB, …
    uint64_t value;
};

struct ElfRelocation {
    uint64_t offset;
    uint32_t type;
    uint32_t sym_idx;
    int64_t  addend;
};
```

#### Example — list ELF exported functions

```cpp
auto img = load_file("target.so");
auto syms = engine.elf_symbols(img);
if (syms) {
    for (auto& s : *syms)
        if (s.bind == 1 /* STB_GLOBAL */ && s.type == 2 /* STT_FUNC */)
            printf("  %s @ 0x%llx\n", s.name.c_str(), s.value);
}
```

---

### Mach-O parser

Parse in-memory Mach-O images including fat (universal) binaries. The parser handles both 32-bit and 64-bit architectures and performs byte-swap for cross-endian fat headers.

| Method | Return | Description |
|---|---|---|
| `macho_fat_slices(macho_image)` | `Result<std::vector<MachOFatSlice>>` | List architecture slices in a fat binary |
| `macho_sections(macho_image)` | `Result<std::vector<MachOSection>>` | Parse sections from `LC_SEGMENT` / `LC_SEGMENT_64` |
| `macho_symbols(macho_image)` | `Result<std::vector<MachOSymbol>>` | Parse the symbol table via `LC_SYMTAB` |
| `macho_load_commands(macho_image)` | `Result<std::vector<MachOLoadCommand>>` | List all load commands with raw data |

#### Mach-O types

```cpp
struct MachOFatSlice {
    uint32_t cpu_type;
    uint32_t cpu_subtype;
    uint64_t offset;
    uint64_t size;
};

struct MachOSection {
    std::string  segname;      // e.g. "__TEXT"
    std::string  sectname;     // e.g. "__text"
    uint64_t     addr;
    uint64_t     size;
    uint32_t     offset;
    uint32_t     flags;
};

struct MachOSymbol {
    std::string  name;
    uint64_t     value;
    uint8_t      type;
    uint8_t      sect;
    int16_t      desc;
};

struct MachOLoadCommand {
    uint32_t cmd;              // LC_SEGMENT_64, LC_SYMTAB, …
    uint32_t size;
    std::vector<uint8_t> data;
};
```

---

### Control flow graph builder

Build a control flow graph from a live function address using the VanHooks disassembler. The builder walks instructions, splits on branches and terminators (return, unconditional jump, INT3), and tracks conditional/unconditional edges.

```cpp
Result<ControlFlowGraph> build_cfg(void* function_start, CfgBuildOptions opts = {});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `max_instructions` | `size_t` | 100000 | Instruction decode limit |
| `follow_calls` | `bool` | false | Recurse into called functions |
| `tag` | `std::string` | — | User tag |

#### CFG types

```cpp
struct BasicBlock {
    uint64_t              start_addr;
    uint64_t              end_addr;
    std::vector<uint64_t> successors;
    std::vector<uint64_t> predecessors;
    bool                  is_entry;
    bool                  is_exit;
};

enum class CfgEdgeKind : uint8_t {
    Fallthrough, ConditionalTrue, ConditionalFalse,
    Unconditional, Call, Return, Indirect,
};

struct CfgEdge {
    uint64_t    from;
    uint64_t    to;
    CfgEdgeKind kind;
};

struct ControlFlowGraph {
    std::vector<BasicBlock> blocks;
    std::vector<CfgEdge>   edges;
    uint64_t               entry_point;
};
```

#### Example — build a function's CFG

```cpp
auto cfg = engine.build_cfg(reinterpret_cast<void*>(&MyFunc));
if (cfg) {
    printf("Blocks: %zu  Edges: %zu\n", cfg->blocks.size(), cfg->edges.size());
    for (auto& blk : cfg->blocks)
        if (blk.is_exit) printf("  exit @ 0x%llx\n", blk.start_addr);
}
```

---

### Binary diffing

Compare two module images function by function, producing a per-function diff with similarity scores. Uses `detect_functions()` internally for boundary detection and name-based matching.

```cpp
Result<BinaryDiffResult> binary_diff(
    std::span<const uint8_t> old_image,
    std::span<const uint8_t> new_image,
    BinaryDiffOptions opts = {});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `similarity_threshold` | `float` | 0.5 | Below this, treat as added/removed |
| `instruction_level` | `bool` | false | Diff individual instructions |
| `tag` | `std::string` | — | User tag |

#### Diff types

```cpp
enum class DiffKind : uint8_t { Identical, Modified, Added, Removed };

struct FunctionDiff {
    std::string  name;
    uint64_t     addr_old;
    uint64_t     addr_new;
    DiffKind     kind;
    float        similarity;     // 0.0–1.0 for Modified entries
};

struct BinaryDiffResult {
    std::vector<FunctionDiff> functions;
    size_t total_old, total_new, matched, modified, added, removed;
};
```

#### Example — diff two builds

```cpp
auto v1 = load_file("game_v1.dll");
auto v2 = load_file("game_v2.dll");
auto diff = engine.binary_diff(v1, v2, { .similarity_threshold = 0.6f });
if (diff) {
    printf("Modified: %zu  Added: %zu  Removed: %zu\n",
           diff->modified, diff->added, diff->removed);
}
```

---

### Pattern scanner v2

Scan a memory region with named wildcard-mask rules. Each `PatternRule` defines a byte sequence and a parallel mask (`0xFF` = exact match, `0x00` = wildcard).

```cpp
Result<std::vector<PatternMatch>> pattern_scan(
    void* base, size_t size,
    std::span<const PatternRule> rules,
    PatternScanOptions opts = {});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `max_matches` | `size_t` | 0 (unlimited) | Stop after N total matches |
| `scan_start` | `uint64_t` | 0 (base) | Region start override |
| `scan_end` | `uint64_t` | 0 (base+size) | Region end override |
| `tag` | `std::string` | — | User tag |

#### Pattern types

```cpp
struct PatternRule {
    std::string              name;
    std::vector<uint8_t>     pattern;
    std::vector<uint8_t>     mask;        // 0xFF = exact, 0x00 = wildcard
    std::vector<std::string> tags;
};

struct PatternMatch {
    uint64_t     address;
    std::string  rule_name;
    size_t       length;
};
```

#### Example — scan for function prologues

```cpp
vanhooks::PatternRule rule;
rule.name    = "push_rbp_sub_rsp";
rule.pattern = { 0x55, 0x48, 0x83, 0xEC, 0x00 };
rule.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };

auto hits = engine.pattern_scan(base, size, {{ rule }});
if (hits)
    for (auto& m : *hits) printf("  %s @ 0x%llx\n", m.rule_name.c_str(), m.address);
```

---

### String scanner

Extract readable strings from a memory region, supporting ASCII and UTF-16LE encodings.

```cpp
Result<std::vector<ExtractedString>> string_scan(
    void* base, size_t size,
    StringScanOptions opts = {});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `min_length` | `size_t` | 4 | Minimum string length |
| `max_length` | `size_t` | 4096 | Maximum string length |
| `include_utf16` | `bool` | true | Also scan for UTF-16LE strings |
| `tag` | `std::string` | — | User tag |

#### String types

```cpp
enum class StringEncoding : uint8_t { Ascii, Utf8, Utf16LE, Utf16BE };

struct ExtractedString {
    uint64_t        address;
    std::string     value;
    StringEncoding  encoding;
    size_t          byte_len;
    std::string     section;
};
```

---

### RTTI recovery

Scan a module for MSVC Run-Time Type Information class descriptors. On Windows, searches `.rdata` and `.data` PE sections for the `".?AV"` MSVC type descriptor pattern and recovers class names, vtable addresses, and base class lists.

```cpp
Result<std::vector<RttiClassInfo>> rtti_scan(void* module_base);
```

> **Platform:** Windows only. Returns `Error::Unsupported` on POSIX.

#### RTTI types

```cpp
struct RttiClassInfo {
    std::string              name;
    uint64_t                 vtable_addr;
    uint64_t                 rtti_addr;
    std::vector<std::string> base_classes;
    size_t                   vtable_slots;
};
```

#### Example — dump RTTI from a loaded DLL

```cpp
HMODULE mod = GetModuleHandleA("engine.dll");
auto classes = engine.rtti_scan(mod);
if (classes)
    for (auto& c : *classes)
        printf("  %s  vtable=0x%llx  slots=%zu\n",
               c.name.c_str(), c.vtable_addr, c.vtable_slots);
```

---

### Function boundary detection

Heuristic detection of function start/end addresses using prologue pattern matching (`push rbp` variants, `sub rsp`) and a configurable confidence threshold.

```cpp
Result<std::vector<FunctionBoundary>> detect_functions(
    void* base, size_t size,
    FunctionDetectOptions opts = {});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `max_functions` | `size_t` | 0 (unlimited) | Limit detected functions |
| `min_confidence` | `float` | 0.5 | Discard below this threshold |
| `tag` | `std::string` | — | User tag |

#### Function boundary types

```cpp
struct FunctionBoundary {
    uint64_t    start;
    uint64_t    end;
    std::string name;              // symbol name if available
    bool        has_symbol;
    float       confidence;        // 0.0–1.0 heuristic confidence
};
```

---

### Error codes — Phase 25

| Name | Code | Description |
|---|---|---|
| `ElfInvalidHeader` | 1400 | Not a valid ELF file |
| `ElfNoSymtab` | 1401 | No symbol table section |
| `ElfNoDynamic` | 1402 | No dynamic section |
| `MachOInvalidHeader` | 1403 | Not a valid Mach-O file |
| `MachOFatSliceNotFound` | 1404 | Requested arch not in fat binary |
| `MachOCodeSigInvalid` | 1405 | Code signature validation failed |
| `CfgBuildFailed` | 1406 | CFG construction failed |
| `BinaryDiffFailed` | 1407 | Binary diffing failed |
| `PatternCompileFailed` | 1408 | Pattern rule compilation failed |
| `RttiNotFound` | 1409 | No RTTI data found |
| `FunctionBoundaryFailed` | 1410 | Function boundary detection failed |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🌐 Part XX — Network Layer v2

Phase 26 extends the network subsystem with packet timing normalisation, DNS fingerprint awareness, TLS JA3/JA4 fingerprinting, traffic replay, inline packet interception, certificate pinning detection, and a Winsock hook layer.

> **Compile-time gate:** all network methods require `VH_NET_ENABLED` at build time. Without it, calls return `Error::Unsupported`.

---

### Packet timing normalisation

Add controlled jitter to outgoing network responses to defeat timing-based anti-cheat profiling.

```cpp
Result<void> net_set_packet_timing(PacketTimingConfig config);
```

#### Config

```cpp
struct PacketTimingConfig {
    double   jitter_ms_min = 0.0;    // minimum added delay (ms)
    double   jitter_ms_max = 5.0;    // maximum added delay (ms)
    bool     enabled       = true;
    std::string tag;
};
```

---

### DNS fingerprinting

Scan network interfaces for DNS queries, identifying anti-cheat canary domains used for client presence verification.

```cpp
Result<std::vector<DnsFingerprint>> net_dns_fingerprint(
    std::string_view interface_name,
    uint32_t timeout_ms = 5000);
```

#### DNS types

```cpp
struct DnsFingerprint {
    std::string  domain;
    std::string  record_type;     // A, AAAA, CNAME, TXT
    uint64_t     ttl;
    bool         is_canary;       // likely AC check domain
    std::string  response;
};
```

---

### TLS fingerprinting

Capture JA3 and JA4 fingerprints from TLS Client Hello messages on the wire, useful for identifying which libraries or processes establish connections.

```cpp
Result<std::vector<TlsFingerprint>> net_tls_fingerprint(
    std::string_view interface_name,
    uint32_t timeout_ms = 5000);
```

#### TLS types

```cpp
struct TlsFingerprint {
    std::string  ja3_hash;
    std::string  ja4_hash;
    std::string  server_name;      // SNI
    uint16_t     tls_version;
    std::vector<uint16_t> cipher_suites;
};
```

#### Example — TLS fingerprint audit

```cpp
auto fps = engine.net_tls_fingerprint("eth0", 10000);
if (fps)
    for (auto& fp : *fps)
        printf("  SNI=%s  JA3=%s  JA4=%s\n",
               fp.server_name.c_str(), fp.ja3_hash.c_str(), fp.ja4_hash.c_str());
```

---

### Traffic replay

Replay a pcapng capture file on the network with configurable timing.

```cpp
Result<void> net_replay(
    std::string_view pcapng_path,
    ReplayOptions opts = {});
```

#### Replay options

```cpp
enum class ReplayMode : uint8_t {
    Realtime,       // replay at original timing
    FastForward,    // replay as fast as possible
    StepByStep,     // replay one packet at a time
};

struct ReplayOptions {
    ReplayMode   mode       = ReplayMode::Realtime;
    double       speed_mult = 1.0;     // for Realtime mode
    std::string  filter;               // BPF filter
    std::string  tag;
};
```

---

### Packet interception

Register inline packet modification rules using WinDivert (Windows) or nfqueue (Linux) for real-time traffic inspection and modification.

```cpp
Result<uint64_t> net_intercept_add(InterceptRule rule);
Result<void>     net_intercept_remove(uint64_t rule_id);
```

#### Intercept types

```cpp
struct InterceptRule {
    std::string  filter;       // BPF/WinDivert filter expression
    bool         drop;         // drop matching packets
    bool         modify;       // allow modification callback
    std::string  tag;
};
```

`net_intercept_add` returns a rule ID used to remove the rule later.

---

### Certificate pinning detection

Detect and map certificate pins (SPKI SHA-256) for a given hostname, identifying HPKP headers, embedded pins, and dynamic pin configurations.

```cpp
Result<std::vector<CertPinInfo>> net_cert_pin_scan(
    std::string_view hostname);
```

#### Cert pin types

```cpp
struct CertPinInfo {
    std::string  hostname;
    std::vector<std::string> pin_hashes;   // SPKI SHA-256 pins
    bool         enforced;
    std::string  source;       // "header" (HPKP), "embedded", "dynamic"
};
```

---

### Winsock hook layer

Install or remove hooks on Winsock (`WSA*`) functions for network monitoring and modification.

> **Platform:** Windows only. Returns `Error::Unsupported` on POSIX.

```cpp
Result<void> net_winsock_hook(WinsockHookConfig config = {});
Result<void> net_winsock_unhook();
```

#### Config

```cpp
struct WinsockHookConfig {
    bool     hook_send    = true;
    bool     hook_recv    = true;
    bool     hook_connect = true;
    bool     hook_accept  = true;
    bool     hook_dns     = true;    // gethostbyname / getaddrinfo
    std::string tag;
};
```

#### Example — monitor Winsock activity

```cpp
auto result = engine.net_winsock_hook({ .hook_send = true, .hook_recv = true });
if (result)
    printf("Winsock hooks installed\n");

// later…
engine.net_winsock_unhook();
```

---

### Error codes — Phase 26

| Name | Code | Description |
|---|---|---|
| `PacketTimingFailed` | 1500 | Packet timing layer failed |
| `DnsResolveFailed` | 1501 | DNS fingerprint capture failed |
| `TlsFingerprintFailed` | 1502 | TLS fingerprint capture failed |
| `ReplaySyncFailed` | 1503 | Traffic replay synchronisation failed |
| `InterceptDriverFailed` | 1504 | Packet intercept driver failed |
| `CertPinDetectFailed` | 1505 | Certificate pin detection failed |
| `WinsockHookFailed` | 1506 | Winsock hook installation failed |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📡 Part XXI — VanTrace v2

Phase 27 adds structured tracing with multiple output formats, filtering, remote streaming, ETW integration, flame graph export, and IDA/Ghidra annotation export.

> **Compile-time gate:** all trace methods require `VH_TRACE_ENABLED` at build time. Without it, calls return `Error::TraceInitFailed` or the relevant trace error.

---

### Trace initialisation

Start or reconfigure the trace subsystem with a ring buffer and output format.

```cpp
Result<void> trace_init(TraceConfig config = {});
Result<void> trace_shutdown();
```

#### TraceConfig

```cpp
enum class TraceFormat : uint8_t {
    Json,        // human-readable JSON lines
    Binary,      // compact binary format
    Collapsed,   // collapsed-stack for flame graphs
};

struct TraceConfig {
    TraceFormat format         = TraceFormat::Json;
    bool        include_stacks = true;
    bool        include_args   = false;    // log hook arguments
    size_t      buffer_size    = 1 << 20;  // ring buffer bytes (1 MB)
    std::string output_path;               // file path or empty for in-memory
    std::string tag;
};
```

#### Example — JSON trace to file

```cpp
engine.trace_init({
    .format      = vanhooks::TraceFormat::Json,
    .buffer_size = 4 << 20,  // 4 MB ring buffer
    .output_path = "trace.jsonl"
});
// … do work …
engine.trace_shutdown();
```

---

### Trace filtering

Apply module/function/address-range filters and call-depth limits to reduce noise.

```cpp
Result<void> trace_set_filter(TraceFilter filter);
```

#### TraceFilter

```cpp
struct TraceFilter {
    std::vector<std::string> include_modules;    // module name allowlist
    std::vector<std::string> exclude_modules;    // module name blocklist
    std::vector<uint64_t>    include_addresses;  // specific function addresses
    uint32_t                 max_depth = 0;      // 0 = unlimited call depth
    std::string              tag;
};
```

Returns `Error::TraceFilterInvalid` if all filter fields are empty (would capture everything with no filtering).

---

### Remote trace viewer

Stream trace data over TCP or a Windows named pipe for live viewing in an external tool.

```cpp
Result<void> trace_remote_start(TraceRemoteConfig config = {});
Result<void> trace_remote_stop();
```

#### TraceRemoteConfig

```cpp
struct TraceRemoteConfig {
    std::string  address    = "127.0.0.1";  // bind address
    uint16_t     port       = 47700;         // TCP port (0 = named pipe)
    std::string  pipe_name;                  // Windows named pipe name
    bool         auto_start = true;
    std::string  tag;
};
```

---

### ETW provider

Register VanHooks as an ETW provider for Windows Performance Analyzer integration.

> **Platform:** Windows only. Returns `Error::Unsupported` on POSIX.

```cpp
Result<void> trace_etw_register(TraceEtwConfig config = {});
Result<void> trace_etw_unregister();
```

#### TraceEtwConfig

```cpp
struct TraceEtwConfig {
    std::string  provider_name = "VanHooks-Trace";
    uint8_t      level         = 4;    // 1=critical … 5=verbose
    uint64_t     keyword_mask  = 0;    // ETW keyword filter
    std::string  tag;
};
```

---

### Flame graph export

Export collected trace data as collapsed-stack entries for flame graph visualisation tools (e.g. FlameGraph, speedscope).

```cpp
Result<std::vector<FlameGraphEntry>> trace_flame_export(
    std::string_view output_path);
```

#### FlameGraphEntry

```cpp
struct FlameGraphEntry {
    std::string  stack;         // semicolon-delimited collapsed stack
    uint64_t     duration_ns;   // inclusive duration in nanoseconds
};
```

#### Example — export flame graph

```cpp
auto flames = engine.trace_flame_export("flames.txt");
if (flames)
    for (auto& f : *flames)
        printf("%s %llu\n", f.stack.c_str(), f.duration_ns);
```

---

### Trace-to-IDA/Ghidra export

Export runtime trace data as IDA Python or Ghidra Java annotation scripts, adding comments and colour tags to disassembly.

```cpp
Result<void> trace_ida_export(TraceIdaExportOptions opts);
```

#### TraceIdaExportOptions

```cpp
enum class IdaExportFormat : uint8_t {
    IdaPython,    // .py script for IDA Pro
    GhidraJava,   // .java script for Ghidra
};

struct TraceIdaExportOptions {
    IdaExportFormat  format       = IdaExportFormat::IdaPython;
    bool             add_comments = true;
    bool             add_colors   = true;
    std::string      output_path;
    std::string      tag;
};
```

#### Example — annotate IDA database

```cpp
engine.trace_ida_export({
    .format      = vanhooks::IdaExportFormat::IdaPython,
    .output_path = "annotate.py"
});
// Open IDA → File → Script file → annotate.py
```

---

### Error codes — Phase 27

| Name | Code | Description |
|---|---|---|
| `TraceInitFailed` | 1600 | Trace subsystem initialisation failed |
| `TraceFilterInvalid` | 1601 | Empty or invalid trace filter |
| `TraceRemoteBindFailed` | 1602 | Remote viewer bind/listen failed |
| `TraceEtwRegisterFailed` | 1603 | ETW provider registration failed |
| `TraceFlameExportFailed` | 1604 | Flame graph export failed |
| `TraceIdaExportFailed` | 1605 | IDA/Ghidra export failed |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🧪 Part XXII — Test Suite

Phase 28 adds a built-in self-test framework with full hook-kind coverage, hardening tests, stress tests, and per-test execution.

---

### Running the full test suite

Execute all built-in self-tests (hook kinds, hardening, injection) with configurable verbosity, timeout, and parallelism.

```cpp
Result<TestSuiteResult> test_run(TestRunConfig config = {});
```

#### TestRunConfig

```cpp
enum class TestVerbosity : uint8_t {
    Quiet,      // only failures
    Summary,    // pass/fail counts
    Verbose,    // every test case
};

struct TestRunConfig {
    TestVerbosity verbosity    = TestVerbosity::Summary;
    uint32_t      timeout_ms   = 30000;   // per-test timeout
    bool          stop_on_fail = false;
    size_t        thread_count = 1;        // parallel test threads
    std::string   filter;                  // glob filter on test names
    std::string   tag;
};
```

#### TestSuiteResult

```cpp
enum class TestResult : uint8_t { Pass, Fail, Skip, Timeout };

struct TestCaseResult {
    std::string  name;
    TestResult   result;
    double       elapsed_ms;
    std::string  message;       // failure/skip reason
};

struct TestSuiteResult {
    std::vector<TestCaseResult> cases;
    size_t  total, passed, failed, skipped;
    double  elapsed_ms;
};
```

#### Example — run all tests

```cpp
auto suite = engine.test_run({ .verbosity = vanhooks::TestVerbosity::Verbose });
if (suite) {
    printf("Results: %zu passed, %zu failed, %zu skipped\n",
           suite->passed, suite->failed, suite->skipped);
    for (auto& c : suite->cases)
        if (c.result == vanhooks::TestResult::Fail)
            printf("  FAIL: %s — %s\n", c.name.c_str(), c.message.c_str());
}
```

---

### Stress testing

Run concurrent hook/unhook operations from multiple threads to detect race conditions and deadlocks.

```cpp
Result<TestSuiteResult> test_stress(StressTestConfig config = {});
```

#### StressTestConfig

```cpp
struct StressTestConfig {
    size_t   thread_count   = 8;
    size_t   iterations     = 10000;
    size_t   chain_depth    = 16;      // max hook chain depth
    uint32_t timeout_ms     = 60000;
    std::string tag;
};
```

Tests included:
- `stress_concurrent_hook_unhook` — N threads hooking/unhooking simultaneously
- `stress_chain_depth` — deep hook chains up to `chain_depth`
- `stress_batch_queue_saturation` — batch queue flooding

---

### Single test execution

Run one named test case by exact name.

```cpp
Result<TestCaseResult> test_run_one(std::string_view test_name,
                                    uint32_t timeout_ms = 30000);
```

Returns a `TestCaseResult` with `TestResult::Skip` and message `"test not found"` if the name does not match any registered test.

---

### Test listing

Enumerate all available test names for programmatic filtering.

```cpp
Result<std::vector<std::string>> test_list();
```

#### Example — list and run filtered tests

```cpp
auto names = engine.test_list();
if (names)
    for (auto& n : *names)
        printf("  %s\n", n.c_str());

// Run only hook tests
auto hooks = engine.test_run({ .filter = "hook_" });
```

---

### Built-in test coverage

The following tests are included in `test_run()`:

| Test name | Category |
|---|---|
| `hook_callsite` | Core hook |
| `hook_hwbp` | Core hook |
| `hook_iat` | Core hook |
| `hook_vtable` | Core hook |
| `hook_mid` | Core hook |
| `hook_pageguard` | Core hook |
| `hook_softbp` | Core hook |
| `hook_eat` | Core hook |
| `hook_exception` | Core hook |
| `hook_threadlocal` | Core hook |
| `hook_tls` | Core hook |
| `hook_syscall` | Core hook |
| `hook_nirvana` | Core hook |
| `hook_plt` | Core hook (Linux/macOS) |
| `hook_got` | Core hook (Linux/macOS) |
| `hardening_polymorphic` | Hardening |
| `hardening_engine_crypt` | Hardening |
| `hardening_tamper_detect` | Hardening |
| `hardening_auto_rehook` | Hardening |

---

### Error codes — Phase 28

| Name | Code | Description |
|---|---|---|
| `TestHarnessFailed` | 1700 | Test harness initialisation failed |
| `TestTimeoutExpired` | 1701 | Test exceeded its timeout |
| `TestAssertionFailed` | 1702 | Test assertion failed |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔥 Part XXIII — Fuzzing Infrastructure

Phase 29 adds a programmatic fuzzing API with multi-engine support (libFuzzer, AFL++, Honggfuzz), 8 subsystem-specific fuzz targets, corpus management, crash deduplication, and sanitizer runtime detection.

---

### Starting a fuzz session

Launch a fuzzing run against one of the built-in targets.

```cpp
Result<void> fuzz_start(FuzzConfig config);
```

#### FuzzConfig

```cpp
enum class FuzzEngine : uint8_t {
    LibFuzzer, AflPlusPlus, Honggfuzz,
};

enum class FuzzTarget : uint8_t {
    Disasm, Trampoline, PeParser, ElfParser,
    MachOParser, Injection, PatternScanner, StringScanner,
};

struct FuzzConfig {
    FuzzEngine   engine         = FuzzEngine::LibFuzzer;
    FuzzTarget   target         = FuzzTarget::Disasm;
    std::string  corpus_dir;                 // seed corpus directory
    std::string  output_dir;                 // crash/artifact output
    size_t       max_iterations = 0;         // 0 = unlimited
    size_t       max_input_size = 4096;
    uint32_t     timeout_ms     = 10000;     // per-input timeout
    bool         detect_leaks   = true;
    std::string  tag;
};
```

Returns `Error::FuzzTargetInvalid` if both `corpus_dir` is empty and `max_iterations` is 0.

#### Example — fuzz the disassembler

```cpp
engine.fuzz_start({
    .engine     = vanhooks::FuzzEngine::LibFuzzer,
    .target     = vanhooks::FuzzTarget::Disasm,
    .corpus_dir = "corpus/disasm",
    .output_dir = "crashes/disasm",
});
```

---

### Stopping a fuzz session

Stop the active fuzz loop and collect all crash artifacts.

```cpp
Result<std::vector<FuzzCrashInfo>> fuzz_stop();
```

#### FuzzCrashInfo

```cpp
struct FuzzCrashInfo {
    std::string  input_hash;      // SHA-256 of crashing input
    std::string  target_name;
    std::string  crash_type;      // "heap-buffer-overflow", "null-deref", …
    std::string  stack_trace;
    size_t       input_size = 0;
    bool         deduplicated = false;
};
```

---

### Corpus management

Query statistics and minimise the seed corpus.

```cpp
Result<CorpusStats> fuzz_corpus_stats();
Result<CorpusStats> fuzz_corpus_minimise(std::string_view corpus_dir);
```

#### CorpusStats

```cpp
struct CorpusStats {
    size_t  total_inputs;
    size_t  minimised_count;
    size_t  total_crashes;
    size_t  unique_crashes;
    double  coverage_pct;
};
```

Returns `Error::FuzzCorpusLoadFailed` if `corpus_dir` is empty or unreadable.

---

### Sanitizer runtime detection

Check at runtime whether a specific sanitizer is compiled in.

```cpp
Result<bool> fuzz_sanitizer_available(SanitizerKind kind);
```

#### SanitizerKind

```cpp
enum class SanitizerKind : uint8_t {
    Asan, Ubsan, Msan, Tsan, Lsan,
};
```

---

### Listing fuzz targets

```cpp
Result<std::vector<std::string>> fuzz_list_targets();
```

Returns: `["disasm", "trampoline", "pe_parser", "elf_parser", "macho_parser", "injection", "pattern_scanner", "string_scanner"]`

---

### Error codes — Phase 29

| Name | Code | Description |
|---|---|---|
| `FuzzTargetInvalid` | 1800 | Invalid fuzz target or config |
| `FuzzCorpusLoadFailed` | 1801 | Corpus directory load failed |
| `FuzzSanitizerMissing` | 1802 | Required sanitizer not available |
| `FuzzCrashDetected` | 1803 | Fuzz session detected a crash |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚙️ Part XXIV — CI/CD Pipeline

Phase 30 adds a programmatic CI/CD API for workflow validation, local job execution across 10 platform configurations, SDK sync checking, release automation, coverage reporting, static analysis, and binary size tracking.

---

### Workflow validation

Validate a GitHub Actions YAML workflow file.

```cpp
Result<void> ci_validate_workflow(std::string_view workflow_path);
```

Returns `Error::CiWorkflowInvalid` if the path is empty or the YAML is malformed.

---

### Local job execution

Run a CI build job locally for any platform configuration.

```cpp
Result<CiJobResult> ci_run_job(CiJobConfig config);
```

#### CiJobConfig / CiJobResult

```cpp
enum class CiPlatform : uint8_t {
    WindowsX64, WindowsX86, WindowsArm64,
    LinuxX64Gcc, LinuxX64Clang, LinuxArm64,
    MacOsX64, MacOsArm64,
    FuzzSmoke, NetEnabled,
};

struct CiJobConfig {
    CiPlatform   platform;
    std::string  build_type  = "Release";
    bool         net_enabled = false;
    bool         fuzz_smoke  = false;
    std::string  tag;
};

struct CiJobResult {
    CiPlatform   platform;
    bool         success;
    double       elapsed_sec;
    size_t       warnings;
    size_t       errors;
    std::string  log_summary;
};
```

---

### SDK sync check

Verify that public headers in the source tree match the SDK copy. Prevents SDK drift.

```cpp
Result<CiSdkSyncResult> ci_check_sdk_sync();
```

#### CiSdkSyncResult

```cpp
struct CiSdkSyncResult {
    bool                     in_sync;
    std::vector<std::string> mismatched_headers;
};
```

#### Example — check SDK sync

```cpp
auto sync = engine.ci_check_sdk_sync();
if (sync && !sync->in_sync) {
    printf("SDK out of sync! Mismatched:\n");
    for (auto& h : sync->mismatched_headers)
        printf("  %s\n", h.c_str());
}
```

---

### Release automation

Build a release archive from a version tag, optionally publishing to GitHub Releases.

```cpp
Result<void> ci_release_build(CiReleaseConfig config);
```

#### CiReleaseConfig

```cpp
struct CiReleaseConfig {
    std::string  version_tag;         // e.g. "v0.2.0"
    bool         generate_archive = true;
    bool         publish_release  = false;
    std::string  tag;
};
```

Returns `Error::CiReleaseBuildFailed` if `version_tag` is empty.

---

### Coverage reporting

Run tests with coverage instrumentation and produce a summary.

```cpp
Result<CiCoverageReport> ci_coverage_report();
```

#### CiCoverageReport

```cpp
struct CiCoverageReport {
    double  line_pct;
    double  branch_pct;
    double  function_pct;
    size_t  lines_covered;
    size_t  lines_total;
};
```

---

### Static analysis

Run a static analyser and collect structured results.

```cpp
Result<CiStaticAnalysisResult> ci_static_analysis(
    std::string_view tool_name = "clang-tidy");
```

#### CiStaticAnalysisResult

```cpp
struct CiStaticAnalysisResult {
    size_t       issues_total;
    size_t       issues_error;
    size_t       issues_warning;
    size_t       issues_note;
    std::string  tool_name;
};
```

---

### Binary size tracking

Measure the size of every build output for each platform.

```cpp
Result<std::vector<CiBinarySizeEntry>> ci_binary_sizes();
```

#### CiBinarySizeEntry

```cpp
struct CiBinarySizeEntry {
    std::string  target_name;     // "vanhooks.lib", "vanhooks.dll"
    CiPlatform   platform;
    size_t       size_bytes;
};
```

---

### Error codes — Phase 30

| Name | Code | Description |
|---|---|---|
| `CiWorkflowInvalid` | 1900 | Workflow YAML is invalid |
| `CiJobFailed` | 1901 | CI job execution failed |
| `CiSdkSyncMismatch` | 1902 | SDK headers out of sync |
| `CiReleaseBuildFailed` | 1903 | Release build failed |
| `CiCoverageReportFailed` | 1904 | Coverage report generation failed |
| `CiStaticAnalysisFailed` | 1905 | Static analysis run failed |

---

## 📖 Part XXV — API Documentation

Phase 31 adds a programmatic documentation API for generating API references, querying module/hook/injection documentation, and building error reference guides — all from within the engine.

### `doc_generate`

```cpp
Result<void> doc_generate(DocGenerateConfig config = {});
```

Generate API documentation from header doc-comments.

**Config:**

| Field | Type | Default | Description |
|---|---|---|---|
| `format` | `DocFormat` | `Html` | Output format: `Html`, `Markdown`, `Json` |
| `output_dir` | `string` | `"docs/api"` | Output directory path |
| `theme` | `string` | `"vanhooks"` | Doxygen theme name |
| `include_private` | `bool` | `false` | Include private/internal APIs |
| `include_source` | `bool` | `false` | Include source code snippets |

**Example:**

```cpp
DocGenerateConfig cfg;
cfg.format     = DocFormat::Markdown;
cfg.output_dir = "docs/md";
auto r = engine.doc_generate(cfg);
```

### `doc_module_info`

```cpp
Result<DocModuleInfo> doc_module_info(std::string_view module_name);
```

Get documentation for a specific module by name.

**Returns:** `DocModuleInfo` with `name`, `category`, `description`, `detects`, `engines`, `functions`.

**Example:**

```cpp
auto info = engine.doc_module_info("vh::unhook");
if (info) {
    // info->category == "vigil"
    // info->description contains module summary
}
```

### `doc_list_modules`

```cpp
Result<std::vector<DocModuleInfo>> doc_list_modules();
```

List all documented modules with their categories. Returns entries for: core, hooks, vigil, inject, analysis, net.

### `doc_hook_kinds`

```cpp
Result<std::vector<HookKindInfo>> doc_hook_kinds();
```

Returns documentation for all 17 hook kinds, including:

| Field | Description |
|---|---|
| `kind` | `HookKindDoc` enum value |
| `name` | Human-readable name |
| `description` | What the hook kind does |
| `when_to_use` | Decision guidance |
| `performance` | Overhead estimate (ns/call) |
| `windows` / `linux_` / `macos` | Platform support flags |

**Example:**

```cpp
auto kinds = engine.doc_hook_kinds();
for (auto& k : *kinds) {
    printf("%s: %s (%s)\n", k.name.c_str(), k.when_to_use.c_str(), k.performance.c_str());
}
```

### `doc_injection_techniques`

```cpp
Result<std::vector<InjectionTechniqueInfo>> doc_injection_techniques();
```

Returns documentation for 25 injection techniques with stealth rankings (1 = most stealthy), platform flags, and prerequisite requirements.

**Example:**

```cpp
auto techs = engine.doc_injection_techniques();
// Sort by stealth:
std::sort(techs->begin(), techs->end(),
    [](auto& a, auto& b) { return a.stealth_rank < b.stealth_rank; });
```

### `doc_error_reference`

```cpp
Result<std::vector<ErrorRefEntry>> doc_error_reference();
```

Returns structured error documentation with `code`, `name`, `cause`, `troubleshooting`, and `recovery_example` for each error.

### Error codes — Phase 31

| Name | Code | Description |
|---|---|---|
| `DocGenerateFailed` | 2000 | Documentation generation failed |
| `DocModuleNotFound` | 2001 | Requested module not found in registry |
| `DocOutputPathInvalid` | 2002 | Output path is empty or inaccessible |

---

## 🔧 Part XXVI — SDK Improvements

Phase 32 adds programmatic SDK management: automated header/lib sync, version checking, changelog retrieval, minimal profile builds, and multi-language binding generation (C, Python, Rust, C#).

### `sdk_sync`

```cpp
Result<SdkSyncReport> sdk_sync(SdkSyncConfig config = {});
```

Synchronise public headers and compiled libraries from the source tree to the SDK directory.

**Config:**

| Field | Type | Default | Description |
|---|---|---|---|
| `source_include_dir` | `string` | `"include"` | Source header root |
| `sdk_include_dir` | `string` | `"../VanHooksSDK/include"` | SDK header root |
| `lib_output_dir` | `string` | `"lib"` | Source lib output |
| `sdk_lib_dir` | `string` | `"../VanHooksSDK/lib"` | SDK lib output |
| `copy_libs` | `bool` | `true` | Copy compiled libraries |
| `copy_headers` | `bool` | `true` | Copy public headers |

**Returns:** `SdkSyncReport` with `headers_copied`, `headers_skipped`, `libs_copied`, `changed_files`.

**Example:**

```cpp
auto report = engine.sdk_sync();
if (report) {
    printf("Synced %zu headers, %zu libs\n", report->headers_copied, report->libs_copied);
}
```

### `sdk_version`

```cpp
Result<SdkVersionInfo> sdk_version();
```

Returns the SDK version and whether the header version matches the compiled library version.

**Returns:** `SdkVersionInfo` with `major`, `minor`, `patch`, `full_string`, `header_matches_lib`.

### `sdk_changelog`

```cpp
Result<std::vector<SdkChangelogEntry>> sdk_changelog();
```

Returns structured changelog entries. Each `SdkChangelogEntry` has `version`, `date`, `added`, `changed`, `removed`, `deprecated` string lists.

### `sdk_build_minimal`

```cpp
Result<void> sdk_build_minimal(SdkMinimalConfig config = {});
```

Build a minimal SDK with only the selected module groups.

**Profiles (`SdkProfile`):**

| Profile | Includes |
|---|---|
| `Full` | All modules |
| `Minimal` | Core hooks only |
| `Analysis` | Core + analysis subsystem |
| `Stealth` | Core + vigil + stealth pack |

Additional per-module flags: `include_inject`, `include_vigil`, `include_analysis`, `include_net`.

### `sdk_generate_bindings`

```cpp
Result<BindingGenResult> sdk_generate_bindings(BindingGenConfig config);
```

Generate language bindings for the VanHooks C API.

**Supported languages (`BindingLang`):** `C`, `Python`, `Rust`, `CSharp`

**Returns:** `BindingGenResult` with `language`, `functions_wrapped`, `types_wrapped`, `generated_files`.

**Example:**

```cpp
BindingGenConfig cfg;
cfg.language   = BindingLang::Python;
cfg.output_dir = "bindings/python";
auto result = engine.sdk_generate_bindings(cfg);
// result->generated_files == {"vanhooks.pyi", "vanhooks_bindings.cpp"}
```

### Error codes — Phase 32

| Name | Code | Description |
|---|---|---|
| `SdkSyncFailed` | 2100 | Header/lib sync failed |
| `SdkVersionMismatch` | 2101 | Header and lib versions do not match |
| `SdkMinimalBuildFailed` | 2102 | Minimal profile build failed |
| `SdkBindingGenFailed` | 2103 | Binding generation failed |

---

## 📚 Part XXVII — Examples & Tutorials

Phase 33 adds a programmatic example registry with 7 comprehensive examples, metadata queries, and build integration.

### `example_list`

```cpp
Result<std::vector<ExampleInfo>> example_list();
```

Returns metadata for all 7 built-in examples:

| Name | Category | Demonstrates |
|---|---|---|
| `quickstart` | core | `hook_trampoline`, `enable`, `remove` |
| `all_hook_kinds` | core | All 17 HookKind values |
| `stealth_pipeline` | stealth | `ac_profile`, `unhook`, `peb_mask`, `telemetry`, `callstack_spoof`, `sleep_obf` |
| `analysis_workflow` | analysis | `pe_exports`, `symbols`, `pattern_scan`, `callstack_capture` |
| `network_capture` | net | `net_aware`, `net_dns_fingerprint`, `net_tls_fingerprint` |
| `cross_platform` | cross-platform | `hook_trampoline`, `hook_plt`, `hook_iat`, platform macros |
| `game_integration` | game-integration | `hook_vtable`, `unhook`, `peb_mask`, `poly::generate`, `shadow::create` |

**`ExampleInfo` fields:** `name`, `title`, `description`, `category`, `source_path`, `demonstrates` (vector of API features).

### `example_get`

```cpp
Result<ExampleInfo> example_get(std::string_view name);
```

Get info for a specific example by name.

**Example:**

```cpp
auto info = engine.example_get("stealth_pipeline");
if (info) {
    printf("Example: %s\n", info->title.c_str());
    printf("Path: %s\n", info->source_path.c_str());
    for (auto& feat : info->demonstrates)
        printf("  - %s\n", feat.c_str());
}
```

### `example_build`

```cpp
Result<ExampleBuildResult> example_build(ExampleBuildConfig config);
```

Build (and optionally run) an example.

**Config:**

| Field | Type | Default | Description |
|---|---|---|---|
| `example_name` | `string` | — | Example to build (required) |
| `build_dir` | `string` | `"build/examples"` | Output directory |
| `run_after` | `bool` | `false` | Run the example after building |

**Returns:** `ExampleBuildResult` with `success`, `output_path`, `build_sec`, `log`.

### Error codes — Phase 33

| Name | Code | Description |
|---|---|---|
| `ExampleNotFound` | 2200 | Requested example does not exist |
| `ExampleBuildFailed` | 2201 | Example build failed |

---

## ⚡ Part XXVIII — Performance Pass

Phase 34 adds a micro-benchmark framework with 8 benchmark targets, an arena allocator API for trampoline stubs, and per-module memory footprint tracking.

### `perf_benchmark`

```cpp
Result<BenchmarkResult> perf_benchmark(BenchmarkConfig config);
```

Run a specific micro-benchmark.

**Benchmark targets (`BenchmarkTarget`):**

| Target | Measures |
|---|---|
| `HookInstall` | Time to install a single hook |
| `HookDispatch` | Per-call overhead through detour |
| `HookRemove` | Time to cleanly remove a hook |
| `BatchInstall` | N hooks in one `apply_queued` cycle |
| `TrampolineAlloc` | Single trampoline allocation |
| `ArenaAlloc` | Arena-based bulk allocation |
| `LockContention` | Concurrent hook lookup latency |
| `CachePressure` | Hook table traversal under load |

**Config:**

| Field | Type | Default | Description |
|---|---|---|---|
| `target` | `BenchmarkTarget` | — | What to benchmark |
| `iterations` | `size_t` | `10000` | Number of iterations |
| `warmup` | `size_t` | `100` | Warmup iterations (excluded) |
| `threads` | `size_t` | `1` | Thread count for contention tests |
| `timeout_ms` | `uint32_t` | `30000` | Per-benchmark timeout |

**Returns:** `BenchmarkResult` with `min_ns`, `max_ns`, `avg_ns`, `median_ns`, `p99_ns`, `iterations`, `total_ms`.

**Example:**

```cpp
BenchmarkConfig cfg;
cfg.target     = BenchmarkTarget::HookDispatch;
cfg.iterations = 100000;
auto r = engine.perf_benchmark(cfg);
printf("Hook dispatch: avg %.1f ns, p99 %.1f ns\n", r->avg_ns, r->p99_ns);
```

### `perf_benchmark_all`

```cpp
Result<std::vector<BenchmarkResult>> perf_benchmark_all(
    size_t iterations = 10000, uint32_t timeout_ms = 60000);
```

Run all 8 benchmarks and return a summary vector.

### `perf_memory_footprint`

```cpp
Result<MemoryFootprint> perf_memory_footprint();
```

Get the current memory usage of the engine and all modules.

**Returns:** `MemoryFootprint` with `engine_bytes`, `hooks_bytes`, `trampolines_bytes`, `vigil_bytes`, `net_bytes`, `total_bytes`.

### `perf_arena_init` / `perf_arena_stats` / `perf_arena_destroy`

```cpp
Result<void>       perf_arena_init(ArenaConfig config = {});
Result<ArenaStats> perf_arena_stats();
Result<void>       perf_arena_destroy();
```

Arena allocator for trampoline stubs — reduces VirtualAlloc calls by pre-allocating executable memory blocks.

**ArenaConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `initial_size` | `size_t` | `65536` (64 KB) | Initial arena block size |
| `max_size` | `size_t` | `16777216` (16 MB) | Maximum total arena size |
| `executable` | `bool` | `true` | Allocate with execute permission |
| `hint_address` | `void*` | `nullptr` | Prefer allocation near this address |

**ArenaStats:** `allocated_bytes`, `used_bytes`, `free_bytes`, `alloc_count`, `arena_count`.

### Error codes — Phase 34

| Name | Code | Description |
|---|---|---|
| `BenchmarkFailed` | 2300 | Benchmark execution failed |
| `BenchmarkTimeout` | 2301 | Benchmark exceeded timeout |
| `ArenaAllocFailed` | 2302 | Arena allocation failed |

---

## 🍎 Part XXIX — Phase 39: macOS Deep Support

Phase 39 introduces 5 modules that replace macOS POSIX stubs with real implementations using Mach, dyld, IOKit, and Security framework APIs. Non-macOS platforms compile to safe stubs returning `Error::Unsupported` or empty defaults.

---

### Mach-O Vigil `<vh/vigil/macho_vigil.vh>`

**Namespace:** `vh::macho_vigil`

Enumerates dyld-loaded images, parses Mach-O headers and sections, and detects code signing and `__RESTRICT` segments.

#### Structs

**`DyldImageInfo`:**

| Field | Type | Description |
|---|---|---|
| `path` | `std::string` | Full path of the loaded image |
| `load_address` | `uint64_t` | Base address in memory |
| `slide` | `uint64_t` | ASLR slide value |
| `is_system` | `bool` | True for images under /usr/lib or /System |

**`MachOSectionInfo`:**

| Field | Type | Description |
|---|---|---|
| `segment` | `std::string` | Segment name (e.g. `__TEXT`) |
| `section` | `std::string` | Section name (e.g. `__text`) |
| `address` | `uint64_t` | Section virtual address |
| `size` | `uint64_t` | Section size in bytes |
| `flags` | `uint32_t` | Mach-O section flags |

#### Functions

| Signature | Description |
|---|---|
| `std::vector<DyldImageInfo> enumerate_dyld_images()` | List all dyld-loaded images |
| `std::vector<MachOSectionInfo> get_sections(const char* image_path)` | Parse sections of a Mach-O image |
| `bool is_code_signed(const char* image_path)` | Check if the image has a code signature |
| `uint32_t get_image_flags(const char* image_path)` | Get Mach-O header flags |
| `bool has_restrict_segment(const char* image_path)` | Check for `__RESTRICT` segment |
| `std::vector<std::string> find_kext_loaded_images()` | Find images loaded by kernel extensions |

---

### SIP Awareness `<vh/vigil/sip_aware.vh>`

**Namespace:** `vh::sip_aware`

Queries macOS System Integrity Protection state at runtime via `csr_get_active_config()`.

#### Enums

**`SipStatus`:** `Unknown`, `Enabled`, `Disabled`, `Partial`

#### Structs

**`SipFlags`:** `filesystem_protection`, `kext_signing`, `task_for_pid_restriction`, `debugging_restriction`, `dtrace_restriction`, `nvram_protection`, `apple_internal_reserved` — all `bool`.

#### Functions

| Signature | Description |
|---|---|
| `SipStatus query_sip_status()` | Get current SIP status |
| `SipFlags query_sip_flags()` | Get detailed SIP flag breakdown |
| `bool can_ptrace_targets()` | Whether ptrace is allowed by SIP |
| `bool can_task_for_pid()` | Whether `task_for_pid` is available |
| `bool can_inject_dyld_insert()` | Whether `DYLD_INSERT_LIBRARIES` works |
| `bool can_load_unsigned_kexts()` | Whether unsigned kexts can load |
| `bool is_amfi_enforced()` | Whether AMFI is enforcing |

---

### Hardened Runtime `<vh/vigil/hardened_runtime.vh>`

**Namespace:** `vh::hardened_runtime`

Detects macOS Hardened Runtime entitlements and code signing via the `csops()` syscall.

#### Structs

**`EntitlementInfo`:** `allow_jit`, `allow_unsigned_executable_memory`, `allow_dyld_environment_variables`, `disable_library_validation`, `disable_executable_page_protection`, `com_apple_security_cs_debugger` — all `bool`.

**`CodeSignInfo`:**

| Field | Type | Description |
|---|---|---|
| `is_signed` | `bool` | Has a code signature |
| `is_valid` | `bool` | Signature is valid |
| `hardened_runtime` | `bool` | Hardened Runtime is active |
| `library_validation` | `bool` | Library validation is enforced |
| `flags` | `uint32_t` | Raw `csops` flags |
| `team_id` | `std::string` | Signing team identifier |
| `signing_id` | `std::string` | Signing identifier |

#### Functions

| Signature | Description |
|---|---|
| `CodeSignInfo query_code_signing()` | Query code signing for this process |
| `CodeSignInfo query_code_signing_for(const char* path)` | Query code signing for an arbitrary binary |
| `EntitlementInfo query_entitlements()` | Query entitlements for this process |
| `bool is_hardened_runtime_active()` | Whether Hardened Runtime is enforced |
| `bool is_library_validation_active()` | Whether Library Validation is enforced |
| `bool can_execute_jit()` | Whether JIT compilation is allowed |
| `bool can_modify_executable_pages()` | Whether executable pages can be modified |
| `bool can_use_dyld_env_vars()` | Whether DYLD environment variables are honoured |

---

### Kext Enumeration `<vh/vigil/kext_enum.vh>`

**Namespace:** `vh::kext_enum`

macOS equivalent of `driver_fence`. Enumerates loaded kexts and System Extensions, identifies known anti-cheat kernel modules.

#### Structs

**`KextInfo`:** `bundle_id`, `version` (string), `load_address`, `size` (uint64), `is_apple`, `is_ac_related` (bool).

**`SystemExtInfo`:** `bundle_id`, `team_id`, `category` (string), `is_active`, `is_ac_related` (bool).

#### Functions

| Signature | Description |
|---|---|
| `std::vector<KextInfo> enumerate_kexts()` | List all loaded kernel extensions |
| `std::vector<SystemExtInfo> enumerate_system_extensions()` | List System Extensions (macOS 11+) |
| `bool has_ac_kext()` | True if an anti-cheat kext is loaded |
| `bool has_ac_system_extension()` | True if an AC system extension is active |
| `std::vector<std::string> get_ac_kext_ids()` | Get bundle IDs of detected AC kexts |

---

### PAC Awareness `<vh/vigil/pac_aware.vh>`

**Namespace:** `vh::pac_aware`

ARM64e Pointer Authentication Code detection and stripping. Reports which hook strategies remain viable under PAC enforcement.

#### Enums

**`PacSupport`:** `Unavailable`, `Available`, `Enforced`

#### Structs

**`PacInfo`:** `data_pac`, `code_pac` (PacSupport), `arm64e`, `kernel_pac` (bool).

#### Functions

| Signature | Description |
|---|---|
| `PacInfo query_pac_support()` | Query PAC hardware and enforcement state |
| `bool is_pac_enforced()` | Whether code PAC is enforced |
| `std::uintptr_t strip_pac(std::uintptr_t ptr)` | Strip PAC bits from a pointer |
| `void* strip_pac_ptr(void* ptr)` | Strip PAC from a void pointer |
| `bool is_pointer_signed(std::uintptr_t ptr)` | Check if upper bits contain a PAC |
| `bool can_use_trampoline_hooks()` | Trampoline hooks viable under PAC |
| `bool can_use_got_hooks()` | GOT hooks viable under PAC |
| `bool can_use_vtable_hooks()` | VTable hooks viable under PAC |

---

## 🐧 Part XXX — Phase 40: Linux Deep Support

Phase 40 introduces 6 modules replacing Linux POSIX stubs with real implementations using /proc, bpf(), Landlock, and MAC system queries. Non-Linux platforms compile to safe stubs.

---

### Linux Vigil `<vh/vigil/linux_vigil.vh>`

**Namespace:** `vh::linux_vigil`

Full Linux process introspection via /proc: module enumeration, memory map parsing, thread listing, TracerPid detection.

#### Structs

**`ModuleInfo`:** `name`, `path` (string), `base`, `end`, `size` (uint64), `is_executable`, `is_shared_object` (bool).

**`MemoryRegion`:** `start`, `end` (uint64), `readable`, `writable`, `executable`, `is_private`, `is_anonymous` (bool), `pathname` (string).

**`ThreadInfo`:** `tid` (uint32), `name` (string), `state` (char), `nice` (int64), `utime`, `stime` (uint64).

#### Functions

| Signature | Description |
|---|---|
| `std::vector<ModuleInfo> enumerate_modules()` | List all loaded modules from /proc/self/maps |
| `std::vector<MemoryRegion> enumerate_memory_regions()` | Full memory map with permissions |
| `std::vector<ThreadInfo> enumerate_threads()` | List all threads via /proc/self/task |
| `bool is_being_traced()` | Check TracerPid in /proc/self/status |
| `bool is_running_as_root()` | UID == 0 |
| `uint32_t get_parent_pid()` | Read PPid from /proc/self/status |
| `std::string get_process_name(uint32_t pid)` | Read comm for any PID |
| `std::string get_exe_path()` | readlink /proc/self/exe |
| `bool has_capability(int cap)` | Check a Linux capability |
| `bool is_namespace_sandboxed()` | Compare namespaces with PID 1 |

---

### procfs Vigil `<vh/vigil/procfs_vigil.vh>`

**Namespace:** `vh::procfs_vigil`

Deep /proc introspection: FD enumeration, cgroup inspection, namespace detection, container detection.

#### Structs

**`FdInfo`:** `fd` (int), `path`, `type` (string), `is_socket`, `is_pipe` (bool).

**`CgroupInfo`:** `hierarchy`, `controller`, `path` (string), `is_v2` (bool).

**`NamespaceInfo`:** `type` (string), `inode` (uint64), `is_root` (bool).

**`StatusField`:** `key`, `value` (string).

#### Functions

| Signature | Description |
|---|---|
| `std::vector<FdInfo> enumerate_fds(uint32_t pid = 0)` | List open FDs (0 = self) |
| `std::vector<CgroupInfo> query_cgroups(uint32_t pid = 0)` | Parse cgroup memberships |
| `std::vector<NamespaceInfo> query_namespaces(uint32_t pid = 0)` | List namespace inodes |
| `std::vector<StatusField> read_proc_status(uint32_t pid = 0)` | Parse all /proc/pid/status fields |
| `std::string read_proc_field(const char* field, uint32_t pid = 0)` | Read a single status field |
| `uint64_t read_proc_mem_value(uint64_t address, uint32_t pid = 0)` | Read a 64-bit value from /proc/pid/mem |
| `bool is_in_container()` | Heuristic: PID namespace differs from PID 1 |
| `bool is_in_docker()` | Check /.dockerenv and cgroup patterns |
| `bool has_proc_access(uint32_t pid)` | Whether /proc/pid is readable |

---

### eBPF Awareness `<vh/vigil/ebpf_aware.vh>`

**Namespace:** `vh::ebpf_aware`

Detects eBPF programs monitoring syscalls, network, and file access via `bpf()` syscall enumeration.

#### Enums

**`BpfProgType`:** `Unknown`, `SocketFilter`, `Kprobe`, `Tracepoint`, `Xdp`, `PerfEvent`, `CgroupSkb`, `CgroupSock`, `LwtIn`, `LwtOut`, `LsmMac`, `Tracing`

#### Structs

**`BpfProgInfo`:** `id` (uint32), `type` (BpfProgType), `name` (string), `run_count` (uint32), `run_time_ns` (uint64), `is_gpl` (bool).

**`BpfMapInfo`:** `id`, `type`, `key_size`, `value_size`, `max_entries` (uint32), `name` (string).

#### Functions

| Signature | Description |
|---|---|
| `std::vector<BpfProgInfo> enumerate_bpf_programs()` | List all loaded BPF programs |
| `std::vector<BpfMapInfo> enumerate_bpf_maps()` | List all BPF maps |
| `bool has_bpf_monitoring()` | Any tracing/kprobe/tracepoint programs loaded |
| `bool has_syscall_tracing()` | BPF programs tracing syscalls |
| `bool has_network_monitoring()` | XDP/socket filter/cgroup programs loaded |
| `bool has_file_monitoring()` | LSM BPF programs for file access |
| `bool has_lsm_bpf()` | LSM-MAC BPF programs active |
| `bool can_load_bpf()` | Whether this process can load BPF programs |

---

### Landlock Awareness `<vh/vigil/landlock_aware.vh>`

**Namespace:** `vh::landlock_aware`

Detects Landlock LSM (Linux 5.13+) restrictions on file and network access.

#### Enums

**`LandlockStatus`:** `Unavailable`, `Available`, `Active`

#### Structs

**`LandlockInfo`:** `status` (LandlockStatus), `abi_version` (uint32), `fs_restrictions`, `net_restrictions` (bool).

#### Functions

| Signature | Description |
|---|---|
| `LandlockInfo query_landlock()` | Full Landlock status query |
| `bool is_landlock_available()` | Whether the kernel supports Landlock |
| `bool is_landlock_active()` | Whether this process has Landlock rules |
| `uint32_t get_abi_version()` | Landlock ABI version (0 = unavailable) |
| `bool has_fs_restrictions()` | File system access restrictions active |
| `bool has_net_restrictions()` | Network restrictions active (ABI v4+) |
| `bool can_write_path(const char* path)` | Test write access to a path |
| `bool can_read_path(const char* path)` | Test read access to a path |

---

### Proton/Wine Awareness `<vh/vigil/proton_aware.vh>`

**Namespace:** `vh::proton_aware`

Detects Wine, Proton, and CrossOver translation layers. On Windows (under Wine) it queries ntdll for `wine_get_version`; on Linux it reads Steam runtime environment variables.

#### Enums

**`WineLayer`:** `None`, `Wine`, `Proton`, `CrossOver`

#### Structs

**`WineInfo`:** `layer` (WineLayer), `version`, `host_os` (string), `is_wow64`, `has_esync`, `has_fsync`, `has_ntsync` (bool).

#### Functions

| Signature | Description |
|---|---|
| `WineInfo query_wine_environment()` | Full Wine/Proton environment query |
| `bool is_wine()` | Running under Wine |
| `bool is_proton()` | Running under Proton specifically |
| `WineLayer get_wine_layer()` | Which translation layer is active |
| `std::string get_wine_version()` | Wine version string |
| `bool has_native_wayland()` | Native Wayland support in Wine |
| `bool has_native_vulkan()` | Wine Vulkan ICD present |
| `bool is_syscall_emulated(const char* dll, const char* func)` | Whether a specific syscall is translated |
| `bool should_use_native_hooks()` | Prefer native (Linux) hooks |
| `bool should_use_windows_hooks()` | Prefer Windows API hooks |

---

### SELinux/AppArmor Awareness `<vh/vigil/selinux_aware.vh>`

**Namespace:** `vh::selinux_aware`

Detects mandatory access control policies (SELinux and AppArmor) and determines how they constrain hooking operations.

#### Enums

**`MacSystem`:** `None`, `SELinux`, `AppArmor`, `Both`

**`EnforcementMode`:** `Disabled`, `Permissive`, `Enforcing`

#### Structs

**`MacInfo`:** `system` (MacSystem), `selinux`, `apparmor` (EnforcementMode), `selinux_context`, `apparmor_profile` (string).

#### Functions

| Signature | Description |
|---|---|
| `MacInfo query_mac()` | Full MAC system query |
| `MacSystem get_active_mac()` | Which MAC system is active |
| `EnforcementMode get_selinux_mode()` | SELinux enforcement mode |
| `std::string get_selinux_context()` | Current SELinux context |
| `EnforcementMode get_apparmor_mode()` | AppArmor enforcement mode |
| `std::string get_apparmor_profile()` | Current AppArmor profile |
| `bool can_ptrace()` | Whether MAC allows ptrace |
| `bool can_mmap_exec()` | Whether MAC allows PROT_EXEC mmap |
| `bool can_modify_proc()` | Whether /proc modifications are allowed |
| `bool is_confined()` | Whether this process is confined by MAC |

---

## 📱 Part XXXI — Phase 41: Mobile Support

Phase 41 introduces 4 modules for Android ARM64 hooking and injection, Android anti-cheat detection, and iOS research. Non-mobile platforms compile to safe stubs returning `Error::Unsupported`.

---

### Android ARM64 Hooking `<vh/vigil/android_hook.vh>`

**Namespace:** `vh::android_hook`

Inline hooks for native NDK libraries using ARM64 LDR X17/BR X17 trampolines, PLT/GOT hook stubs, and ART method resolution.

#### Enums

**`HookType`:** `InlineNative`, `ArtMethod`, `PltGot`

#### Structs

**`NativeHookInfo`:** `library`, `symbol` (string), `target`, `detour`, `original` (uintptr_t), `type` (HookType), `active` (bool).

**`ArtMethodInfo`:** `class_name`, `method_name`, `signature` (string), `art_method_ptr`, `entry_point` (uintptr_t).

#### Functions

| Signature | Description |
|---|---|
| `Result<NativeHookInfo> hook_native(const char* library, const char* symbol, void* detour)` | Install an inline hook on a native symbol |
| `Result<void> unhook_native(const NativeHookInfo& info)` | Remove a previously installed hook |
| `Result<NativeHookInfo> hook_plt(const char* caller_lib, const char* target_lib, const char* symbol, void* detour)` | Install a PLT/GOT hook |
| `Result<ArtMethodInfo> resolve_art_method(const char* class_name, const char* method_name, const char* signature)` | Resolve an ART method pointer |
| `Result<void> hook_art_method(const ArtMethodInfo& method, uintptr_t replacement)` | Replace an ART method's entry point |
| `bool is_art_runtime()` | Whether libart.so is loaded |
| `std::string get_art_version()` | ART runtime version string |
| `std::vector<std::string> enumerate_native_libraries()` | List all native .so files from /proc/self/maps |

---

### Android Injection `<vh/vigil/android_inject.vh>`

**Namespace:** `vh::android_inject`

Multiple injection vectors for loading native libraries into Android processes: ptrace + dlopen, /proc/pid/mem, Zygote hooking, linker namespace manipulation.

#### Enums

**`InjectionMethod`:** `ZygoteHook`, `PtraceDlopen`, `ProcMem`, `LinkerNamespace`

#### Structs

**`InjectionResult`:** `method` (InjectionMethod), `base` (uintptr_t), `library_path` (string), `success` (bool).

#### Functions

| Signature | Description |
|---|---|
| `Result<InjectionResult> inject_library(uint32_t pid, const char* library_path, InjectionMethod method)` | Inject a library using a specific method |
| `Result<InjectionResult> inject_library_auto(uint32_t pid, const char* library_path)` | Auto-select the best injection method |
| `bool can_ptrace_pid(uint32_t pid)` | Whether ptrace is possible for the target |
| `bool can_access_proc_mem(uint32_t pid)` | Whether /proc/pid/mem is accessible |
| `bool is_zygote_available()` | Whether the Zygote socket is present |
| `bool has_root()` | Running as root or su binary present |
| `bool has_magisk()` | Magisk root manager detected |
| `bool has_kernelsu()` | KernelSU detected |
| `std::string get_linker_namespace(uint32_t pid)` | Get linker namespace info for a PID |

---

### Android Anti-Cheat Awareness `<vh/vigil/android_ac_aware.vh>`

**Namespace:** `vh::android_ac_aware`

Detects SafetyNet / Play Integrity, root hiding, known AC modules (GameGuard, EAC, BattlEye), Frida, Xposed, and emulator heuristics.

#### Enums

**`IntegrityLevel`:** `Unknown`, `NoIntegrity`, `BasicDevice`, `DeviceCts`, `StrongDevice`

#### Structs

**`SafetyNetInfo`:** `available`, `cts_profile_match`, `basic_integrity` (bool), `level` (IntegrityLevel).

**`RootDetectionInfo`:** `su_binary`, `magisk_detected`, `kernelsu_detected`, `busybox_present`, `test_keys`, `selinux_permissive`, `props_modified` — all `bool`.

**`AcModuleInfo`:** `name`, `package`, `native_lib` (string), `detected` (bool).

#### Functions

| Signature | Description |
|---|---|
| `SafetyNetInfo query_safety_net()` | Query SafetyNet / Play Integrity availability |
| `RootDetectionInfo query_root_detection()` | Comprehensive root detection scan |
| `std::vector<AcModuleInfo> detect_ac_modules()` | Detect known anti-cheat native libraries |
| `bool is_play_integrity_active()` | Play Integrity service detected |
| `bool is_root_hidden()` | Root present but hidden (Magisk Hide etc.) |
| `bool is_frida_detected()` | Frida agent or server detected |
| `bool is_xposed_present()` | Xposed framework loaded |
| `bool has_tampered_signature()` | APK signature differs from expected |
| `bool is_debuggable()` | ro.debuggable is set |
| `bool is_emulator()` | Running on an emulator |

---

### iOS Research `<vh/vigil/ios_research.vh>`

**Namespace:** `vh::ios_research`

Research-phase module for jailbroken iOS. Detects jailbreak type (Substrate, Substitute, Ellekit, Dopamine), provides Objective-C runtime introspection, and handles PAC stripping on A12+.

#### Enums

**`JailbreakType`:** `None`, `Substrate`, `Substitute`, `Ellekit`, `Dopamine`, `Unknown`

#### Structs

**`JailbreakInfo`:** `type` (JailbreakType), `version` (string), `has_tfp0`, `has_pac_bypass`, `rootless` (bool).

**`ObjcMethodInfo`:** `class_name`, `selector` (string), `imp` (uintptr_t), `is_class_method` (bool).

#### Functions

| Signature | Description |
|---|---|
| `JailbreakInfo detect_jailbreak()` | Detect jailbreak type and capabilities |
| `bool is_jailbroken()` | Whether the device is jailbroken |
| `bool has_substrate()` | MobileSubstrate loaded |
| `bool has_substitute()` | Substitute loaded |
| `bool has_ellekit()` | ElleKit loaded |
| `bool can_hook_objc()` | ObjC hooking is viable |
| `Result<ObjcMethodInfo> resolve_objc_method(const char* class_name, const char* selector)` | Resolve an ObjC method IMP |
| `std::vector<std::string> enumerate_loaded_classes()` | List all loaded ObjC classes |
| `bool has_pac_on_device()` | Device has PAC hardware (A12+) |
| `std::uintptr_t strip_pac_ios(std::uintptr_t ptr)` | Strip PAC bits from a pointer |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

<div align="center">

*VanHooks Functions Guide · v0.1.0*

<sub>Built and maintained by <a href="https://github.com/TsyVM">TsyVM</a> · <a href="https://www.teamvanilla.org/">TeamVanilla</a></sub>

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:DC2626,100:0D0D0D&height=80&section=footer"/>

</div>
