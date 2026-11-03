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

[Phase 10 — Hardening](#-part-xiii--phase-10-hardening) · [Shared Library ABI](#-part-xiv--shared-library-abi)

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

<div align="center">

*VanHooks Functions Guide · v0.1.0*

<sub>Built and maintained by <a href="https://github.com/TsyVM">TsyVM</a> · <a href="https://www.teamvanilla.org/">TeamVanilla</a></sub>

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:DC2626,100:0D0D0D&height=80&section=footer"/>

</div>
