# VanHooks — Functions Guide

**Public API Reference · v1.0.0**  
C++23 · Windows / Linux / macOS · x86 / x64 / ARM64

---

One include is all you need:

```cpp
#include <vh/vh.hpp>
```

Everything in this document lives in the `vh::` namespace unless stated otherwise.

---

## Table of Contents

1. [Legend](#part-i--legend)
2. [Result Type and Error Handling](#part-ii--result-type-and-error-handling)
3. [Level 1 API — One-line hooks](#part-iii--level-1-api)
4. [Level 2 API — Explicit hook types](#part-iv--level-2-api)
5. [Hook Object Methods](#part-v--hook-object-methods)
6. [Group](#part-vi--group)
7. [HookRegistry](#part-vii--hookregistry)
8. [Configuration Structs](#part-viii--configuration-structs)
9. [Error Codes](#part-ix--error-codes)
10. [Quick Reference](#part-x--quick-reference-card)

---

## Part I — Legend

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

---

## Part II — Result Type and Error Handling

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

---

## Part III — Level 1 API

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

---

## Part IV — Level 2 API

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

---

## Part V — Hook Object Methods

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

---

## Part VI — Group

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

---

## Part VII — HookRegistry

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

---

## Part VIII — Configuration Structs

All config structs live in the `vh::config::` namespace and are defined in `<vh/config.hpp>`, which is included automatically by `<vh/vh.hpp>`.

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

---

## Part IX — Error Codes

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

---

## Part X — Quick Reference Card

### Include

```cpp
#include <vh/vh.hpp>
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

---

*VanHooks Functions Guide · v1.0.0*
