# VanHooks
<img src="[https://your-image-url-here.jpg](https://cdn.discordapp.com/attachments/1512188478329196735/1512376847227289682/Screenshot_20260605_034442_Gallery.jpg" alt="VanHooks Banner">
**Modern C++23 Cross-Platform Function Hooking Library**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)

[![Windows](https://img.shields.io/badge/Windows-x86%20%7C%20x64-0078D4?logo=windows)](lib/)
[![Linux](https://img.shields.io/badge/Linux-x64%20%7C%20ARM64-FCC624?logo=linux&logoColor=black)](lib/)
[![macOS](https://img.shields.io/badge/macOS-x64%20%7C%20ARM64-000000?logo=apple)](lib/)

VanHooks is a production-grade, cross-platform function hooking library for C++23. It provides inline trampoline hooks, import table hooks, procedure linkage table hooks, virtual function table hooks, and mid-function register-context hooks — all through a single unified API backed by `std::expected` error handling and RAII lifetime management.

---

## Why VanHooks?

| | MinHook | EasyHook | SafetyHook | PolyHook2 | **VanHooks** |
|---|---|---|---|---|---|
| **Platforms** | Win | Win | Win / Lin | Win | **Win / Lin / macOS** |
| **ARM64** | ✗ | ✗ | ✗ | ✗ | **✓** |
| **Hook types** | Trampoline | Trampoline + IAT | Trampoline | Trampoline + IAT + VTable | **Trampoline + IAT + PLT + VTable + Mid** |
| **Error handling** | C enum | C enum | exceptions | exceptions | **`std::expected`** |
| **C++ standard** | C89 API | .NET | C++23 | C++20 | **C++23** |
| **macOS lazy pointers** | ✗ | ✗ | ✗ | ✗ | **✓** |
| **RAII hook lifetime** | ✗ | ✗ | ✓ | ✓ | **✓** |
| **Batch group operations** | ✗ | ✗ | ✗ | ✗ | **✓** |
| **Hook chaining** | ✗ | ✓ | ✗ | ✓ | **✓** |
| **Mid-function hooks** | ✗ | ✗ | ✓ | ✗ | **✓** |

---

## Requirements

| Requirement | Minimum |
|---|---|
| C++ standard | C++23 |
| MSVC | 19.38+ (Visual Studio 2022 17.8+) |
| GCC | 13+ |
| Clang | 17+ |
| CMake | 3.25+ (optional — drop-in use requires no build system) |
| Windows target | Windows 10 1903 / Windows Server 2019 |

No runtime dependencies. Zydis is compiled into the library.

---

## Installation

### Option A — Drop-in (precompiled, no build system required)

Copy `include/` into your project and link against the precompiled `.lib` for your target.

**Library selection:**

| Target | Configuration | Path |
|---|---|---|
| Windows x64 | Release | `lib/win-x64/Release/vanhooks.lib` |
| Windows x86 | Release | `lib/win-x86/Release/vanhooks.lib` |

All precompiled libs use a static CRT (`/MT` Release, `/MTd` Debug). No Visual C++ Redistributable is required. See [`lib/README.md`](lib/README.md) for MSVC project settings and ARM64 / Linux / macOS build-from-source instructions.

**CMake (drop-in):**

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

**MSVC project (manual):**

1. **Additional Include Directories** → add `include\`
2. **Additional Library Directories** → add `lib\win-x64\Release\` (adjust for arch/config)
3. **Additional Dependencies** → add `vanhooks.lib`
4. **Runtime Library** → `Multi-threaded (/MT)` for Release, `Multi-threaded Debug (/MTd)` for Debug

---

## Quick Start

One include is all you need:

```cpp
#include <vh/vh.hpp>
```

Everything lives in the `vh::` namespace.

### Intercept a function (no call-through needed)

```cpp
int my_detour(int a, int b) {
    printf("intercepted!\n");
    return a + b;
}

auto r = vh::hook(&target_fn, &my_detour);
if (!r) {
    printf("failed: %s\n", vh::error_to_string(r.error()).data());
}
// Hook is live. r->valid() == true.
// Hook removes itself when r goes out of scope.
```

### Intercept a function and call the original

```cpp
static int (*orig_fn)(int, int) = nullptr;

int my_detour(int a, int b) {
    printf("add(%d, %d)\n", a, b);
    return orig_fn(a, b);   // call through to real function
}

auto r = vh::hook(&target_fn, &my_detour, &orig_fn);
```

### Hook a system function by name

```cpp
static decltype(&MessageBoxW) orig_mbw = nullptr;

BOOL WINAPI hk_mbw(HWND h, LPCWSTR text, LPCWSTR cap, UINT type) {
    return orig_mbw(h, L"[Intercepted]", cap, type);
}

auto r = vh::hook("user32", "MessageBoxW", &hk_mbw, &orig_mbw);
```

---

## Hook Types

VanHooks provides five hook types, all returning the same `Result<Hook>` type.

### Inline (trampoline) hook

Patches the first bytes of the target function with a jump. Works on any function whose prologue is large enough — 5 bytes on x86/x64, 16 bytes on ARM64.

```cpp
auto r = vh::inline_hook(&target, &detour, &orig, { .tag = "Module.Function" });
```

### IAT hook — Windows

Patches an Import Address Table entry. Intercepts calls from a specific module without modifying the target function itself. Useful for short functions that cannot be safely inline-hooked.

```cpp
// Patch the IAT entry in a specific module
auto r = vh::iat_hook("MessageBoxW", (void*)&hk_mbw,
                      { .module_name = "my_app.exe", .tag = "IAT.MessageBoxW" });

// Patch every loaded module's IAT entry at once
auto hooks = vh::iat_hook_all("malloc", (void*)&hk_malloc);
```

### PLT hook — Linux / macOS

Patches the Procedure Linkage Table (Linux) or lazy pointer (macOS) used by the dynamic linker. The POSIX equivalent of an IAT hook.

```cpp
auto r = vh::plt_hook("libc", "malloc", (void*)&hk_malloc, { .tag = "libc.malloc" });
```

### VTable hook

Patches a single slot in a C++ virtual function table.

```cpp
// Hook IDXGISwapChain::Present (slot 8)
void** vtbl = *reinterpret_cast<void***>(swap_chain_ptr);

static HRESULT (STDMETHODCALLTYPE *orig_Present)(IDXGISwapChain*, UINT, UINT) = nullptr;

HRESULT STDMETHODCALLTYPE hk_Present(IDXGISwapChain* sc, UINT sync, UINT flags) {
    // render overlay
    return orig_Present(sc, sync, flags);
}

auto r = vh::vtable_hook(vtbl, 8,
                         (void*)&hk_Present,
                         (void**)&orig_Present,
                         { .tag = "DXGI.Present" });
```

### Mid-function hook

Installs a hook at a byte offset inside a function. Does not redirect control flow — observes and optionally modifies CPU register state at that point, then continues original execution.

```cpp
auto r = vh::mid_hook(game_update_fn,
    [](vh::MidContext* ctx) noexcept {
        player_health = static_cast<int>(ctx->rax);
    },
    { .offset = 0x1C, .tag = "Game.HealthReadback" });
```

---

## Hook Lifetime and RAII

Every hook creation function returns `Result<Hook>`. The `Hook` object removes the hook automatically when it is destroyed — you do not need to call remove manually in normal use.

```cpp
{
    auto r = vh::hook(&fn, &detour);
    // hook is live here
}
// hook automatically removed when r goes out of scope
```

To control hook state explicitly:

```cpp
auto r = vh::hook(&fn, &detour);
auto& h = *r;

h.disable();    // deactivate without removing
h.enable();     // reactivate
h.remove();     // permanently remove (destructor also does this)

h.valid();      // is the hook installed?
h.enabled();    // is it currently active?
h.tag();        // the tag string set at creation
```

---

## Groups — Batch Lifecycle Management

A `Group` owns multiple hooks and enables, disables, or removes them all inside a single thread-suspension window — significantly cheaper than operating on each hook individually.

```cpp
auto grp = vh::group("RenderHooks");

grp.add(vh::vtable_hook(vtbl, 8,  (void*)&hk_Present))
   .add(vh::vtable_hook(vtbl, 16, (void*)&hk_Reset))
   .add(vh::iat_hook("CreateDevice", (void*)&hk_CreateDevice));

grp.enable();   // one suspension window for all three
grp.disable();  // same

// Find a specific hook by tag
grp.at("DXGI.Present").disable();

// Iterate
for (auto& h : grp) {
    printf("%s: %s\n", h.tag().c_str(), h.enabled() ? "on" : "off");
}

// Maximum performance — queue operations, flush once
grp.queue_enable().apply();
```

---

## Hook Chaining

A second detour can be inserted in front of an existing hook. Execution order after chaining:

```
new_detour → original_detour → real_function
```

Chain links must be removed in reverse order of creation.

```cpp
auto base = vh::inline_hook(&fn, &detour1, &orig1).value();

static decltype(&fn) chain_orig = nullptr;
auto link = base.chain(&detour2, &chain_orig).value();

// Later, in reverse order:
link.remove();
base.remove();
```

---

## Error Handling

VanHooks uses `std::expected<T, vh::Error>` (aliased as `vh::Result<T>`) throughout. No exceptions are thrown, no global error state, zero overhead on the success path.

```cpp
auto r = vh::hook(&fn, &detour, &orig);

if (!r) {
    printf("failed: %s\n", vh::error_to_string(r.error()).data());
    return;
}

vh::Hook h = std::move(*r);
```

Chain results with `.and_then()` and `.transform_error()`:

```cpp
auto r = vh::hook(&fn, &detour, &orig)
    .and_then([](vh::Hook h) -> vh::Result<vh::Hook> {
        h.disable();
        return h;
    });
```

See the [Functions Guide](VanHooks_Functions_Guide.md) for the full error code reference.

---

## Multi-Module Projects — HookRegistry

`HookRegistry` is a process-wide singleton that owns named Groups. Use it when multiple DLLs in the same process register hooks independently and a single shutdown call should clean all of them up.

```cpp
// Module A (render DLL):
auto render = vh::group("Render");
render.add(vh::vtable_hook(vtbl, 8, (void*)&hk_Present));
vh::HookRegistry::global().register_group(std::move(render));

// Module B (network DLL):
auto net = vh::group("Network");
net.add(vh::api_hook("ws2_32", "send", &hk_send));
vh::HookRegistry::global().register_group(std::move(net));

// Shutdown — one call removes everything from both modules:
vh::HookRegistry::global().remove_all();
```

---

## Platform Support

| Platform | x86 | x64 | ARM64 |
|---|---|---|---|
| Windows | ✓ | ✓ | Build from source |
| Linux | — | ✓ | ✓ |
| macOS | — | ✓ | ✓ |

Precompiled `.lib` files are provided for Windows x86 and x64. ARM64 and POSIX targets require a source build — see [`lib/README.md`](lib/README.md).

---

## Documentation

- **[VanHooks_Functions_Guide.md](VanHooks_Functions_Guide.md)** — Complete API reference: every function, every configuration field, every error code.
- **[lib/README.md](lib/README.md)** — Precompiled library matrix, MSVC project setup, and build-from-source instructions for ARM64 and POSIX.
---

## License

MIT — see [LICENSE](LICENSE)
