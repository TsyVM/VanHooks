<div align="center">

<img src="vh-logo.png" width="600" alt="VanHooks"/>

<p><em>Modern C++23 Cross-Platform Function Hooking &amp; Process Injection Library</em></p>

<a href="#">
<img src="https://readme-typing-svg.demolab.com/?lines=Five+hook+types.+One+unified+API.;24+injection+techniques.+Indirect+syscalls.;Trampoline+%C2%B7+IAT+%C2%B7+PLT+%C2%B7+VTable+%C2%B7+Mid.;std%3A%3Aexpected+errors.+RAII+lifetimes.;Windows+%C2%B7+Linux+%C2%B7+macOS+%C2%B7+ARM64.;Groups+batch+hooks+in+one+suspension.;No+PAGE_EXECUTE_READWRITE.+Ever.&font=Fira%20Code&center=true&width=700&height=45&color=DC2626&vCenter=true&size=20&pause=1800"/>
</a>

<br/>

[![License: MIT](https://img.shields.io/badge/License-MIT-DC2626?style=for-the-badge&labelColor=0D0D0D)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-DC2626?style=for-the-badge&labelColor=0D0D0D&logo=cplusplus&logoColor=DC2626)](https://en.cppreference.com/w/cpp/23)
[![Windows](https://img.shields.io/badge/Windows-x86%20%7C%20x64-DC2626?style=for-the-badge&labelColor=0D0D0D&logo=windows&logoColor=DC2626)](lib/)
[![Linux](https://img.shields.io/badge/Linux-x64%20%7C%20ARM64-DC2626?style=for-the-badge&labelColor=0D0D0D&logo=linux&logoColor=DC2626)](lib/)
[![macOS](https://img.shields.io/badge/macOS-x64%20%7C%20ARM64-DC2626?style=for-the-badge&labelColor=0D0D0D&logo=apple&logoColor=DC2626)](lib/)
[![TeamVanilla](https://img.shields.io/badge/Team-TeamVanilla-DC2626?style=for-the-badge&labelColor=0D0D0D)](https://www.teamvanilla.org/)

<br/>

[![Stars](https://img.shields.io/github/stars/tsyvm/vanhooks?style=for-the-badge&color=DC2626&labelColor=0D0D0D)](../../stargazers)
[![Issues](https://img.shields.io/github/issues/tsyvm/vanhooks?style=for-the-badge&color=DC2626&labelColor=0D0D0D)](../../issues)
[![Last Commit](https://img.shields.io/github/last-commit/tsyvm/vanhooks?style=for-the-badge&color=DC2626&labelColor=0D0D0D)](../../commits)
[![Downloads](https://img.shields.io/github/downloads/tsyvm/vanhooks/total?style=for-the-badge&color=DC2626&labelColor=0D0D0D)](../../releases)

<br/>

[![Hook types](https://img.shields.io/badge/Hooks-5%20types-DC2626?style=flat-square&labelColor=0D0D0D)](#-hook-types)
[![Injection](https://img.shields.io/badge/Injection-24%20techniques-DC2626?style=flat-square&labelColor=0D0D0D)](#-process-injection)
[![Syscalls](https://img.shields.io/badge/Syscalls-indirect%20mode-DC2626?style=flat-square&labelColor=0D0D0D)](#stealth-hardening)
[![Error handling](https://img.shields.io/badge/Errors-std%3A%3Aexpected-DC2626?style=flat-square&labelColor=0D0D0D)](#-error-handling)
[![RAII](https://img.shields.io/badge/Lifetime-RAII%20hooks-DC2626?style=flat-square&labelColor=0D0D0D)](#-hook-lifetime-and-raii)
[![Zero deps](https://img.shields.io/badge/Runtime-zero%20dependencies-DC2626?style=flat-square&labelColor=0D0D0D)](#%EF%B8%8F-requirements)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

VanHooks is a production-grade, cross-platform function hooking and process injection library for C++23. It provides inline trampoline hooks, import table hooks, procedure linkage table hooks, virtual function table hooks, mid-function register-context hooks, and a 24-technique injection catalogue — all through a single unified API backed by `std::expected` error handling and RAII lifetime management.

All injection paths use indirect syscalls (executing at ntdll gadget addresses) so kernel stack walks see a legitimate origin. No `PAGE_EXECUTE_READWRITE` memory is ever allocated — all code pages follow the RW → RX lifecycle.

VanHooks is distributed as **precompiled static libraries with public API headers**. Drop the headers and the matching `.lib` files into your project and link — no build system integration or source compilation required.

<div align="center">

### 📑 Contents

[Why VanHooks](#-why-vanhooks) · [Requirements](#%EF%B8%8F-requirements) · [Installation](#-installation) · [Quick Start](#-quick-start)

[Hook Types](#-hook-types) · [Hook Lifetime](#-hook-lifetime-and-raii) · [Groups](#-groups--batch-lifecycle-management) · [Hook Chaining](#-hook-chaining)

[Process Injection](#-process-injection) · [Error Handling](#-error-handling) · [HookRegistry](#-multi-module-projects--hookregistry) · [Platform Support](#-platform-support)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🧭 Why VanHooks

| | MinHook | EasyHook | SafetyHook | PolyHook2 | **VanHooks** |
|---|---|---|---|---|---|
| **Platforms** | Win | Win | Win / Lin | Win | **Win / Lin / macOS** |
| **ARM64** | ✗ | ✗ | ✗ | ✗ | **✓** |
| **Hook types** | Trampoline | Trampoline + IAT | Trampoline | Trampoline + IAT + VTable | **Trampoline + IAT + PLT + VTable + Mid** |
| **Process injection** | ✗ | ✗ | ✗ | ✗ | **24 techniques** |
| **Indirect syscalls** | ✗ | ✗ | ✗ | ✗ | **✓ (all injection)** |
| **Error handling** | C enum | C enum | exceptions | exceptions | **`std::expected`** |
| **C++ standard** | C89 API | .NET | C++23 | C++20 | **C++23** |
| **macOS lazy pointers** | ✗ | ✗ | ✗ | ✗ | **✓** |
| **RAII hook lifetime** | ✗ | ✗ | ✓ | ✓ | **✓** |
| **Batch group operations** | ✗ | ✗ | ✗ | ✗ | **✓** |
| **Hook chaining** | ✗ | ✓ | ✗ | ✓ | **✓** |
| **Mid-function hooks** | ✗ | ✗ | ✓ | ✗ | **✓** |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🛠️ Requirements

| | |
|---|---|
| **C++ standard** | C++23 |
| **MSVC** | 19.38+ (Visual Studio 2022 17.8+) |
| **GCC** | 13+ |
| **Clang** | 17+ |
| **CMake** | 3.25+ — optional; drop-in use needs no build system |
| **Windows target** | Windows 10 1903 / Windows Server 2019 |
| **Runtime dependencies** | None — Zydis is compiled into the library |

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📦 Installation

### Option A — Drop-in (precompiled, no build system required)

Copy `include/` into your project and link against the precompiled `.lib` for your target.

| Target | Configuration | Path |
|---|---|---|
| Windows x64 | Release | `lib/win-x64/Release/vanhooks.lib` |
| Windows x64 | Debug | `lib/win-x64/Debug/vanhooks.lib` |
| Windows x86 | Release | `lib/win-x86/Release/vanhooks.lib` |
| Windows x86 | Debug | `lib/win-x86/Debug/vanhooks.lib` |

All precompiled libs use a static CRT (`/MT` Release, `/MTd` Debug). No Visual C++ Redistributable is required. See [`lib/README.md`](lib/README.md) for MSVC project settings and ARM64 / Linux / macOS build-from-source instructions.

### Option B — CMake (drop-in)

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

### Option C — MSVC project (manual)

1. **Additional Include Directories** → add `include\`
2. **Additional Library Directories** → add `lib\win-x64\Release\` (adjust for arch/config)
3. **Additional Dependencies** → add `vanhooks.lib`
4. **Runtime Library** → `Multi-threaded (/MT)` for Release, `Multi-threaded Debug (/MTd)` for Debug

### Single include

```cpp
#include <vh/vh.vh>
```

Everything lives in the `vh::` namespace.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚡ Quick Start

### Intercept a function (no call-through needed)

```cpp
#include <vh/vh.vh>

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🪝 Hook Types

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔒 Hook Lifetime and RAII

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📦 Groups — Batch Lifecycle Management

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🔗 Hook Chaining

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 💉 Process Injection

VanHooks includes a full injection subsystem with 24 techniques, all hardened with indirect syscalls. Include `<vh/inject.vh>` for the core 4 methods, or `<vh/inject_unified.vh>` for the full 24-technique catalogue.

### Quick Start — LoadLibrary (simplest)

```cpp
#include <vh/inject.vh>

auto inj = vh::inject(pid, "C:\\payloads\\research.dll");
if (!inj) {
    fprintf(stderr, "inject failed: %d\n", (int)inj.error());
    return;
}
// DLL is running in pid; ejects when inj goes out of scope
```

### Manual-Map (no module-list entry)

```cpp
std::vector<uint8_t> pe = load_from_resource();
auto inj = vh::inject_from_memory(pid, pe,
    { .method = vh::InjectMethod::ManualMap, .tag = "research" });
```

### Thread-Hijack (no remote thread spawned)

```cpp
auto inj = vh::inject(pid, dll_path,
    { .method = vh::InjectMethod::ThreadHijack });
```

### APC Queue (fires on next alertable wait)

```cpp
auto inj = vh::inject(pid, dll_path,
    { .method = vh::InjectMethod::ApcQueue });
```

### Method Trade-offs

| Method | Module list | Remote thread | Timing | Detection |
|---|---|---|---|---|
| **LoadLibrary** | Visible | Yes | Immediate | Trivially detected |
| **ManualMap** | Hidden | Yes (shellcode) | Immediate | No loader entry |
| **ThreadHijack** | Visible | No | Immediate | No thread-creation callback |
| **ApcQueue** | Visible | No | Non-deterministic | No thread-creation callback |

### Extended Catalogue (24 techniques)

The unified API (`<vh/inject_unified.vh>`) adds 20 more techniques across five groups:

- **Process-birth:** EarlyBird APC, Herpaderping, Ghosting, Doppelgänging
- **Remote-thread modern:** NtCreateThreadEx, RtlCreateUserThread, Reflective, SetWindowsHookEx
- **APC-modern:** QueueApcEx2, Waiting-thread hijack
- **Callback-hijack:** KernelCallbackTable, Threadless callback, Module-stomp
- **Window-message:** PROP_PROPAGATE, Extra Window Memory
- **Process manipulation:** Process Hollowing, PoolParty, NtMapViewOfSection

### Stealth Hardening

Every injection path routes through `vh::inject_stealth` — a shared helper layer that replaces Win32 APIs with indirect syscalls:

| Win32 API | VanHooks replacement | NT syscall |
|---|---|---|
| `OpenProcess` | `vh_open_process` | `NtOpenProcess` |
| `VirtualAllocEx` | `vh_alloc_remote` | `NtAllocateVirtualMemory` |
| `WriteProcessMemory` | `vh_write_remote` | `NtWriteVirtualMemory` |
| `ReadProcessMemory` | `vh_read_remote` | `NtReadVirtualMemory` |
| `VirtualFreeEx` | `vh_free_remote` | `NtFreeVirtualMemory` |
| `VirtualProtectEx` | `vh_protect_remote` | `NtProtectVirtualMemory` |
| `CreateRemoteThread` | `vh_create_thread` | `NtCreateThreadEx` |
| `OpenThread` | `vh_open_thread` | `NtOpenThread` |
| `CloseHandle` | `vh_close` | `NtClose` |
| `CreateToolhelp32Snapshot` | `vh_find_thread` | `NtQuerySystemInformation` |
| — | `vh_queue_apc` | `NtQueueApcThread` |
| — | `vh_write_shellcode` | alloc RW → write → flip RX |

All syscalls execute at ntdll gadget addresses (indirect mode), so the kernel-mode callback stack shows a legitimate ntdll return address. `PAGE_EXECUTE_READWRITE` is never allocated — shellcode goes through the `vh_write_shellcode` helper which allocates RW, writes, then flips to RX.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ❌ Error Handling

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🏭 Multi-Module Projects — HookRegistry

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 🌐 Platform Support

| Platform | x86 | x64 | ARM64 |
|---|---|---|---|
| Windows | ✓ | ✓ | Build from source |
| Linux | — | ✓ | ✓ |
| macOS | — | ✓ | ✓ |

Precompiled `.lib` files are provided for Windows x86 and x64. ARM64 and POSIX targets require a source build — see [`lib/README.md`](lib/README.md).

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📁 Package Layout

```
VanHooksSDK/
├── include/
│   ├── vh/                         ← public API headers (.vh)
│   │   ├── vh.vh                   ← single-include entry point
│   │   ├── config.vh               ← build configuration
│   │   ├── hook.vh                 ← Hook type and RAII lifetime
│   │   ├── group.vh                ← batch lifecycle management
│   │   ├── mid.vh                  ← mid-function hooks
│   │   ├── inject.vh               ← core 4 injection methods
│   │   ├── inject_unified.vh       ← full 24-technique catalogue
│   │   └── ...                     ← every public header
│   └── vanhooks/                   ← implementation headers
│       └── vanhooks.vh
├── lib/
│   ├── win-x64/{Release,Debug}/    vanhooks.lib
│   └── win-x86/{Release,Debug}/    vanhooks.lib
├── VanHooks_Functions_Guide.md     ← complete API reference
├── LICENSE
└── README.md
```

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## 📖 Documentation

- **[VanHooks_Functions_Guide.md](VanHooks_Functions_Guide.md)** — Complete API reference: every function, every configuration field, every error code. Includes the injection API and stealth helpers.
- **[lib/README.md](lib/README.md)** — Precompiled library matrix, MSVC project setup, and build-from-source instructions for ARM64 and POSIX.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:0D0D0D,50:DC2626,100:0D0D0D&height=3"/>

## ⚖️ License

This SDK — the public headers and prebuilt libraries — is released under the **MIT License**. See [LICENSE](LICENSE).

### Source License

The full VanHooks source code is available under a **commercial source license**. A source license gives you access to the complete implementation, the ability to build custom configurations, target additional architectures, and integrate VanHooks into proprietary toolchains.

For pricing and licensing inquiries, contact **[TeamVanilla](https://www.teamvanilla.org/)** or reach out on [Discord](https://discord.gg/TeJHcV9EJW).

<div align="center">

<sub>Built and maintained by <a href="https://github.com/TsyVM">TsyVM</a> · <a href="https://www.teamvanilla.org/">TeamVanilla</a></sub>

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:DC2626,100:0D0D0D&height=80&section=footer"/>

</div>
