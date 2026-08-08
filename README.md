<div align="center">

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:000000,50:8B0000,100:000000&height=220&section=header&text=VanHooks&fontSize=70&fontColor=FF3B3B&animation=fadeIn&fontAlignY=35&desc=Modern%20C%2B%2B23%20Cross-Platform%20Function%20Hooking%20Library&descAlignY=55&descSize=18&descColor=CCCCCC"/>

<a href="#">
<img src="https://readme-typing-svg.demolab.com/?lines=Trampoline+%C2%B7+IAT+%C2%B7+PLT+%C2%B7+VTable+%C2%B7+Mid-Function;One+API.+Every+Platform.+Zero+Exceptions.;std%3A%3Aexpected+all+the+way+down.&font=Fira%20Code&center=true&width=650&height=45&color=FF3B3B&vCenter=true&size=22&pause=1800"/>
</a>

<br/>

[![License: MIT](https://img.shields.io/badge/License-MIT-FF3B3B?style=for-the-badge&labelColor=000000)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-FF3B3B?style=for-the-badge&labelColor=000000&logo=cplusplus&logoColor=FF3B3B)](https://en.cppreference.com/w/cpp/23)
[![Windows](https://img.shields.io/badge/Windows-x86%20%7C%20x64-FF3B3B?style=for-the-badge&labelColor=000000&logo=windows&logoColor=FF3B3B)](lib/)
[![Linux](https://img.shields.io/badge/Linux-x64%20%7C%20ARM64-FF3B3B?style=for-the-badge&labelColor=000000&logo=linux&logoColor=FF3B3B)](lib/)
[![macOS](https://img.shields.io/badge/macOS-x64%20%7C%20ARM64-FF3B3B?style=for-the-badge&labelColor=000000&logo=apple&logoColor=FF3B3B)](lib/)

<br/>

[![Stars](https://img.shields.io/github/stars/yourname/vanhooks?style=for-the-badge&color=FF3B3B&labelColor=000000)](../../stargazers)
[![Issues](https://img.shields.io/github/issues/yourname/vanhooks?style=for-the-badge&color=FF3B3B&labelColor=000000)](../../issues)
[![Last Commit](https://img.shields.io/github/last-commit/yourname/vanhooks?style=for-the-badge&color=FF3B3B&labelColor=000000)](../../commits)
[![Downloads](https://img.shields.io/github/downloads/yourname/vanhooks/total?style=for-the-badge&color=FF3B3B&labelColor=000000)](../../releases)

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

VanHooks is a production-grade, cross-platform function hooking library for C++23. It provides inline trampoline hooks, import table hooks, procedure linkage table hooks, virtual function table hooks, and mid-function register-context hooks — all through a single unified API backed by `std::expected` error handling and RAII lifetime management. A built-in network layer, **VanNet**, ships in the same library for live packet capture and protocol parsing.

<div align="center">

### 📑 Table of Contents

[Why VanHooks](#-why-vanhooks) · [Features](#-features-at-a-glance) · [Requirements](#️-requirements) · [Installation](#-installation) · [Quick Start](#-quick-start) · [Hook Types](#-hook-types) · [Lifetime & RAII](#️-hook-lifetime-and-raii) · [Groups](#️-groups--batch-lifecycle-management) · [Chaining](#-hook-chaining) · [Error Handling](#-error-handling) · [HookRegistry](#-multi-module-projects--hookregistry) · [VanNet](#-vannet--built-in-network-layer) · [Platform Support](#️-platform-support) · [Roadmap](#️-roadmap) · [FAQ](#-faq) · [Docs](#-documentation)

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
| **Built-in packet capture** | ✗ | ✗ | ✗ | ✗ | 🔴 **✓ (VanNet)** |

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ⚡ Features at a Glance

<div align="center">

| 🪝 | 🧵 | 🧩 | 📦 |
|:---:|:---:|:---:|:---:|
| **5 Hook Types** | **Zero Exceptions** | **RAII Everywhere** | **Single Header** |
| Trampoline · IAT · PLT · VTable · Mid-function | `std::expected` end to end | Hooks and groups clean up on scope exit | `#include <vh/vh.hpp>` and go |
| 🌐 | 🖥️ | ⚙️ | 🔗 |
| **VanNet Built-in** | **True Cross-Platform** | **C++23 Native** | **Chainable Hooks** |
| Live capture + full protocol parsing | Windows · Linux · macOS · ARM64 | Concepts, `expected`, modern idioms | Stack detours without losing the original |

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ⚙️ Requirements

| Requirement | Minimum |
|---|---|
| C++ standard | C++23 |
| MSVC | 19.38+ (Visual Studio 2022 17.8+) |
| GCC | 13+ |
| Clang | 17+ |
| CMake | 3.25+ (optional — drop-in use requires no build system) |
| Windows target | Windows 10 1903 / Windows Server 2019 |

> No runtime dependencies for the hooking engine. Zydis is compiled into the library.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📥 Installation

### Option A — Drop-in (precompiled, no build system required)

Copy `include/` into your project and link against the precompiled `.lib` for your target.

**Library selection:**

| Target | Configuration | Path |
|---|---|---|
| Windows x64 | Release | `lib/win-x64/Release/vanhooks.lib` |
| Windows x86 | Release | `lib/win-x86/Release/vanhooks.lib` |

All precompiled libs use a static CRT (`/MT` Release, `/MTd` Debug). No Visual C++ Redistributable is required. See [`lib/README.md`](lib/README.md) for MSVC project settings and ARM64 / Linux / macOS build-from-source instructions.

<details>
<summary><b>🔧 CMake (drop-in) — click to expand</b></summary>

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

</details>

<details>
<summary><b>🔧 MSVC project (manual) — click to expand</b></summary>

1. **Additional Include Directories** → add `include\`
2. **Additional Library Directories** → add `lib\win-x64\Release\` (adjust for arch/config)
3. **Additional Dependencies** → add `vanhooks.lib`
4. **Runtime Library** → `Multi-threaded (/MT)` for Release, `Multi-threaded Debug (/MTd)` for Debug

</details>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🩸 Quick Start

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🪝 Hook Types

VanHooks provides five hook types, all returning the same `Result<Hook>` type.

<details open>
<summary><b>Inline (trampoline) hook</b></summary>

Patches the first bytes of the target function with a jump. Works on any function whose prologue is large enough — 5 bytes on x86/x64, 16 bytes on ARM64.

```cpp
auto r = vh::inline_hook(&target, &detour, &orig, { .tag = "Module.Function" });
```

</details>

<details>
<summary><b>IAT hook — Windows</b></summary>

Patches an Import Address Table entry. Intercepts calls from a specific module without modifying the target function itself. Useful for short functions that cannot be safely inline-hooked.

```cpp
// Patch the IAT entry in a specific module
auto r = vh::iat_hook("MessageBoxW", (void*)&hk_mbw,
                      { .module_name = "my_app.exe", .tag = "IAT.MessageBoxW" });

// Patch every loaded module's IAT entry at once
auto hooks = vh::iat_hook_all("malloc", (void*)&hk_malloc);
```

</details>

<details>
<summary><b>PLT hook — Linux / macOS</b></summary>

Patches the Procedure Linkage Table (Linux) or lazy pointer (macOS) used by the dynamic linker. The POSIX equivalent of an IAT hook.

```cpp
auto r = vh::plt_hook("libc", "malloc", (void*)&hk_malloc, { .tag = "libc.malloc" });
```

</details>

<details>
<summary><b>VTable hook</b></summary>

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

</details>

<details>
<summary><b>Mid-function hook</b></summary>

Installs a hook at a byte offset inside a function. Does not redirect control flow — observes and optionally modifies CPU register state at that point, then continues original execution.

```cpp
auto r = vh::mid_hook(game_update_fn,
    [](vh::MidContext* ctx) noexcept {
        player_health = static_cast<int>(ctx->rax);
    },
    { .offset = 0x1C, .tag = "Game.HealthReadback" });
```

</details>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ♻️ Hook Lifetime and RAII

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🗂️ Groups — Batch Lifecycle Management

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ❗ Error Handling

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🧩 Multi-Module Projects — HookRegistry

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

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🌐 VanNet — Built-in Network Layer

**VanNet** is VanHooks' built-in network layer: live packet capture, offline
pcap/pcapng read/write, BPF filtering, and full protocol parsing, compiled
directly into `libvanhooks` alongside the hooking engine with no external
runtime dependencies of its own.

### Enable / disable

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release   # VH_ENABLE_NET=ON by default
cmake -B build -DVH_ENABLE_NET=OFF          # hooking only, smaller binary
```

### Quick start

```cpp
#include <vh/vh.hpp>   // VanNet pulled in automatically

// Hook a function
auto hook = vh::hook(&target, &detour);

// Capture packets from the same host
auto cap = vh::net::Capture::open("eth0");
if (cap) {
    cap->filter("tcp port 443");
    cap->start([](vh::net::Packet pkt) {
        printf("captured %zu bytes\n", pkt.raw_len());

        // Full layer-by-layer parse
        if (auto parsed = pkt.parse()) {
            auto* ip = parsed->getLayerOfType<vanhooks::net::IPv4Layer>();
            if (ip)
                printf("  src=%s\n", ip->getSrcIPAddress().to_string().c_str());
        }
    });
}
```

### API reference

| Type | Description |
|---|---|
| `vh::net::Capture` | RAII live capture. `open()` → `filter()` → `start(cb)` → `stop()` |
| `vh::net::PcapReader` | Read `.pcap` / `.pcapng` files packet by packet |
| `vh::net::PcapWriter` | Write raw or parsed packets to a `.pcap` file |
| `vh::net::Filter` | BPF expression builder |
| `vh::net::Packet` | Non-owning view returned in the callback; call `parse()` for full decode |
| `vh::net::devices()` | List all live-capture-capable interfaces |

All factory methods return `vh::Result<T>` (`std::expected<T, vh::Error>`),
matching the rest of the VanHooks API exactly.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🖥️ Platform Support

<div align="center">

| Platform | x86 | x64 | ARM64 |
|:---:|:---:|:---:|:---:|
| 🪟 Windows | ✅ | ✅ | 🟡 Build from source |
| 🐧 Linux | — | ✅ | ✅ |
| 🍎 macOS | — | ✅ | ✅ |

</div>

Precompiled `.lib` files are provided for Windows x86 and x64. ARM64 and POSIX targets require a source build — see [`lib/README.md`](lib/README.md).

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## ❓ FAQ

<details>
<summary><b>Does VanHooks throw exceptions?</b></summary>
<br/>
No. Every fallible operation returns <code>vh::Result&lt;T&gt;</code> (<code>std::expected&lt;T, vh::Error&gt;</code>). The library never throws from its own code paths.
</details>

<details>
<summary><b>Do I need CMake to use VanHooks?</b></summary>
<br/>
No — drop-in usage only requires copying <code>include/</code> and linking the precompiled <code>.lib</code>. CMake is optional and mainly useful for ARM64/POSIX source builds or VanNet configuration.
</details>

<details>
<summary><b>Can I use VanHooks without VanNet?</b></summary>
<br/>
Yes. Build with <code>-DVH_ENABLE_NET=OFF</code> to exclude the packet capture and protocol parsing layer entirely, producing a smaller binary with only the hooking engine.
</details>

<details>
<summary><b>What happens if I hook a function that's already hooked by another library?</b></summary>
<br/>
Behavior depends on hook type and installation order. Use <code>HookRegistry</code> and <code>tag()</code> to track ownership across modules, and prefer <code>chain()</code> over re-hooking the same target directly.
</details>

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 📚 Documentation

- **[VanHooks_Functions_Guide.md](VanHooks_Functions_Guide.md)** — Complete API reference: every function, every configuration field, every error code.
- **[lib/README.md](lib/README.md)** — Precompiled library matrix, MSVC project setup, and build-from-source instructions for ARM64 and POSIX.

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-FF3B3B?style=for-the-badge&labelColor=000000)](../../pulls)

<img width="100%" src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,50:8B0000,100:000000&height=3&section=header"/>

<div align="center">

## 📄 License

**MIT** — see [LICENSE](LICENSE)

### ⭐ Star History

<a href="https://star-history.com/#yourname/vanhooks&Date">
  <img src="https://api.star-history.com/svg?repos=yourname/vanhooks&type=Date&theme=dark" width="60%"/>
</a>

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:000000,50:8B0000,100:000000&height=120&section=footer"/>

</div>
