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

[Glossary](#glossary) · [Result Type](#result-type) · [Level 1 API](#level-1-api) · [Level 2 API](#level-2-api) · [Hook Object](#hook-object) · [Group](#group) · [HookRegistry](#hookregistry) · [Config Structs](#config-structs) · [Error Codes](#error-codes) · [Pattern Scanner](#pattern-scanner) · [Anti-Debug Detection](#anti-debug-detection) · [Disassembler](#disassembler) · [Process Injection](#process-injection) · [Symbol Resolution](#symbol-resolution) · [PE Introspection](#pe-introspection) · [Breakpoints](#breakpoints) · [Call Stack Capture](#call-stack-capture) · [VanTrace](#vantrace) · [Network API](#network-api) · [Quick Reference](#quick-reference)

---

## Glossary

| Term | Meaning |
|---|---|
| **Hook** | Both the act of interception and the RAII object representing it. Owns the interception for its lifetime; removes it automatically on destruction. |
| **Target** | The function or address being intercepted. |
| **Detour** | Your replacement function. Must match the target's calling convention and signature exactly. |
| **Original** | A function pointer VanHooks fills in so your detour can call through to the real function. |
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
```

Intercepts `target` so calls go to `detour`. No call-through.

### `vh::hook(target, detour, original_out)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(Fn* target, Fn* detour, Fn** original_out);
```

Same, but fills `*original_out` with the trampoline address.

```cpp
static int (*orig_add)(int, int) = nullptr;

int detour_add(int a, int b) {
    printf("add(%d, %d)\n", a, b);
    return orig_add(a, b);
}

auto r = vh::hook(&add, &detour_add, &orig_add);
```

### `vh::hook(module, symbol, detour, original_out)`

```cpp
template<typename Fn>
Result<Hook> vh::hook(std::string_view module,
                      std::string_view symbol,
                      Fn* detour,
                      Fn** original_out = nullptr);
```

Resolves `target` by module and symbol name, then installs an inline hook.

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
```

Patches the first bytes of `target` with a jump and builds a trampoline. Options: [`config::Trampoline`](#configtrampoline)

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

Patches a single slot in a C++ virtual function table. Slots are zero-indexed in declaration order.

```cpp
void** vtbl = *reinterpret_cast<void***>(swap_chain);

static HRESULT (STDMETHODCALLTYPE *orig_Present)(IDXGISwapChain*, UINT, UINT) = nullptr;

HRESULT STDMETHODCALLTYPE hk_Present(IDXGISwapChain* sc, UINT sync, UINT flags) {
    return orig_Present(sc, sync, flags);
}

auto r = vh::vtable_hook(vtbl, 8,
                         (void*)&hk_Present,
                         (void**)&orig_Present,
                         { .tag = "DXGI.Present" });
```

### `vh::iat_hook`

```cpp
Result<Hook> vh::iat_hook(std::string_view import_name,
                          void* detour,
                          config::IAT opts = {});
```

**Windows only.** Patches one IAT entry. Options: [`config::IAT`](#configiat)

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

Installs a callback at a byte offset inside a function. Does not redirect control flow — exposes CPU register state at that instruction boundary.

**`MidCallback` signature:**

```cpp
using MidCallback = void (*)(MidContext*) noexcept;
```

**`MidContext` fields (x64):** `rax`…`r15`, `rflags` — all `uint64_t`. Writes take effect when the callback returns.

```cpp
auto r = vh::mid_hook(game_update_ptr,
    [](vh::MidContext* ctx) noexcept {
        player_health = static_cast<int>(ctx->rax);
    },
    { .offset = 0x1C, .tag = "Game.HealthReadback" });
```

---

## Hook Object

Every creation function returns `Result<Hook>`. Move-only. The destructor calls `remove()` automatically.

### Lifecycle

| Method | Description |
|---|---|
| `enable()` | Activates the hook. Returns `*this`. |
| `disable()` | Deactivates without removing. Returns `*this`. |
| `remove()` | Permanently uninstalls. `valid()` returns `false` afterward. |

### Chaining

```cpp
Result<Hook> hook.chain(void* next_detour,
                        void** next_original_out = nullptr,
                        std::string tag = {})
```

Inserts a detour in front of an existing hook. Remove links before base hooks — `ChainOrderViolation` otherwise.

### Introspection

| Method | Return Type | Description |
|---|---|---|
| `valid()` | `bool` | Hook is installed and usable. |
| `enabled()` | `bool` | Hook is currently active. |
| `tag()` | `std::string` | Label set at creation, or empty. |
| `kind()` | `HookKind` | Which hook type this is. |
| `target()` | `void*` | Address of the original function. |
| `detour()` | `void*` | Address of the replacement function. |
| `trampoline()` | `void*` | Call-through trampoline. `nullptr` for IAT/PLT/VTable. |

---

## Group

Owns a collection of `Hook` objects. All lifecycle operations happen in a single thread-suspension window.

```cpp
auto grp = vh::group("GroupName");
grp.add(vh::vtable_hook(vtbl, 8,  (void*)&hk_Present))
   .add(vh::vtable_hook(vtbl, 16, (void*)&hk_Reset));

grp.enable();
grp.disable();
grp.remove_all();
```

| Method | Description |
|---|---|
| `add(Hook)` | Takes ownership. Returns `*this`. |
| `add(Result<Hook>)` | Silently skips errors. Returns `*this`. |
| `enable()` | Enables all hooks in one thread-suspension window. |
| `disable()` | Disables all hooks. |
| `remove_all()` | Removes and destroys all hooks. |
| `at(string_view tag)` | Find by tag. Throws `std::out_of_range` if not found. |
| `size()` | Number of hooks in the group. |
| `queue_enable()` / `queue_disable()` | Queue without flushing. |
| `apply()` | Flush all queued operations in one window. |

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
| `find_group(name)` | Returns pointer or `nullptr`. |
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

### `config::IAT`

```cpp
struct IAT {
    std::string_view module_name;   // module to patch (empty = all)
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
    size_t      offset      = 0;      // byte offset into target function
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

### `Engine::Config`

```cpp
vanhooks::Engine::Config cfg;
cfg.enable_integrity_watchdog = true;
cfg.watchdog_interval_ms      = 250;
cfg.suppress_etw              = true;   // Windows only
cfg.suppress_amsi             = true;   // Windows only
```

| Field | Default | Description |
|---|---|---|
| `allocator` | `nullptr` | Custom trampoline allocator. `nullptr` = default near-target. |
| `trampoline_pool_size` | `65536` | Bytes per pool slab. |
| `auto_flush_icache` | `true` | Flush instruction cache after each patch. |
| `enable_integrity_watchdog` | `false` | Start background integrity watchdog thread. |
| `watchdog_interval_ms` | `500` | Watchdog poll interval. |
| `suppress_etw` | `false` | Patch `EtwEventWrite` / `EtwEventWriteFull`. Windows only. |
| `suppress_amsi` | `false` | Patch `AmsiScanBuffer` / `AmsiScanString`. Windows only. |

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
| `Unsupported` | Operation not supported on this platform or architecture. |
| `OutOfRange` | Index or offset outside valid bounds. |
| `OsError` | OS call failed. |

### Memory

| Code | Meaning |
|---|---|
| `MemoryAllocationFailed` | Could not allocate trampoline memory. |
| `MemoryProtectFailed` | Could not change memory protection. |
| `MemoryReadFailed` | Could not read from target address. |
| `MemoryWriteFailed` | Could not write patch bytes. |
| `TrampolineNoSpace` | Prologue too short. Consider IAT/PLT. |

### Hook lifecycle

| Code | Meaning |
|---|---|
| `HookNotFound` | Handle refers to a removed or unknown hook. |
| `HookAlreadyExists` | Target already hooked. |
| `HookInstallFailed` | Install failed (usually a memory error). |
| `HookRemoveFailed` | Remove failed. |
| `HookAlreadyEnabled` | `enable()` on an active hook. |
| `HookAlreadyDisabled` | `disable()` on an inactive hook. |

### Thread / chain / PE / breakpoint

| Code | Meaning |
|---|---|
| `ThreadInPrologue` | Thread IP was inside stolen bytes; IP fixup applied. Informational. |
| `ChainOrderViolation` | Chain link removed before its base. |
| `TrampolineNoSpace` | Prologue insufficient for relocation. |
| `BreakpointSlotExhausted` | All DR0–DR3 slots occupied. |
| `PeInvalidHeader` | DOS/NT signature mismatch. |
| `CallstackCaptureFailed` | `RtlCaptureStackBackTrace` / `backtrace` returned 0. |

---

## Pattern Scanner

All in `vanhooks::scanner::`. Always available — no CMake flag required.

### `scan_pattern` — range scan

```cpp
Result<std::vector<uintptr_t>> scan_pattern(
    const void*      base,
    size_t           size,
    std::string_view ida_pattern);
```

`?` or `??` matches any byte.

### `scan_bytes` — exact bytes

```cpp
std::vector<uintptr_t> scan_bytes(
    const void*              base,
    size_t                   size,
    std::span<const uint8_t> needle);
```

### `scan_process` — process-wide (Windows)

```cpp
Result<std::vector<uintptr_t>> scan_process(std::string_view ida_pattern);
```

### `scan_module` — named module (Windows)

```cpp
Result<std::vector<uintptr_t>> scan_module(
    std::string_view module_name,
    std::string_view ida_pattern);
```

### `parse_pattern` — pre-compile for reuse

```cpp
Result<Pattern> parse_pattern(std::string_view input);
```

---

## Anti-Debug Detection

All in `vanhooks::antidebug::`. Always available.

### `check_all`

```cpp
vanhooks::antidebug::Report check_all();
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

### Techniques (Windows — 8 total)

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

On **Linux**: `ptrace(PTRACE_TRACEME)`.

Individual checks also available: `check_is_debugger_present()`, `check_remote_debugger()`, `check_debug_port()`, `check_heap_flags()`, `check_nt_global_flag()`, `check_close_handle_exception()`, `check_timing()`, `check_debugger_processes()`.

---

## Disassembler

Zydis-backed. Always available. Types in `vh::disasm::`.

```cpp
vh::disasm::Disassembler dis;

// Decode one instruction
auto insn = dis.decode_one(code_span, runtime_va);

// Decode enough to cover N bytes (prologue stealing)
auto insns = dis.decode_min_bytes(code_span, runtime_va, 14);

// Free functions
vh::disasm::decode_until_branch(fn_ptr, 128);
vh::disasm::decode_prologue(fn_ptr, 5);
vh::disasm::safe_copy_length(fn_ptr, 5);
vh::disasm::rewrite(insns, original_va, new_va);   // fix RIP-relative refs
vh::disasm::format_listing(insns);
```

**`Instruction` fields:** `address`, `length`, `kind` (`InsnKind`), `bytes[16]`, `absolute_target`, `mnemonic`.

**`InsnKind` values:** `Generic`, `Call`, `Jump`, `JumpConditional`, `Return`, `Nop`, `RipRelative`, `PcRelative`, `Privileged`.

---

## Process Injection

**Windows only. Requires `VH_INJECT_ENABLED`.**

```cpp
#include <vh/inject.hpp>

auto inj = vh::inject(pid, "C:\\payload.dll",
                      { .method = vh::InjectMethod::ManualMap });

auto inj2 = vh::inject_from_memory(pid, pe_bytes,
                                    { .method = vh::InjectMethod::ThreadHijack });

inj->eject();   // or let it destruct
```

| Method | Module-list entry | Remote thread | Stealth |
|---|:---:|:---:|:---:|
| `LoadLibrary` | ✓ | ✓ | Low |
| `ManualMap` | ✗ | ✓ (shellcode) | Medium |
| `ThreadHijack` | Configurable | ✗ | High |
| `ApcQueue` | Configurable | ✗ | High |

**`Injection` methods:** `eject()`, `valid()`, `pid()`, `method()`, `tag()`.

---

## Symbol Resolution

**Requires `VH_SYMBOLS_ENABLED`.** DbgHelp (Windows) / `dladdr` + libbacktrace (POSIX).

```cpp
#include <vh/symbols.hpp>

auto sym = vh::symbols::resolve(address);
if (sym)
    printf("%s + 0x%zx  [%s]\n",
           sym->name.c_str(), address - sym->address, sym->module.c_str());

auto addr = vh::symbols::find("NtQuerySystemInformation", "ntdll.dll");
auto loc  = vh::symbols::source_location(address);   // file + line

for (auto& line : vh::symbols::current_stack())
    puts(line.c_str());

vh::symbols::demangle(raw_name);
```

**`Symbol` fields:** `name`, `raw_name`, `address`, `size`, `module`, `file`, `line`.

---

## PE Introspection

**Windows only. Requires `VH_PE_ENABLED`.**

```cpp
#include <vh/pe.hpp>

auto pe = vh::pe::open("ntdll.dll");

// Sections
for (auto& s : pe->sections().value_or({}))
    printf("%-8s  VA=0x%llx  %c%c%c\n",
           s.name.c_str(), s.virtual_address,
           s.readable() ? 'R' : '-',
           s.writable() ? 'W' : '-',
           s.executable() ? 'X' : '-');

// Exports
auto exp = pe->find_export("NtQuerySystemInformation");
auto exp2 = pe->find_export_by_ordinal(42);

// Imports
auto imports = pe->imports_from("kernel32.dll");
auto imp = pe->find_import("kernel32.dll", "VirtualProtect");

// Code caves
for (auto& cave : pe->find_caves(32, /*exec_only=*/true))
    printf("cave @ 0x%llx  %zu bytes  [%s]\n",
           cave.address, cave.size, cave.section_name.c_str());

// All loaded modules
auto mods = vh::pe::modules();
```

**Factories:** `vh::pe::open(name)`, `vh::pe::open_at(base)`, `vh::pe::open_handle(HMODULE)`, `vh::pe::modules()`.

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

hw->apply_to_new_thread(GetCurrentThread()); // Windows, hardware only
```

**`Action`:** `Continue` (re-arm) · `Remove` (one-shot)

**`HwCondition`:** `Execute` · `Write` · `ReadWrite`

**`HwSize`:** `Byte` · `Word` · `Dword` · `Qword` (x64 only)

**`Breakpoint` methods:** `remove()` · `active()` · `address()` · `apply_to_new_thread(HANDLE)`

---

## Call Stack Capture

**Requires `VH_CALLSTACK_ENABLED`.**

```cpp
#include <vh/callstack.hpp>

auto frames = vh::callstack::capture(/*skip=*/2, /*max_depth=*/32);
for (auto addr : frames.value_or({}))
    printf("  0x%016llx\n", addr);

// Annotated (requires VH_SYMBOLS_ENABLED)
auto ann = vh::callstack::capture_annotated();
puts(vh::callstack::format(ann.value()).c_str());
```

---

## VanTrace

Structured runtime event tracing. Lock-free ring buffer, background consumer, pluggable sinks. **Requires `VH_TRACE_ENABLED`.**

```cpp
#include <vh/trace.hpp>   // or <vh/vh.hpp> with VH_TRACE_ENABLED
```

### Lifecycle

```cpp
vh::Tracer tracer;                          // construct (no thread yet)
tracer.set_sink(my_sink);                   // install a sink
tracer.set_filter(my_filter);               // optional: pre-buffer gate
tracer.start();                             // start consumer thread
// ... install hooks and attach them ...
tracer.stop();                              // flush + join consumer
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

```cpp
// Cooperative (default) — detour calls enter()/exit() manually
auto h = vh::hook("d3d9.dll", "EndScene", &hk_EndScene, &orig_EndScene).value();
static vh::AttachedHook g_hook = tracer.attach(h).value();

// Transparent — VanTrace auto-instruments; detour unchanged
// entry + exit recorded via internal mid hooks; x64 exit, degrades to entry-only elsewhere
static vh::AttachedHook g_hook2 = tracer.attach(
    h,
    "d3d9.EndScene",                                   // optional tag override
    vanhooks::trace::AttachMode::Transparent
).value();

// Transparent entry-only — no exit recording
static vh::AttachedHook g_hook3 = tracer.attach(
    h, {}, vanhooks::trace::AttachMode::TransparentEntry
).value();
```

### `AttachMode`

| Value | Description |
|---|---|
| `AttachMode::Cooperative` | Detour calls `enter()` / `exit()` (or holds `CallScope`) manually. All platforms. Default. |
| `AttachMode::Transparent` | Internal stubs auto-record entry + exit. x64 exit only; degrades gracefully. |
| `AttachMode::TransparentEntry` | Auto-record entry only. All platforms. |

### Cooperative usage — `CallScope`

```cpp
static vh::AttachedHook g_es_hook;

HRESULT __stdcall hk_EndScene(IDirect3DDevice9* dev) {
    vh::CallScope scope(g_es_hook);   // HookEnter recorded here
    return orig_EndScene(dev);        // HookExit recorded on scope exit
}
```

Or manual if you need the timestamp:

```cpp
HRESULT __stdcall hk_EndScene(IDirect3DDevice9* dev) {
    auto ts = g_es_hook.enter();           // HookEnter recorded
    HRESULT hr = orig_EndScene(dev);
    g_es_hook.exit(ts);                    // HookExit recorded with duration
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
    g_hook.capture_context(desc, sizeof(*desc)); // stored before enter()
    vh::CallScope scope(g_hook);                 // context attached to this event
    return orig(dev, desc, ...);
}
// In the sink: ev.has_context == true, ev.context.data has the raw bytes
```

`kRawContextCapacity` is 64 bytes. Larger captures are truncated silently.

### Filters

Pre-buffer gate — events that fail the filter never enter the ring:

```cpp
vh::TraceFilter f;
f.include_handles  = { h1.handle(), h2.handle() }; // only these hooks (empty = all)
f.include_kinds    = { vanhooks::HookKind::Trampoline }; // only trampoline (empty = all)
f.include_threads  = { GetCurrentThreadId() };     // only this thread (empty = all)
f.min_duration     = std::chrono::microseconds(100); // HookExit only: >=100 µs
f.sample_every_n   = 10;                           // every 10th call per hook

tracer.set_filter(f);
```

### Configuration

```cpp
vanhooks::trace::TracerConfig cfg;
cfg.ring_capacity    = 8192;  // must be power of two; default 4096
cfg.overflow_policy  = vanhooks::trace::OverflowPolicy::BlockNewer; // or DropOldest
cfg.enable_timing    = true;  // timestamp + duration; false saves two clock reads/event
cfg.enable_thread_id = true;  // OS thread ID; false saves one syscall/event
cfg.enable_call_depth = true; // per-thread nesting depth

vh::Tracer tracer(cfg);
```

| `OverflowPolicy` | Behaviour when ring is full |
|---|---|
| `BlockNewer` | Drop the incoming event. Default. |
| `DropOldest` | Overwrite the oldest unconsumed event. |

### `TraceEvent` fields

| Field | Type | Description |
|---|---|---|
| `kind` | `TraceEventKind` | `HookEnter`, `HookExit`, `TraceDropped` |
| `hook_kind` | `HookKind` | Trampoline / IAT / PLT / VTable / Mid |
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

### Custom sink example — binary log file

```cpp
class BinaryFileSink : public vh::ISink {
public:
    explicit BinaryFileSink(const char* path)
        : f_(fopen(path, "wb")) {}
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

### Detaching

```cpp
tracer.detach(g_hook.meta().handle);   // by HookHandle
tracer.detach(h);                      // by vh::Hook (wrapper overload)
```

After detach, the `AttachedHook` becomes invalid (`valid() == false`). Outstanding `CallScope` objects that were in flight at detach time complete normally.

---

## Network API

Requires `VH_NET_ENABLED` and Npcap / libpcap. Types in `vh::net::` / `vanhooks::net::`.

### Devices

```cpp
for (const auto& d : vh::net::devices())
    printf("%-20s %s\n", d.name.c_str(), d.ip4.c_str());
```

### Live capture

```cpp
auto cap = vh::net::Capture::open("eth0");   // or open_by_ip("10.0.0.5")
cap->filter("tcp port 443")
   .snap_len(65535)
   .promiscuous(true);

cap->start([](vh::net::Packet p) {
    auto parsed = p.parse();
    if (auto* tcp = parsed->getLayerOfType<vanhooks::net::TcpLayer>())
        printf("%u -> %u\n", tcp->getSrcPort(), tcp->getDstPort());
});

cap->stop();
auto s = cap->stats();   // optional<Stats> — received, dropped, if_dropped
```

> ⚠️ The `Packet` passed to the callback is a non-owning view. Copy `raw_data()` if you need it after the callback returns.

### Offline files

```cpp
// Read
auto r = vh::net::PcapReader::open("dump.pcap");
r->filter("udp port 53");
while (auto pkt = r->next()) { /* process */ }

// Write
auto w = vh::net::PcapWriter::open("out.pcap");
w->write(pkt);
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
vh::plt_hook    ("lib", "sym", det)
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

**VanTrace**
```cpp
vh::Tracer tracer(cfg);           // TracerConfig optional
tracer.set_sink(sink);            // ISink, NullSink, CallbackSink, or custom
tracer.set_filter(filter);        // TraceFilter — handles, kinds, threads, min_dur, sample_n
tracer.start();

// Attach modes
tracer.attach(h)                                           // Cooperative (default)
tracer.attach(h, "tag", AttachMode::Transparent)          // auto entry+exit
tracer.attach(h, "tag", AttachMode::TransparentEntry)     // auto entry only

// Inside cooperative detour
vh::CallScope scope(g_hook);      // RAII enter/exit
g_hook.capture_context(ptr, sz);  // attach raw bytes to next enter event

tracer.detach(g_hook.meta().handle);
auto s = tracer.stats();          // produced, consumed, dropped, overflows
tracer.stop();
```

**Pattern scanner**
```cpp
vanhooks::scanner::scan_pattern(base, size, "48 8B 05 ? ? ? ?");
vanhooks::scanner::scan_process("E8 ? ? ? ? 85 C0");
vanhooks::scanner::scan_module("game.exe", "48 89 5C 24 ?");
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
dis.decode_min_bytes(span, va, n);
vh::disasm::decode_until_branch(fn, 128);
vh::disasm::rewrite(insns, old_va, new_va);
vh::disasm::format_listing(insns);
```

**Injection (Windows, VH_INJECT_ENABLED)**
```cpp
vh::inject(pid, "payload.dll", { .method = vh::InjectMethod::ManualMap });
vh::inject_from_memory(pid, pe_bytes, { .method = vh::InjectMethod::ThreadHijack });
inj.eject();
```

**Symbols (VH_SYMBOLS_ENABLED)**
```cpp
vh::symbols::resolve(address);
vh::symbols::find("CreateFileW", "ntdll");
vh::symbols::source_location(address);
vh::symbols::current_stack();
vh::symbols::demangle(raw_name);
```

**PE (Windows, VH_PE_ENABLED)**
```cpp
auto pe = vh::pe::open("ntdll.dll");
pe->sections();    pe->find_export("Fn");    pe->find_import("k32", "VP");
pe->find_caves(32, true);
vh::pe::modules();
```

**Breakpoints (VH_BREAKPOINT_ENABLED)**
```cpp
vh::breakpoint::set_software(addr, cb);
vh::breakpoint::set_hardware(addr, HwCondition::Write, HwSize::Dword, cb);
bp.remove();    bp.active();    bp.apply_to_new_thread(h);
```

**Call stack (VH_CALLSTACK_ENABLED)**
```cpp
vh::callstack::capture(2, 32);
vh::callstack::capture_annotated();
vh::callstack::format(frames);
```

**Network (VH_NET_ENABLED)**
```cpp
vh::net::devices();
auto cap = vh::net::Capture::open("eth0");
cap->filter("tcp port 443").start([](vh::net::Packet p) { ... });
auto r = vh::net::PcapReader::open("in.pcap");
auto w = vh::net::PcapWriter::open("out.pcap");
```

---

<div align="center">
<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:0A0A0A,50:7A0C0C,100:0A0A0A&height=90&section=footer"/>
</div>
echo "Functions guide written"
