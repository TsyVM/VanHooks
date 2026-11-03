#pragma once

/**
 * VanHooks - Modern C++23 Function Hooking Library
 * Architecture: x86, x64, ARM64
 * Backends: Trampoline (inline), IAT, PLT/GOT
 */

#include <cstdint>
#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <span>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <mutex>

namespace vanhooks {

// ─────────────────────────────────────────────
//  Version
// ─────────────────────────────────────────────

inline constexpr int VERSION_MAJOR = 0;
inline constexpr int VERSION_MINOR = 2;
inline constexpr int VERSION_PATCH = 0;
inline constexpr std::string_view VERSION_STRING = "0.2.0";

// Integer macros usable in preprocessor #if (constexpr ints are not).
// Form: major*10000 + minor*100 + patch  →  0.2.0 = 200
#define VH_VERSION_MAJOR 0
#define VH_VERSION_MINOR 2
#define VH_VERSION_PATCH 0
#define VH_VERSION       (VH_VERSION_MAJOR * 10000 + VH_VERSION_MINOR * 100 + VH_VERSION_PATCH)

// ─────────────────────────────────────────────
//  Platform detection
// ─────────────────────────────────────────────

#if defined(_WIN32) || defined(_WIN64)
    #define VH_PLATFORM_WINDOWS 1
#elif defined(__linux__)
    #define VH_PLATFORM_LINUX 1
#elif defined(__APPLE__)
    #define VH_PLATFORM_MACOS 1
#endif

#if defined(__x86_64__) || defined(_M_X64)
    #define VH_ARCH_X64 1
#elif defined(__i386__) || defined(_M_IX86)
    #define VH_ARCH_X86 1
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define VH_ARCH_ARM64 1
#endif

// ─────────────────────────────────────────────
//  Error types
// ─────────────────────────────────────────────

enum class Error : uint32_t {
    // General
    Ok                      = 0,
    NotInitialized          = 1,
    AlreadyInitialized      = 2,
    InvalidArgument         = 3,
    Unsupported             = 4,
    OutOfRange              = 5,
    OsError                 = 6,
    InvalidAddress          = 7,   // byte at address is not the expected opcode

    // Memory
    MemoryAllocationFailed  = 100,
    MemoryProtectFailed     = 101,
    MemoryReadFailed        = 102,
    MemoryWriteFailed       = 103,
    TrampolineNoSpace       = 104,

    // Hook lifecycle
    HookNotFound            = 200,
    HookAlreadyExists       = 201,
    HookInstallFailed       = 202,
    HookRemoveFailed        = 203,
    HookAlreadyEnabled      = 204,
    HookAlreadyDisabled     = 205,

    // Disassembly
    DisassemblyFailed       = 300,
    InstructionTooShort     = 301,
    UnsupportedInstruction  = 302,

    // Module / symbol
    ModuleNotFound          = 400,
    SymbolNotFound          = 401,
    IATEntryNotFound        = 402,
    PLTEntryNotFound        = 403,
    EATEntryNotFound        = 404,
    GOTEntryNotFound        = 405,

    // Thread
    ThreadSuspendFailed     = 500,
    ThreadResumeFailed      = 501,
    ThreadInPrologue        = 502,  // a thread's IP is inside stolen prologue bytes

    // Batch / chain
    QueueEmpty              = 600,  // apply_queued called with nothing queued
    ChainBaseNotFound       = 601,  // base HookHandle passed to chain() is unknown
    ChainOrderViolation     = 602,  // chain link removed before its base

    // PE introspection
    PeInvalidHeader         = 700,  // DOS/NT signature mismatch or bad offset
    PeNoExportDirectory     = 701,  // module has no export directory
    PeNoImportDirectory     = 702,  // module has no import directory
    PeItemNotFound          = 703,  // named export/import/section not found

    // Breakpoints
    BreakpointAlreadySet    = 800,  // a breakpoint is already installed at this address
    BreakpointNotFound      = 801,  // no breakpoint exists at the given address
    BreakpointSlotExhausted = 802,  // all four hardware debug registers are in use
    BreakpointInstallFailed = 803,  // OS call to set/clear context failed

    // Call-stack capture
    CallstackCaptureFailed  = 900,  // RtlCaptureStackBackTrace / backtrace returned 0
};

std::string_view error_to_string(Error e) noexcept;

template<typename T>
using Result = std::expected<T, Error>;

// Convenience: success with no value
using Status = Result<void>;

// ─────────────────────────────────────────────
//  Hook handle (opaque)
// ─────────────────────────────────────────────

struct HookHandle {
    uint64_t id = 0;
    bool valid() const noexcept { return id != 0; }
    explicit operator bool() const noexcept { return valid(); }
};

inline bool operator==(HookHandle a, HookHandle b) noexcept { return a.id == b.id; }

// ─────────────────────────────────────────────
//  Hook kind
// ─────────────────────────────────────────────

enum class HookKind : uint8_t {
    CallSite,               // Single CALL/JMP site displacement patch (E8/E9 rel32)
    Trampoline,             // Inline 5/14-byte patch + trampoline stub
    IAT,                    // Import Address Table redirect
    PLT,                    // Procedure Linkage Table redirect (Linux/macOS)
    GOT,                    // Global Offset Table redirect (Linux/macOS; already-resolved slots)
    VTable,                 // Virtual function table pointer swap
    Mid,                    // Mid-function hook at arbitrary instruction boundary
    HwBp,                   // Hardware breakpoint (DR0-DR3 + VEH); no memory write; Windows/x64 only
    PageGuard,              // PAGE_GUARD VEH trap; no inline patch; Windows only
    InstrumentationCallback,// Nirvana IC - kernel-to-user transition hook; Windows x64 only
    DelayIAT,               // Delay-load Import Address Table redirect (Windows only)
    SoftBp,                 // Software breakpoint (0xCC / BRK) via VEH; first-class alias for veh_hook
    EAT,                    // Export Address Table hook; patches callee's export slot
    Syscall,                // Syscall gate hook; intercepts Nt* stubs before kernel transition (Windows x64)
    TlsCallback,            // TLS callback table hook; fires before DllMain
    Exception,              // Arbitrary exception-code VEH filter hook
    ThreadLocal,            // Per-thread active trampoline hook (TLS-flag gated detour)
};

// ─────────────────────────────────────────────
//  Mid-function hook: register context
//  Passed by pointer to MidCallback; contains
//  saved GPRs and flags at the hook site.
// ─────────────────────────────────────────────

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4324) // structure padded due to alignment specifier
#endif
struct alignas(8) MidContext {
#if defined(VH_ARCH_X64)
    // Pushed in this order (highest → lowest address on the stack):
    // rax, rcx, rdx, rbx, rbp, rsi, rdi, r8..r15, rflags
    // Laid out so index 0 = rflags (top of saved area), matching push order.
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint64_t rflags;   // saved by PUSHFQ, restored by POPFQ
#elif defined(VH_ARCH_ARM64)
    // Full 64-bit GPR file: x0..x28, fp (x29), lr (x30).
    // x29/fp and x30/lr stored by name for readability at call sites.
    // x8..x28 were previously absent — they carry calling-convention scratch
    // values and (on Apple Silicon) hot-path float intermediates.
    uint64_t x[29];    // x0..x28  (offsets 0..224)
    uint64_t fp;       // x29 frame pointer (offset 232)
    uint64_t lr;       // x30 link register  (offset 240)
    uint64_t sp;       // stack pointer at hook site (offset 248)
    uint64_t nzcv;     // condition flags (offset 256)
    uint64_t fpcr;     // FP control register (offset 264)
    uint64_t fpsr;     // FP status register  (offset 272)
    // 128-bit NEON/SVE registers v0..v31.
    // Each stored as two uint64_t (lo, hi) so the struct stays POD.
    // v0..v7 are argument/result registers; v8..v15 are callee-saved;
    // v16..v31 are caller-saved scratch — all captured for full fidelity.
    uint64_t v[32][2]; // v[n][0]=lo64, v[n][1]=hi64 (offset 280..792)
#elif defined(VH_ARCH_X86)
    // The x86 stub is PUSHFD then PUSHA, and the callback is handed the ESP
    // that results -- so this struct must describe exactly what PUSHA writes.
    //
    // PUSHA pushes EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, each decrementing
    // the stack, so ascending from the pointer the callback receives the order
    // is EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX -- EIGHT dwords -- and EFLAGS
    // from the PUSHFD sits above them.
    //
    // This declared seven, omitting the ESP slot. Everything from EBX up was
    // therefore reading the register below it: `ebx` returned ESP, `edx`
    // returned EBX, `ecx` returned EDX, `eax` returned ECX, and `eflags`
    // returned EAX. EFLAGS itself was outside the struct. Only x86 was
    // affected; the x64 layout has no equivalent slot and was always right.
    //
    // `esp` is the stack pointer as PUSHA saw it, which is the value at the
    // hook site minus the four bytes PUSHFD had already pushed. Add 4 to get
    // the site's own ESP.
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t eflags;
#endif
};
#ifdef _MSC_VER
#pragma warning(pop)
#endif

// Callback invoked at the hook site with the saved register context.
// Must be noexcept — runs with a modified stack frame.
using MidCallback = void (*)(MidContext*) noexcept;

// ─────────────────────────────────────────────
//  Return-hook context and callbacks
//
//  hook_mid_return() installs an entry thunk (via hook_mid at byte_offset)
//  plus a shared return stub.  When the hooked function returns:
//
//    1. The entry thunk captures the real return address from the stack
//       and replaces it with the return stub's address.
//    2. The return stub fires with a ReturnContext* holding the return
//       value registers and the real return address.
//    3. user_return_cb() may modify ctx->retval_* before the stub
//       jumps to the original return target.
//
//  x64 only.  ARM64/x86 return Error::Unsupported.
// ─────────────────────────────────────────────

struct ReturnContext {
#if defined(VH_ARCH_X64)
    uint64_t retval_rax;   // primary integer / pointer return value
    uint64_t retval_rdx;   // second half of 128-bit return / ignored
    // xmm0 carries float/double/SSE return values (low 64 bits = double lane).
    // xmm1 carries the upper half of __m128 / pair-of-float returns; some
    // calling convention extensions (e.g. Clang vector ABI) also use it for
    // a second float result.  Both are now captured so callers can observe and
    // modify the full vector return without truncation.
    double   retval_xmm0;  // XMM0 low 64 bits
    double   retval_xmm1;  // XMM1 low 64 bits
    uint64_t hook_id;      // stable hook identifier (matches HookHandle::id)
    uint64_t real_ret_addr;// the caller's actual return address
#elif defined(VH_ARCH_ARM64)
    // Full ARM64 return register set.
    // x0/x1 carry integer/pointer results (or the two halves of a 128-bit int).
    // v0/v1 carry floating-point, NEON, and short-vector results.
    // x8 carries an indirect result location pointer when the callee writes a
    // large struct through it — captured so callers can intercept that path.
    uint64_t retval_x0;
    uint64_t retval_x1;
    uint64_t retval_x8;    // indirect result pointer (sret); 0 if unused
    uint64_t retval_v0[2]; // v0 lo/hi 64-bit lanes
    uint64_t retval_v1[2]; // v1 lo/hi 64-bit lanes
    uint64_t hook_id;
    uint64_t real_ret_addr;
#elif defined(VH_ARCH_X86)
    uint32_t retval_eax;
    uint32_t retval_edx;
    uint32_t hook_id;
    uint32_t real_ret_addr;
#endif
};

// Called at function entry (same thread, same call frame).
// ctx  — register snapshot at the hook site.
// Nullable: pass nullptr to observe entry only through hook_mid semantics.
using MidReturnEnterCallback = void (*)(MidContext* ctx) noexcept;

// Called when the hooked function returns, before control goes back to the
// original caller.  May modify ctx->retval_* to change the return value.
using ReturnCallback = void (*)(ReturnContext* ctx) noexcept;

// ─────────────────────────────────────────────
//  Hook descriptor
// ─────────────────────────────────────────────

struct HookDesc {
    HookHandle  handle;
    HookKind    kind;
    void*       target;       // original function address
    void*       detour;       // replacement function address
    void*       trampoline;   // callable original (trampoline hooks only)
    bool        enabled;
    std::string tag;          // optional human-readable label
};

// ─────────────────────────────────────────────
//  Trampoline hook options
// ─────────────────────────────────────────────

// TrampolineOptions is kept for backward compatibility.
// Prefer vh::config::Trampoline — it is the canonical type.
// Both have the same layout; TrampolineOptions is a deprecated alias.
struct TrampolineOptions {
    bool        thread_safe     = true;   // suspend threads during patch
    std::string tag;
};
// Note: vh::config::Trampoline (in vh/config.vh) mirrors this struct exactly.
// New code should use vh::config::Trampoline. A static_assert in vh/config.vh
// verifies that both types remain field-compatible.

// ─────────────────────────────────────────────
//  IAT hook options
// ─────────────────────────────────────────────

struct IATOptions {
    std::string module_name;  // module containing the IAT (empty = all loaded)
    std::string import_name;  // symbol name to redirect
    std::string tag;
};

// ─────────────────────────────────────────────
//  PLT hook options (Linux/macOS)
// ─────────────────────────────────────────────

struct PLTOptions {
    std::string library_name; // shared object name
    std::string symbol_name;
    std::string tag;
};

// ─────────────────────────────────────────────
//  VTable hook options
// ─────────────────────────────────────────────

struct VTableOptions {
    void**      vtable;       // pointer to vtable array
    size_t      slot_index;   // which slot to patch
    std::string tag;
};

// ─────────────────────────────────────────────
//  CallSite hook options
//
//  A callsite hook patches the 32-bit relative displacement of a single
//  CALL (E8) or JMP (E9) instruction, redirecting only that call site to
//  a detour function without touching the target function's prologue.
//  The original function remains reachable through *orig_fn.
//
//  Primary target: x86 (32-bit Windows) — NFS: Most Wanted, GTA: SA.
//  x64: returns Error::TrampolineNoSpace if &detour is outside ±2 GB.
//  ARM64: returns Error::Unsupported.
// ─────────────────────────────────────────────

struct CallSiteOptions {
    bool        thread_safe = true;  // suspend threads during patch window
    std::string tag;                 // forwarded to Hook for VanTrace / registry lookup
};

// ─────────────────────────────────────────────
//  HwBp hook options  (Hardware Breakpoint via DR0-DR3 + VEH)
//
//  Windows x64 only.  On POSIX / ARM64 returns Error::Unsupported.
//  Up to 4 HwBp hooks may be active simultaneously (DR0-DR3 limit).
// ─────────────────────────────────────────────

struct HwBpOptions {
    // Which debug register to use (0-3). Engine picks the first free one
    // if left at sentinel value 0xFF.
    uint8_t     dr_slot = 0xFF;
    std::string tag;
};

// ─────────────────────────────────────────────
//  PageGuard hook options  (PAGE_GUARD VEH trap)
//
//  Windows only.  On POSIX, returns Error::Unsupported.

// ─────────────────────────────────────────────

// Condition under which the guard trap fires.
enum class PageGuardCondition : uint8_t {
    Execute = 0,   // fires on instruction fetch from the page
    Read    = 1,   // fires on any read access
    Write   = 2,   // fires on any write access
    Any     = 3,   // fires on any access
};

struct PageGuardOptions {
    PageGuardCondition  condition   = PageGuardCondition::Execute;
    bool                auto_rearm  = true;   // re-apply PAGE_GUARD after each trip
    std::string         tag;
};

// ─────────────────────────────────────────────
//  Nirvana Instrumentation Callback options
//
//  Windows x64 only.  Returns Error::Unsupported on all other platforms.
//  Process-wide singleton: only one IC callback per process.
//  Second install returns Error::HookAlreadyExists.
// ─────────────────────────────────────────────

// Called on every kernel-to-user-mode transition. R10 contains the return
// address of the original syscall site; RSP points to the user-mode stack.
// The callback must be a naked or __declspec(noreturn) asm stub in practice;
// this is the C++ declaration for registration only.
using ICCallback = void (*)(void) noexcept;

struct ICOptions {
    std::string tag;
};

// ─────────────────────────────────────────────
//  EAT hook options  (Export Address Table)
//
//  Patches the export address table slot of a named export in the target
//  module, redirecting all future dynamic callers who resolve the export via
//  GetProcAddress / dlsym after the hook is installed.  Does NOT affect
//  already-resolved IAT slots — pair with hook_iat for complete coverage.
//  Windows only in this implementation; returns Error::Unsupported on POSIX.
// ─────────────────────────────────────────────

struct EATOptions {
    std::string module_name;  // e.g. "ntdll.dll" or "ntdll"
    std::string export_name;  // e.g. "NtProtectVirtualMemory"
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return !module_name.empty() && !export_name.empty();
    }
};

// ─────────────────────────────────────────────
//  GOT hook options  (Linux/macOS Global Offset Table)
//
//  Distinct from PLT: PLT redirect affects lazy-bound calls;
//  GOT redirect patches the already-resolved slot, affecting all callers
//  that go through the GOT pointer regardless of bind-now state.
// ─────────────────────────────────────────────

struct GOTOptions {
    std::string library_name; // shared object name, e.g. "libc"
    std::string symbol_name;  // e.g. "malloc"
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return !library_name.empty() && !symbol_name.empty();
    }
};

// ─────────────────────────────────────────────
//  Syscall hook options  (Windows x64 only)
//
//  Patches the syscall instruction site inside a named Nt* stub in ntdll,
//  intercepting the transition before it reaches the kernel.  Internally
//  this is a callsite hook on the `syscall` offset inside the stub.
//  Returns Error::Unsupported on non-Windows / non-x64.
// ─────────────────────────────────────────────

struct SyscallOptions {
    std::string function_name; // e.g. "NtProtectVirtualMemory"
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return !function_name.empty();
    }
};

// ─────────────────────────────────────────────
//  TLS callback hook options  (Windows only)
//
//  Patches a slot in the TLS callback table of a module, intercepting
//  callbacks that fire before DllMain on thread attach/detach.
//  slot = 0 patches the first registered callback; use larger indices
//  to reach subsequent ones (returns Error::OutOfRange if slot >= count).
// ─────────────────────────────────────────────

struct TlsCallbackOptions {
    void*       module_base = nullptr; // null = hosting module (self)
    size_t      slot        = 0;       // which TLS callback slot to patch
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Exception hook options  (Windows VEH — arbitrary exception code)
//
//  Installs a VEH that fires when the given exc_code is raised in any
//  address within [addr_low, addr_high).  Pass addr_high = 0 to match any
//  address.  The callback receives a MidContext* populated from the CONTEXT
//  at exception time.  Multiple exception hooks with the same code are
//  supported.
// ─────────────────────────────────────────────

struct ExceptionOptions {
    uint32_t    exc_code  = 0;                 // e.g. EXCEPTION_ACCESS_VIOLATION (0xC0000005)
    uintptr_t   addr_low  = 0;                 // filter range low  (0 = any)
    uintptr_t   addr_high = 0;                 // filter range high (0 = any)
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return exc_code != 0;
    }
};

// Exception callback: receives the thread context at throw time.
// Returns true to swallow (EXCEPTION_CONTINUE_EXECUTION), false to pass on.
using ExceptionCallback = bool (*)(MidContext* ctx, uint32_t code, uintptr_t addr) noexcept;

// ─────────────────────────────────────────────
//  Thread-local hook options
//
//  Installs a trampoline hook with a TLS flag in the detour prologue.
//  The hook is only logically active on threads that have called
//  hook_thread_local_enable() on the returned handle.  Other threads
//  pass straight through to the original function with ~2ns overhead
//  (a single TLS read + branch).
// ─────────────────────────────────────────────

struct ThreadLocalOptions {
    bool        thread_safe = true;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Allocator interface (replaceable)
// ─────────────────────────────────────────────

struct IAllocator {
    virtual ~IAllocator() = default;

    // Allocate executable memory near `hint` (within ±2GB for rel32 jumps)
    virtual Result<void*> alloc_near(void* hint, size_t size) = 0;

    // Allocate executable memory anywhere
    virtual Result<void*> alloc(size_t size) = 0;

    virtual void          free(void* ptr, size_t size) = 0;
};

// ─────────────────────────────────────────────
//  Core engine
// ─────────────────────────────────────────────

class Engine {
public:
    struct Config {
        std::shared_ptr<IAllocator> allocator;        // null = default
        size_t   trampoline_pool_size  = 65536;       // bytes per pool slab
        bool     auto_flush_icache     = true;        // flush instruction cache after patch

        // Integrity watchdog: background thread that detects kernel-driver hook removal
        // and reinstalls affected hooks.  Spawned via NtCreateThreadEx (Windows) so
        // CreateThread does not appear in the import table.
        bool     enable_integrity_watchdog = false;
        uint32_t watchdog_interval_ms      = 500;     // check period in milliseconds

        // Tier 3 user-mode suppression (Windows only; no-op on HVCI/VBS systems).
        // suppress_etw: patches ntdll!EtwEventWrite and EtwEventWriteFull to
        //   return STATUS_SUCCESS immediately, silencing user-mode ETW telemetry
        //   used by many EDR/AV products to detect API activity.
        // suppress_amsi: patches amsi.dll!AmsiScanBuffer and AmsiScanString to
        //   return AMSI_RESULT_CLEAN without scanning, bypassing the Anti-Malware
        //   Scan Interface.  No-op if amsi.dll is not loaded in the process.
        bool     suppress_etw              = false;
        bool     suppress_amsi            = false;

        // HwBp-path ETW/AMSI suppression (no byte patch; Windows x64 only).
        // Uses a hardware breakpoint on EtwEventWrite / AmsiScanBuffer instead of
        // patching .text bytes, evading EDR .text hash comparisons.
        // Mutually exclusive with suppress_etw / suppress_amsi on the same target.
#if defined(VH_PLATFORM_WINDOWS) && defined(VH_ARCH_X64)
        bool     suppress_etw_hwbp        = false;
        bool     suppress_amsi_hwbp       = false;
#endif

        // Called by the integrity watchdog when hook bytes are found tampered.
        // Receives the handle and kind of the affected hook. Invoked from the
        // watchdog background thread — implementation must be thread-safe.
        std::function<void(HookHandle, HookKind)> on_hook_tampered;

        // watchdog_check_mem_image: when true (and enable_integrity_watchdog is
        // true), each watchdog cycle calls vh::peb_mask::validate_mem_image()
        // on every module that owns an active hooked target.  A MEM_PRIVATE page
        // inside an image range is evidence that a kernel driver has rewritten
        // bytes inside what should be a clean mapped section — the same signal
        // CfAcCompat surfaces for HGWC detection.  The watchdog logs and fires
        // on_mem_image_violation for each offending module; it does NOT attempt
        // to fix the pages (that would require kernel privileges).
        // Windows only; silently ignored on POSIX.
        bool watchdog_check_mem_image = false;

        // Called when the watchdog detects MEM_PRIVATE pages inside a module's
        // image range.  Arguments: the module base address and the count of
        // private committed regions found.  Invoked from the watchdog background
        // thread — implementation must be thread-safe.
        std::function<void(void* module_base, uint32_t private_count)> on_mem_image_violation;

        // watchdog_check_trampoline_pool: when true (and enable_integrity_watchdog
        // is true), each watchdog cycle walks every known trampoline slot and
        // calls VirtualQuery on it to verify it is still MEM_COMMIT with
        // PAGE_EXECUTE_READ (or PAGE_EXECUTE_READWRITE on code-cave slots, which
        // carry the page protection of the host image section).
        //
        // Kernel-mode AC drivers sometimes remap trampoline pool pages to
        // PAGE_NOACCESS or free them entirely (MEM_FREE / MEM_RESERVE) rather
        // than restoring the bytes at the hook site, bypassing the per-byte
        // integrity check in the normal watchdog path.  This check surfaces that
        // class of removal before the engine tries to call through the bad slot.
        //
        // Windows only; silently ignored on POSIX.
        bool watchdog_check_trampoline_pool = false;

        // Called when the watchdog detects that a trampoline slot's page
        // protection or commit state has been changed unexpectedly.
        // Arguments: slot address, the hook handle it belongs to, and the
        // observed MBI state (as a MEMORY_BASIC_INFORMATION*).  Invoked from
        // the watchdog background thread — implementation must be thread-safe.
        std::function<void(void* slot, HookHandle handle, uint32_t observed_protect)>
            on_trampoline_pool_violation;
    };

    explicit Engine(Config cfg);
    Engine();   ///< Construct with default Config (equivalent to Engine(Config{}))
    ~Engine();

    Engine(const Engine&)            = delete;
    Engine& operator=(const Engine&) = delete;
    Engine(Engine&&)                 = default;
    Engine& operator=(Engine&&)      = default;

    // ── Trampoline (inline) hooks ──────────────

    [[nodiscard]]
    Result<HookHandle> hook_trampoline(
        void*                    target,
        void*                    detour,
        void**                   original_out = nullptr,
        TrampolineOptions        opts         = {}
    );

    // Typed convenience wrapper
    template<typename Fn>
    [[nodiscard]]
    Result<HookHandle> hook(Fn* target, Fn* detour, Fn** original_out = nullptr,
                            TrampolineOptions opts = {})
    {
        return hook_trampoline(
            reinterpret_cast<void*>(target),
            reinterpret_cast<void*>(detour),
            reinterpret_cast<void**>(original_out),
            std::move(opts)
        );
    }

    // Address-based convenience wrapper — accepts a raw uintptr_t target so
    // callers working with runtime-resolved addresses (pattern scans, version
    // tables) do not need to write a reinterpret_cast at every call site.
    //
    //   engine.hook(0x5D5DB0, &MyFunc);
    //   engine.hook(0x5E7859, &MyDetour, &orgFunc);
    template<typename Fn>
    [[nodiscard]]
    Result<HookHandle> hook(uintptr_t target, Fn* detour, Fn** original_out = nullptr,
                            TrampolineOptions opts = {})
    {
        return hook_trampoline(
            reinterpret_cast<void*>(target),
            reinterpret_cast<void*>(detour),
            reinterpret_cast<void**>(original_out),
            std::move(opts)
        );
    }

    // ── API hooks (resolve by module + symbol name) ───
    // Equivalent to MinHook MH_CreateHookApiEx.
    // Resolves target via GetModuleHandle/GetProcAddress (Windows) or
    // dlsym (POSIX), then installs a trampoline hook.

    [[nodiscard]]
    Result<HookHandle> hook_api(
        std::string_view  module_name,
        std::string_view  function_name,
        void*             detour,
        void**            original_out = nullptr,
        TrampolineOptions opts         = {}
    );

    template<typename Fn>
    [[nodiscard]]
    Result<HookHandle> hook_api(
        std::string_view  module_name,
        std::string_view  function_name,
        Fn*               detour,
        Fn**              original_out = nullptr,
        TrampolineOptions opts         = {})
    {
        return hook_api(module_name, function_name,
                        reinterpret_cast<void*>(detour),
                        reinterpret_cast<void**>(original_out),
                        std::move(opts));
    }

    // ── IAT hooks ─────────────────────────────

    // Patch the first IAT entry matching opts.import_name
    // (in opts.module_name if specified, otherwise the first loaded module that has it).
    [[nodiscard]]
    Result<HookHandle> hook_iat(void* detour, IATOptions opts);

    // Patch every IAT entry matching opts.import_name across all loaded modules.
    // Returns handles for each patched slot; useful for hooking CRT imports
    // that appear in multiple DLLs (e.g., malloc, VirtualAlloc).
    [[nodiscard]]
    Result<std::vector<HookHandle>> hook_iat_all(void* detour, IATOptions opts);

    // ── Delay-load IAT hooks ───────────────────
    //
    // Delay-loaded DLLs are described by IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
    // (directory 13), a separate data directory from the standard import
    // directory.  Windows populates the delay-load IAT lazily on first call
    // via __delayLoadHelper2.  hook_iat() silently does nothing against a
    // delay-loaded symbol — the standard import directory contains no entry
    // for it — and returns IATEntryNotFound.  hook_delay_iat() walks the
    // delay-import descriptor table instead.
    //
    // If the delay-load IAT slot has not yet been populated (the DLL has
    // never been called), hook_delay_iat() forces resolution by loading the
    // target DLL and resolving the symbol before patching, so the slot is
    // always valid by the time the detour is installed.
    //
    // Windows only; returns Error::Unsupported on POSIX.

    [[nodiscard]]
    Result<HookHandle> hook_delay_iat(void* detour, IATOptions opts);

    [[nodiscard]]
    Result<std::vector<HookHandle>> hook_delay_iat_all(void* detour, IATOptions opts);

    // ── PLT/GOT hooks ─────────────────────────

    [[nodiscard]]
    Result<HookHandle> hook_plt(void* detour, PLTOptions opts);

    // ── VTable hooks ──────────────────────────

    [[nodiscard]]
    Result<HookHandle> hook_vtable(void* detour, VTableOptions opts);

    // ── CallSite hooks ────────────────────────
    // Patch the 32-bit relative displacement of a single CALL (E8) or JMP (E9)
    // instruction at site_addr, redirecting only that one call site to detour.
    // The displaced original target is written to *original_out.
    //
    // Prefer the typed overload (Fn* site_addr) when the call site can be cast;
    // use the uintptr_t overload for runtime-resolved pattern-scan addresses.

    [[nodiscard]]
    Result<HookHandle> hook_callsite(
        uintptr_t         site_addr,
        void*             detour,
        void**            original_out = nullptr,
        CallSiteOptions   opts         = {}
    );

    template<typename Fn>
    [[nodiscard]]
    Result<HookHandle> hook_callsite(Fn* site_addr, Fn* detour,
                                     Fn** original_out = nullptr,
                                     CallSiteOptions opts = {})
    {
        return hook_callsite(
            reinterpret_cast<uintptr_t>(site_addr),
            reinterpret_cast<void*>(detour),
            reinterpret_cast<void**>(original_out),
            std::move(opts));
    }

    // ── Mid-function hooks ────────────────────
    // Install a hook at `byte_offset` bytes into `target`.  The actual patch
    // site is rounded up to the nearest complete instruction boundary (never
    // splits an instruction).  `callback` is called with a MidContext* that
    // holds a snapshot of all GPRs and flags at the hook site; the original
    // instructions are still executed after the callback returns.
    //
    // No original-out pointer is provided — mid hooks do not redirect control
    // flow; they observe/modify register state at a chosen program point.

    [[nodiscard]]
    Result<HookHandle> hook_mid(
        void*             target,
        size_t            byte_offset,
        MidCallback       callback,
        TrampolineOptions opts = {}
    );

    // Install a return hook at `byte_offset` bytes into `target`.
    //
    // `user_enter_cb` (nullable) is called with a MidContext* at function
    // entry, before the original instructions run — same semantics as hook_mid.
    //
    // `user_return_cb` is called every time the hooked scope returns,
    // with a ReturnContext* containing the return-value registers and the
    // real return address.  Return-value registers may be modified in-place.
    //
    // Internally this installs:
    //   • a hook_mid at `byte_offset` (the entry thunk)
    //   • a shared return stub allocated in the trampoline pool
    //
    // Both are tracked under the returned HookHandle; remove() cleans up both.
    // x64 only — returns Error::Unsupported on ARM64 and x86.
    [[nodiscard]]
    Result<HookHandle> hook_mid_return(
        void*                  target,
        size_t                 byte_offset,
        MidReturnEnterCallback user_enter_cb,   // nullable
        ReturnCallback         user_return_cb,
        TrampolineOptions      opts = {}
    );

    // ── Hardware Breakpoint hooks (HwBp / DR0-DR3 + VEH) ────────────────────
    //
    // No bytes are written to the target function.  Triggers on execution via
    // an EXCEPTION_SINGLE_STEP VEH.  Windows/x64 only; returns
    // Error::Unsupported on other platforms.  Max 4 active hooks (DR0-DR3).

    [[nodiscard]]
    Result<HookHandle> hook_hwbp(
        void*        target,
        MidCallback  callback,    // same MidContext* signature as hook_mid
        HwBpOptions  opts = {}
    );

    // ── PAGE_GUARD VEH trap hooks ─────────────────────────────────────────
    //
    // Sets PAGE_GUARD on the target's page via VirtualProtect and intercepts
    // EXCEPTION_GUARD_PAGE in a VEH.  Windows only; returns Unsupported on
    // POSIX.

    [[nodiscard]]
    Result<HookHandle> hook_page_guard(
        void*              target,    // any address in the page to guard
        MidCallback        callback,
        PageGuardOptions   opts = {}
    );

    // ── Nirvana Instrumentation Callback ──────────────────────────────────
    //
    // Sets KPROCESS.InstrumentationCallback via NtSetInformationProcess(0x28).
    // Fires on every kernel-to-user-mode transition (syscall return, APC,
    // exception).  Process-wide singleton: second install returns
    // Error::HookAlreadyExists.  Windows x64 only.

    [[nodiscard]]
    Result<HookHandle> hook_instrumentation_callback(
        ICCallback  callback,   // must be a valid executable stub
        ICOptions   opts = {}
    );

    // ── EAT hook — Export Address Table ──────────────────────────────────
    //
    // Patches the EAT slot of opts.export_name in opts.module_name.
    // Affects callers that resolve the symbol via GetProcAddress / dlsym
    // AFTER the hook is installed.  Does not affect already-resolved IAT slots.
    // Windows only; returns Error::Unsupported on POSIX.

    [[nodiscard]]
    Result<HookHandle> hook_eat(void* detour, EATOptions opts);

    // ── GOT hook — Global Offset Table (Linux/macOS) ──────────────────────
    //
    // Patches the already-resolved GOT slot for opts.symbol_name in the
    // DSO identified by opts.library_name.  Distinct from PLT: PLT patches
    // the lazy-bind thunk; GOT patches the resolved pointer directly.
    // Returns Error::Unsupported on Windows.

    [[nodiscard]]
    Result<HookHandle> hook_got(void* detour, GOTOptions opts);

    // ── Syscall gate hook (Windows x64 only) ─────────────────────────────
    //
    // Locates the `syscall` instruction inside the named Nt* stub in ntdll
    // and installs a callsite hook on that byte, intercepting transitions
    // before they reach the kernel.  Returns Error::Unsupported on non-Windows
    // / non-x64 platforms.

    [[nodiscard]]
    Result<HookHandle> hook_syscall(void* detour, SyscallOptions opts);

    // ── TLS callback hook (Windows only) ────────────────────────────────
    //
    // Patches a slot in the IMAGE_TLS_DIRECTORY callback table of opts.module_base
    // (or the hosting DLL if null).  Fires before DllMain on thread attach/detach.
    // Returns Error::Unsupported on POSIX.

    [[nodiscard]]
    Result<HookHandle> hook_tls_callback(void* detour, TlsCallbackOptions opts);

    // ── Exception hook — arbitrary exception code VEH ─────────────────────
    //
    // Installs a VEH that fires for opts.exc_code raised within
    // [opts.addr_low, opts.addr_high).  addr_high == 0 means "any address".
    // callback returns true to swallow, false to pass on.

    [[nodiscard]]
    Result<HookHandle> hook_exception(ExceptionCallback callback, ExceptionOptions opts);

    // ── Return hook — exposed at vh:: level ──────────────────────────────
    //
    // Convenience wrapper exposing hook_mid_return in a single call.
    // user_enter_cb may be null if entry observation is not needed.

    [[nodiscard]]
    Result<HookHandle> hook_return(
        void*                  target,
        MidReturnEnterCallback user_enter_cb,
        ReturnCallback         user_return_cb,
        TrampolineOptions      opts = {}
    ) {
        return hook_mid_return(target, 0, user_enter_cb, user_return_cb, std::move(opts));
    }

    template<typename Fn>
    [[nodiscard]]
    Result<HookHandle> hook_return(
        Fn*                    target,
        MidReturnEnterCallback user_enter_cb,
        ReturnCallback         user_return_cb,
        TrampolineOptions      opts = {})
    {
        return hook_return(reinterpret_cast<void*>(target),
                           user_enter_cb, user_return_cb, std::move(opts));
    }

    // ── Thread-local hook ────────────────────────────────────────────────
    //
    // Installs a trampoline hook with a per-thread TLS flag gating the detour.
    // Only threads that call hook_thread_local_enable(handle) see the detour;
    // all others fall through to the original with minimal overhead.

    [[nodiscard]]
    Result<HookHandle> hook_thread_local(
        void*               target,
        void*               detour,
        void**              original_out = nullptr,
        ThreadLocalOptions  opts = {}
    );

    template<typename Fn>
    [[nodiscard]]
    Result<HookHandle> hook_thread_local(
        Fn*               target,
        Fn*               detour,
        Fn**              original_out = nullptr,
        ThreadLocalOptions opts = {})
    {
        return hook_thread_local(reinterpret_cast<void*>(target),
                                 reinterpret_cast<void*>(detour),
                                 reinterpret_cast<void**>(original_out),
                                 std::move(opts));
    }

    // Enable / disable the thread-local hook for the CALLING thread only.
    void thread_local_enable (HookHandle handle) noexcept;
    void thread_local_disable(HookHandle handle) noexcept;

    // ── Lifecycle ─────────────────────────────

    [[nodiscard]] Status enable(HookHandle handle);
    [[nodiscard]] Status disable(HookHandle handle);
    [[nodiscard]] Status remove(HookHandle handle);

    [[nodiscard]] Status enable_all();
    [[nodiscard]] Status disable_all();
    [[nodiscard]] Status remove_all();

    // ── Batch queue API ───────────────────────
    // Queue operations and flush them within a single thread-suspension window.
    // Amortises Toolhelp32 / ptrace / task_threads overhead across many hooks.
    //
    //   eng.queue_enable(h1);
    //   eng.queue_enable(h2);
    //   eng.queue_disable(h3);
    //   eng.apply_queued();   // one suspension, all patches applied atomically

    void   queue_enable (HookHandle handle);
    void   queue_disable(HookHandle handle);
    void   queue_remove (HookHandle handle);
    [[nodiscard]] Status apply_queued();
    void   clear_queue() noexcept;
    size_t queue_size()  const noexcept;

    // ── Hook chaining ─────────────────────────
    // Chain a second detour onto an already-hooked target.
    // The new detour receives the previous detour's trampoline as its
    // "original", forming a linked list:
    //   target → detour_N → ... → detour_1 → original
    //
    // Returns a HookHandle that must be removed before the base hook.

    [[nodiscard]]
    Result<HookHandle> chain(HookHandle base,
                             void*      next_detour,
                             void**     next_original_out = nullptr,
                             std::string tag = {});

    // ── Internal thread-entry thunk ───────────
    // Called by the platform watchdog thread (NtCreateThreadEx on Windows,
    // std::thread on POSIX).  Public only so a static C-callable trampoline
    // in engine.cpp can reach it without declaring Windows types in this header.
    // Do not call directly.
    static void watchdog_thread_body(void* engine_ptr) noexcept;

    // ── IP fixup on remove ────────────────────
    // When removing a trampoline hook, if a suspended thread's instruction
    // pointer lands inside the stolen prologue bytes, advance it past the
    // patch so execution continues correctly in the restored original.
    // Effective only when thread_safe=true (default).
    bool ip_fixup_on_remove = true;

    // ── Address-based lookup ──────────────────
    // Find the handle of a hook installed on `target`.  Returns an invalid
    // handle if no hook exists for that address (check with .valid()).

    [[nodiscard]] HookHandle find_by_target(const void* target) const noexcept;

    // ── Introspection ─────────────────────────

    [[nodiscard]] std::optional<HookDesc> describe(HookHandle handle) const;
    [[nodiscard]] std::vector<HookDesc>   list_hooks() const;
    [[nodiscard]] size_t                  hook_count() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    void start_watchdog();
    void stop_watchdog();
    void watchdog_loop();

    friend void install_suppress_hwbp(Engine&, void*, void*, const char*) noexcept;
};

// Config is now complete — safe to define the default-config constructor inline.
// (GCC CWG2076: default member initializers of nested structs are not available
//  inside the enclosing class body, so we can't write Engine(Config cfg = {}) there.)
inline Engine::Engine() : Engine(Config{}) {}

// ─────────────────────────────────────────────
//  Global convenience engine
// ─────────────────────────────────────────────

Engine& global_engine();

// Shorthand using global engine
template<typename Fn>
[[nodiscard]] Result<HookHandle> hook(Fn* target, Fn* detour, Fn** original_out = nullptr,
                                      TrampolineOptions opts = {})
{
    return global_engine().hook(target, detour, original_out, std::move(opts));
}

template<typename Fn>
[[nodiscard]] Result<HookHandle> hook_api(
    std::string_view  module_name,
    std::string_view  function_name,
    Fn*               detour,
    Fn**              original_out = nullptr,
    TrampolineOptions opts         = {})
{
    return global_engine().hook_api(module_name, function_name,
                                    detour, original_out, std::move(opts));
}

[[nodiscard]] inline Status enable(HookHandle h)  { return global_engine().enable(h); }
[[nodiscard]] inline Status disable(HookHandle h) { return global_engine().disable(h); }
[[nodiscard]] inline Status remove(HookHandle h)  { return global_engine().remove(h); }

} // namespace vanhooks

// ─────────────────────────────────────────────
//  std::hash specialization for HookHandle
//  Enables use in std::unordered_set / std::unordered_map without
//  a custom hasher argument at every call site.
// ─────────────────────────────────────────────
template<>
struct std::hash<vanhooks::HookHandle> {
    size_t operator()(vanhooks::HookHandle h) const noexcept {
        return std::hash<uint64_t>{}(h.id);
    }
};

// Short alias — use vhook:: instead of vanhooks::
namespace vhook = vanhooks;
