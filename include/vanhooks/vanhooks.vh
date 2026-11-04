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

    // Phase 21 — Hook Engine v2
    ConditionNotMet         = 1000, // conditional hook predicate returned false (info-only)
    LazyNotResolved         = 1001, // lazy hook has not yet been triggered
    SwapNotSupported        = 1002, // hook kind does not support in-place detour swap
    PriorityConflict        = 1003, // two hooks on the same target share a priority value
    ExitScanFailed          = 1004, // control-flow analysis could not enumerate return sites

    // Phase 22 — Cross-Platform Hook Parity
    DyldInterposeFailed     = 1100, // macOS DYLD_INSERT_LIBRARIES interpose failed
    MachOImportNotFound     = 1101, // macOS Mach-O lazy/non-lazy symbol pointer not found
    PtraceSetFailed         = 1102, // Linux ptrace(POKEUSR) for debug register failed
    MachThreadSetFailed     = 1103, // macOS thread_set_state for debug register failed
    VeneerAllocFailed       = 1104, // ARM64 veneer stub allocation failed (±128 MB)
    RiscVUnsupported        = 1105, // RISC-V target requires rv64gc disassembler (not yet loaded)

    // Phase 23 — Injection Engine v2
    PtraceAttachFailed      = 1200,
    ProcessVmWriteFailed    = 1201,
    TaskForPidFailed        = 1202,
    AndroidLinkerFailed     = 1203,
    ShellcodeGenFailed      = 1204,
    ManualMapV2Failed       = 1205,
    ReflectiveTlsFailed     = 1206,

    // Phase 24 — Advanced Hook Techniques
    RelayPoolExhausted      = 1300,
    CowSplitFailed          = 1301,
    IdtAccessDenied         = 1302,
    MsrAccessDenied         = 1303,
    ExceptionPortFailed     = 1304,
    SignalHandlerFailed     = 1305,
    JitCacheStale           = 1306,

    // Phase 25 — Analysis Subsystem v2
    ElfInvalidHeader        = 1400,
    ElfNoSymtab             = 1401,
    ElfNoDynamic            = 1402,
    MachOInvalidHeader      = 1403,
    MachOFatSliceNotFound   = 1404,
    MachOCodeSigInvalid     = 1405,
    CfgBuildFailed          = 1406,
    BinaryDiffFailed        = 1407,
    PatternCompileFailed    = 1408,
    RttiNotFound            = 1409,
    FunctionBoundaryFailed  = 1410,

    // Phase 26 — Network Layer v2
    PacketTimingFailed      = 1500,
    DnsResolveFailed        = 1501,
    TlsFingerprintFailed    = 1502,
    ReplaySyncFailed        = 1503,
    InterceptDriverFailed   = 1504,
    CertPinDetectFailed     = 1505,
    WinsockHookFailed       = 1506,

    // Phase 27 — VanTrace v2
    TraceInitFailed         = 1600,
    TraceFilterInvalid      = 1601,
    TraceRemoteBindFailed   = 1602,
    TraceEtwRegisterFailed  = 1603,
    TraceFlameExportFailed  = 1604,
    TraceIdaExportFailed    = 1605,

    // Phase 28 — Test Suite
    TestHarnessFailed       = 1700,
    TestTimeoutExpired      = 1701,
    TestAssertionFailed     = 1702,

    // Phase 29 — Fuzzing Infrastructure
    FuzzTargetInvalid       = 1800,
    FuzzCorpusLoadFailed    = 1801,
    FuzzSanitizerMissing    = 1802,
    FuzzCrashDetected       = 1803,

    // Phase 30 — CI/CD Pipeline
    CiWorkflowInvalid       = 1900,
    CiJobFailed             = 1901,
    CiSdkSyncMismatch       = 1902,
    CiReleaseBuildFailed    = 1903,
    CiCoverageReportFailed  = 1904,
    CiStaticAnalysisFailed  = 1905,

    // Phase 31 — API Documentation
    DocGenerateFailed       = 2000,
    DocModuleNotFound       = 2001,
    DocOutputPathInvalid    = 2002,

    // Phase 32 — SDK Improvements
    SdkSyncFailed           = 2100,
    SdkVersionMismatch      = 2101,
    SdkMinimalBuildFailed   = 2102,
    SdkBindingGenFailed     = 2103,

    // Phase 33 — Examples & Tutorials
    ExampleNotFound         = 2200,
    ExampleBuildFailed      = 2201,

    // Phase 34 — Performance Pass
    BenchmarkFailed         = 2300,
    BenchmarkTimeout        = 2301,
    ArenaAllocFailed        = 2302,

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
    // Phase 21: duration tracking — entry_tsc is captured by the entry thunk
    // (QPC ticks on Windows, steady_clock ticks on POSIX).  duration_ns is
    // computed by the return stub before the callback fires.
    uint64_t entry_tsc;    // timestamp counter at function entry
    uint64_t duration_ns;  // wall-clock nanoseconds from entry to return
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
    uint64_t entry_tsc;
    uint64_t duration_ns;
#elif defined(VH_ARCH_X86)
    uint32_t retval_eax;
    uint32_t retval_edx;
    uint32_t hook_id;
    uint32_t real_ret_addr;
    uint32_t entry_tsc_lo;
    uint32_t entry_tsc_hi;
    uint32_t duration_ns_lo;
    uint32_t duration_ns_hi;
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
    int32_t     priority = 0; // Phase 21: ordering on same target (higher = first)
    bool        stats_enabled = false; // Phase 21: per-hook statistics active
    bool        conditional   = false; // Phase 21: predicate-gated hook
    bool        lazy          = false; // Phase 21: deferred until first call
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
//  Phase 21 — Hook Engine v2 types
// ─────────────────────────────────────────────

// Hook statistics snapshot (non-atomic copy for external consumption).
// Obtained via Engine::stats() or Hook::stats().
struct HookStatsSnapshot {
    uint64_t call_count         = 0;  // total invocations recorded
    uint64_t total_duration_ns  = 0;  // cumulative detour duration (nanoseconds)
    uint64_t average_duration_ns= 0;  // total_duration_ns / call_count (0 if no calls)
    uint64_t max_duration_ns    = 0;  // worst-case single-call duration
    int64_t  last_call_timestamp= 0;  // steady_clock ticks at last invocation (0 = never)
};

// Condition predicate for conditional hooks.
// target: the original function address the hook is installed on.
// user_data: opaque pointer passed through ConditionalOptions.
// Must be safe to call from any thread; must not throw.
using ConditionFn = bool (*)(void* target, void* user_data) noexcept;

// ── Conditional hook options ──────────────────
//
// Installs a hook that only redirects to the detour when condition()
// returns true.  When the predicate returns false the original function
// executes with near-zero overhead.  Internally uses a SoftBp/VEH thunk
// that evaluates the predicate before dispatch.

struct ConditionalOptions {
    ConditionFn condition   = nullptr; // required — null returns InvalidArgument
    void*       user_data   = nullptr; // forwarded to condition()
    int32_t     priority    = 0;       // hook ordering on same target (higher = first)
    bool        thread_safe = true;
    bool        stats       = false;   // enable per-hook call statistics
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return condition != nullptr; }
};

// ── Lazy hook options ─────────────────────────
//
// Defers actual trampoline installation until the target function is
// called for the first time.  An INT3 + VEH thunk captures the first
// hit, installs the real hook, and replays the call.  Saves trampoline
// pool memory for rarely-used hooks.

struct LazyOptions {
    int32_t     priority    = 0;
    bool        thread_safe = true;
    bool        stats       = false;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ── Function-exit hook options ────────────────
//
// Patches every RET/RETN instruction in the target function body so
// the callback fires on each return path.  Requires control-flow
// analysis via Zydis to enumerate return sites.  Distinct from
// hook_mid_return() which patches a single entry point.

struct ExitHookOptions {
    size_t      max_scan_bytes = 4096; // how far to disassemble from target
    int32_t     priority       = 0;
    bool        thread_safe    = true;
    bool        stats          = false;
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Phase 22 — Cross-Platform Hook Parity types
// ─────────────────────────────────────────────

// ── macOS dyld interpose ──────────────────────
// Generates a __DATA,__interpose section entry. Requires the library
// to be loaded via DYLD_INSERT_LIBRARIES. macOS only; returns
// Unsupported on other platforms.

struct DyldInterposeOptions {
    std::string original_symbol; // e.g. "_malloc"
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return !original_symbol.empty();
    }
};

// ── macOS Mach-O import hook ──────────────────
// Patches lazy/non-lazy symbol pointers in __DATA,__la_symbol_ptr or
// __DATA,__nl_symbol_ptr of the target library.

struct MachOImportOptions {
    std::string library_name;  // e.g. "libSystem.B.dylib"
    std::string symbol_name;   // e.g. "_malloc"
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return !library_name.empty() && !symbol_name.empty();
    }
};

// ── ARM64 veneer stub options ─────────────────
// Controls veneer allocation for ARM64 B/BL instructions that exceed
// the ±128 MB direct branch range.

struct VeneerOptions {
    bool        prefer_adrp_ldr = true;  // prefer ADRP+LDR over veneer chain
    std::string tag;

    [[nodiscard]] constexpr bool valid() const noexcept { return true; }
};

// ─────────────────────────────────────────────
//  Phase 23 — Injection Engine v2 types
// ─────────────────────────────────────────────

enum class InjectPlatform : uint8_t {
    Auto,       // detect from target PID
    LinuxX64,
    LinuxARM64,
    MacOSX64,
    MacOSARM64,
    AndroidARM64,
    AndroidARM32,
};

enum class ShellcodeArch : uint8_t {
    X86,
    X64,
    ARM64,
    ARM32,
};

struct ShellcodeGenOptions {
    ShellcodeArch     arch            = ShellcodeArch::X64;
    bool              null_free       = true;    // avoid null bytes
    bool              pic             = true;    // position-independent
    size_t            max_size        = 4096;
    std::string       tag;
};

struct InjectRecommendResult {
    uint8_t           method_id       = 0;       // InjectMethodEx value
    std::string       method_name;
    uint8_t           stealth_score   = 0;       // 0-100
    uint8_t           compat_score    = 0;       // 0-100
    std::string       notes;
};

struct ManualMapV2Options {
    bool              handle_tls      = true;    // resolve TLS callbacks
    bool              handle_seh      = true;    // register exception tables
    bool              handle_delay_imports = true;
    bool              handle_static_init   = true;  // run CRT initializers
    bool              handle_apisets  = true;    // resolve API set redirections
    bool              zero_header    = true;    // erase PE header after mapping
    std::string       tag;
};

struct ReflectiveV2Options {
    bool              handle_tls      = true;
    bool              handle_exceptions = true;
    bool              handle_delay_imports = true;
    std::string       tag;
};

// ─────────────────────────────────────────────
//  Phase 24 — Advanced Hook Techniques types
// ─────────────────────────────────────────────

struct RelayOptions {
    size_t            pool_size       = 64;      // max hooks in the relay pool
    bool              thread_safe     = true;
    std::string       tag;
};

struct CowHookOptions {
    bool              thread_safe     = true;
    std::string       tag;
};

struct SignalHookOptions {
    int               signal_num      = 5;       // SIGTRAP by default
    std::string       tag;
};

struct ExceptionPortOptions {
    std::string       tag;
};

struct JitHookOptions {
    size_t            monitor_interval_ms = 100; // re-check JIT cache
    bool              auto_repatch    = true;    // re-patch on JIT recompile
    std::string       tag;
};

// ─────────────────────────────────────────────
//  Phase 25 — Analysis Subsystem v2 types
// ─────────────────────────────────────────────

// ── ELF parser types ────────────────────────

struct ElfSection {
    std::string name;
    uint32_t    type        = 0;
    uint64_t    flags       = 0;
    uint64_t    address     = 0;
    uint64_t    offset      = 0;
    uint64_t    size        = 0;
    uint32_t    link        = 0;
    uint32_t    info        = 0;
    uint64_t    addralign   = 0;
    uint64_t    entsize     = 0;
};

struct ElfSymbol {
    std::string  name;
    uint64_t     value       = 0;
    uint64_t     size        = 0;
    uint8_t      bind        = 0;   // STB_LOCAL/GLOBAL/WEAK
    uint8_t      type        = 0;   // STT_FUNC/OBJECT/...
    uint16_t     section_idx = 0;
};

struct ElfDynEntry {
    int64_t  tag   = 0;
    uint64_t value = 0;
};

struct ElfRelocation {
    uint64_t offset  = 0;
    uint32_t type    = 0;
    uint32_t sym_idx = 0;
    int64_t  addend  = 0;
};

// ── Mach-O parser types ─────────────────────

struct MachOSection {
    std::string  segname;
    std::string  sectname;
    uint64_t     addr       = 0;
    uint64_t     size       = 0;
    uint32_t     offset     = 0;
    uint32_t     flags      = 0;
};

struct MachOSymbol {
    std::string  name;
    uint64_t     value  = 0;
    uint8_t      type   = 0;
    uint8_t      sect   = 0;
    int16_t      desc   = 0;
};

struct MachOLoadCommand {
    uint32_t cmd  = 0;
    uint32_t size = 0;
    std::vector<uint8_t> data;
};

struct MachOFatSlice {
    uint32_t cpu_type    = 0;
    uint32_t cpu_subtype = 0;
    uint64_t offset      = 0;
    uint64_t size        = 0;
};

// ── Control flow graph ──────────────────────

struct BasicBlock {
    uint64_t                  start_addr = 0;
    uint64_t                  end_addr   = 0;
    std::vector<uint64_t>     successors;
    std::vector<uint64_t>     predecessors;
    bool                      is_entry   = false;
    bool                      is_exit    = false;
};

enum class CfgEdgeKind : uint8_t {
    Fallthrough,
    ConditionalTrue,
    ConditionalFalse,
    Unconditional,
    Call,
    Return,
    Indirect,
};

struct CfgEdge {
    uint64_t    from  = 0;
    uint64_t    to    = 0;
    CfgEdgeKind kind  = CfgEdgeKind::Fallthrough;
};

struct ControlFlowGraph {
    std::vector<BasicBlock> blocks;
    std::vector<CfgEdge>   edges;
    uint64_t               entry_point = 0;
};

// ── Binary diffing ──────────────────────────

enum class DiffKind : uint8_t {
    Identical,
    Modified,
    Added,
    Removed,
};

struct FunctionDiff {
    std::string  name;
    uint64_t     addr_old = 0;
    uint64_t     addr_new = 0;
    DiffKind     kind     = DiffKind::Identical;
    float        similarity = 1.0f;  // 0.0–1.0 for Modified
};

struct BinaryDiffResult {
    std::vector<FunctionDiff> functions;
    size_t                    total_old   = 0;
    size_t                    total_new   = 0;
    size_t                    matched     = 0;
    size_t                    modified    = 0;
    size_t                    added       = 0;
    size_t                    removed     = 0;
};

// ── Pattern scanner v2 ─────────────────────

struct PatternRule {
    std::string              name;
    std::vector<uint8_t>     pattern;
    std::vector<uint8_t>     mask;       // 0xFF = exact, 0x00 = wildcard
    std::vector<std::string> tags;
};

struct PatternMatch {
    uint64_t     address    = 0;
    std::string  rule_name;
    size_t       length     = 0;
};

// ── String scanner ──────────────────────────

enum class StringEncoding : uint8_t {
    Ascii,
    Utf8,
    Utf16LE,
    Utf16BE,
};

struct ExtractedString {
    uint64_t        address  = 0;
    std::string     value;
    StringEncoding  encoding = StringEncoding::Ascii;
    size_t          byte_len = 0;
    std::string     section;
};

// ── Type reconstruction (RTTI) ──────────────

struct RttiClassInfo {
    std::string              name;
    uint64_t                 vtable_addr  = 0;
    uint64_t                 rtti_addr    = 0;
    std::vector<std::string> base_classes;
    size_t                   vtable_slots = 0;
};

// ── Function boundary detection ─────────────

struct FunctionBoundary {
    uint64_t    start     = 0;
    uint64_t    end       = 0;
    std::string name;          // symbol name if available
    bool        has_symbol = false;
    float       confidence = 1.0f;   // 0.0–1.0 heuristic confidence
};

// ── Analysis options ────────────────────────

struct CfgBuildOptions {
    size_t   max_instructions = 100000;
    bool     follow_calls     = false;
    std::string tag;
};

struct BinaryDiffOptions {
    float    similarity_threshold = 0.5f;  // below this, treat as added/removed
    bool     instruction_level    = false;  // diff individual instructions
    std::string tag;
};

struct PatternScanOptions {
    size_t   max_matches    = 0;     // 0 = unlimited
    uint64_t scan_start     = 0;     // 0 = module base
    uint64_t scan_end       = 0;     // 0 = module end
    std::string tag;
};

struct StringScanOptions {
    size_t   min_length   = 4;
    size_t   max_length   = 4096;
    bool     include_utf16 = true;
    std::string tag;
};

struct FunctionDetectOptions {
    size_t   max_functions   = 0;    // 0 = unlimited
    float    min_confidence  = 0.5f;
    std::string tag;
};

// ─────────────────────────────────────────────
//  Phase 26 — Network Layer v2 types
// ─────────────────────────────────────────────

struct PacketTimingConfig {
    double   jitter_ms_min  = 0.0;   // minimum added delay
    double   jitter_ms_max  = 5.0;   // maximum added delay
    bool     enabled        = true;
    std::string tag;
};

struct DnsFingerprint {
    std::string  domain;
    std::string  record_type;   // A, AAAA, CNAME, TXT
    uint64_t     ttl       = 0;
    bool         is_canary = false;
    std::string  response;
};

struct TlsFingerprint {
    std::string  ja3_hash;
    std::string  ja4_hash;
    std::string  server_name;   // SNI
    uint16_t     tls_version = 0;
    std::vector<uint16_t> cipher_suites;
};

enum class ReplayMode : uint8_t {
    Realtime,       // replay at original timing
    FastForward,    // replay as fast as possible
    StepByStep,     // replay one packet at a time
};

struct ReplayOptions {
    ReplayMode   mode        = ReplayMode::Realtime;
    double       speed_mult  = 1.0;    // for Realtime mode
    std::string  filter;               // BPF filter
    std::string  tag;
};

struct InterceptRule {
    std::string  filter;               // BPF/WinDivert filter expression
    bool         drop       = false;   // drop matching packets
    bool         modify     = false;   // allow modification callback
    std::string  tag;
};

struct CertPinInfo {
    std::string  hostname;
    std::vector<std::string> pin_hashes;  // SPKI SHA-256 pins
    bool         enforced   = false;
    std::string  source;     // "header" (HPKP), "embedded", "dynamic"
};

struct WinsockHookConfig {
    bool     hook_send      = true;
    bool     hook_recv      = true;
    bool     hook_connect   = true;
    bool     hook_accept    = true;
    bool     hook_dns       = true;    // gethostbyname / getaddrinfo
    std::string tag;
};

// ─────────────────────────────────────────────
//  Phase 27 — VanTrace v2 types
// ─────────────────────────────────────────────

enum class TraceFormat : uint8_t {
    Json,           // human-readable JSON lines
    Binary,         // compact binary format
    Collapsed,      // collapsed-stack for flame graphs
};

struct TraceConfig {
    TraceFormat format         = TraceFormat::Json;
    bool        include_stacks = true;
    bool        include_args   = false;   // log hook arguments
    size_t      buffer_size    = 1 << 20; // ring buffer bytes (1 MB)
    std::string output_path;              // file path or empty for in-memory
    std::string tag;
};

struct TraceFilter {
    std::vector<std::string> include_modules;   // module name allowlist
    std::vector<std::string> exclude_modules;   // module name blocklist
    std::vector<uint64_t>    include_addresses; // specific function addresses
    uint32_t                 max_depth     = 0; // 0 = unlimited call depth
    std::string              tag;
};

struct TraceRemoteConfig {
    std::string  address       = "127.0.0.1"; // bind address
    uint16_t     port          = 47700;        // TCP port (0 = named pipe)
    std::string  pipe_name;                    // Windows named pipe name
    bool         auto_start    = true;
    std::string  tag;
};

struct TraceEtwConfig {
    std::string  provider_name = "VanHooks-Trace";
    uint8_t      level         = 4;   // 1=critical … 5=verbose
    uint64_t     keyword_mask  = 0;   // ETW keyword filter
    std::string  tag;
};

struct FlameGraphEntry {
    std::string  stack;        // semicolon-delimited collapsed stack
    uint64_t     duration_ns;  // inclusive duration
};

enum class IdaExportFormat : uint8_t {
    IdaPython,     // .py script for IDA Pro
    GhidraJava,    // .java script for Ghidra
};

struct TraceIdaExportOptions {
    IdaExportFormat  format       = IdaExportFormat::IdaPython;
    bool             add_comments = true;
    bool             add_colors   = true;
    std::string      output_path;
    std::string      tag;
};

// ─────────────────────────────────────────────
//  Phase 28 — Test Suite types
// ─────────────────────────────────────────────

enum class TestVerbosity : uint8_t {
    Quiet,          // only failures
    Summary,        // pass/fail counts
    Verbose,        // every test case
};

struct TestRunConfig {
    TestVerbosity verbosity    = TestVerbosity::Summary;
    uint32_t      timeout_ms   = 30000;  // per-test timeout
    bool          stop_on_fail = false;
    size_t        thread_count = 1;      // parallel test threads
    std::string   filter;                // glob filter on test names
    std::string   tag;
};

enum class TestResult : uint8_t {
    Pass,
    Fail,
    Skip,
    Timeout,
};

struct TestCaseResult {
    std::string  name;
    TestResult   result     = TestResult::Pass;
    double       elapsed_ms = 0.0;
    std::string  message;    // failure/skip reason
};

struct TestSuiteResult {
    std::vector<TestCaseResult> cases;
    size_t  total   = 0;
    size_t  passed  = 0;
    size_t  failed  = 0;
    size_t  skipped = 0;
    double  elapsed_ms = 0.0;
};

struct StressTestConfig {
    size_t   thread_count     = 8;
    size_t   iterations       = 10000;
    size_t   chain_depth      = 16;    // max hook chain depth
    uint32_t timeout_ms       = 60000;
    std::string tag;
};

// ─────────────────────────────────────────────
//  Phase 29 — Fuzzing Infrastructure types
// ─────────────────────────────────────────────

enum class FuzzEngine : uint8_t {
    LibFuzzer,
    AflPlusPlus,
    Honggfuzz,
};

enum class FuzzTarget : uint8_t {
    Disasm,
    Trampoline,
    PeParser,
    ElfParser,
    MachOParser,
    Injection,
    PatternScanner,
    StringScanner,
};

struct FuzzConfig {
    FuzzEngine   engine          = FuzzEngine::LibFuzzer;
    FuzzTarget   target          = FuzzTarget::Disasm;
    std::string  corpus_dir;                // seed corpus directory
    std::string  output_dir;                // crash/artifact output
    size_t       max_iterations  = 0;       // 0 = unlimited
    size_t       max_input_size  = 4096;
    uint32_t     timeout_ms      = 10000;   // per-input timeout
    bool         detect_leaks    = true;
    std::string  tag;
};

enum class SanitizerKind : uint8_t {
    Asan,    // AddressSanitizer
    Ubsan,   // UndefinedBehaviorSanitizer
    Msan,    // MemorySanitizer
    Tsan,    // ThreadSanitizer
    Lsan,    // LeakSanitizer
};

struct FuzzCrashInfo {
    std::string  input_hash;     // SHA-256 of crashing input
    std::string  target_name;
    std::string  crash_type;     // "heap-buffer-overflow", "null-deref", …
    std::string  stack_trace;
    size_t       input_size = 0;
    bool         deduplicated = false;
};

struct CorpusStats {
    size_t  total_inputs    = 0;
    size_t  minimised_count = 0;
    size_t  total_crashes   = 0;
    size_t  unique_crashes  = 0;
    double  coverage_pct    = 0.0;
};

// ─────────────────────────────────────────────
//  Phase 30 — CI/CD Pipeline types
// ─────────────────────────────────────────────

enum class CiPlatform : uint8_t {
    WindowsX64,
    WindowsX86,
    WindowsArm64,
    LinuxX64Gcc,
    LinuxX64Clang,
    LinuxArm64,
    MacOsX64,
    MacOsArm64,
    FuzzSmoke,
    NetEnabled,
};

struct CiJobConfig {
    CiPlatform   platform;
    std::string  build_type    = "Release"; // Release, Debug, RelWithDebInfo
    bool         net_enabled   = false;
    bool         fuzz_smoke    = false;
    std::string  tag;
};

struct CiJobResult {
    CiPlatform   platform;
    bool         success       = false;
    double       elapsed_sec   = 0.0;
    size_t       warnings      = 0;
    size_t       errors        = 0;
    std::string  log_summary;
};

struct CiSdkSyncResult {
    bool         in_sync       = false;
    std::vector<std::string> mismatched_headers;
};

struct CiReleaseConfig {
    std::string  version_tag;        // e.g. "v0.2.0"
    bool         generate_archive  = true;
    bool         publish_release   = false;  // GitHub Release
    std::string  tag;
};

struct CiCoverageReport {
    double  line_pct       = 0.0;
    double  branch_pct     = 0.0;
    double  function_pct   = 0.0;
    size_t  lines_covered  = 0;
    size_t  lines_total    = 0;
};

struct CiStaticAnalysisResult {
    size_t  issues_total    = 0;
    size_t  issues_error    = 0;
    size_t  issues_warning  = 0;
    size_t  issues_note     = 0;
    std::string tool_name;    // "clang-tidy", "cppcheck", "PVS-Studio"
};

struct CiBinarySizeEntry {
    std::string  target_name;    // "vanhooks.lib", "vanhooks.dll"
    CiPlatform   platform;
    size_t       size_bytes = 0;
};

// ─────────────────────────────────────────────
//  Phase 31 — API Documentation types
// ─────────────────────────────────────────────

enum class DocFormat : uint8_t {
    Html,           // Doxygen HTML output
    Markdown,       // Markdown reference
    Json,           // Machine-readable JSON schema
};

struct DocGenerateConfig {
    DocFormat    format          = DocFormat::Html;
    std::string  output_dir     = "docs/api";
    std::string  theme          = "vanhooks";   // Doxygen theme name
    bool         include_private = false;
    bool         include_source  = false;        // include source snippets
    std::string  tag;
};

struct DocModuleInfo {
    std::string  name;           // e.g. "vh::unhook"
    std::string  category;       // e.g. "vigil", "inject", "analysis"
    std::string  description;
    std::vector<std::string> detects;      // what this module detects/provides
    std::vector<std::string> engines;      // AC engines that exercise it
    std::vector<std::string> functions;    // public API functions
};

enum class HookKindDoc : uint8_t {
    Trampoline, Mid, CallSite, IAT, PLT, GOT, VTable,
    HwBp, PageGuard, Nirvana, SoftBp, EAT, Syscall,
    TLS, Exception, ThreadLocal, EPT
};

struct HookKindInfo {
    HookKindDoc  kind;
    std::string  name;
    std::string  description;
    std::string  when_to_use;
    std::string  performance;     // "ns/call", "cache impact"
    bool         windows   = false;
    bool         linux_    = false;
    bool         macos     = false;
};

struct InjectionTechniqueInfo {
    std::string  name;
    std::string  description;
    uint8_t      stealth_rank = 0;  // 1 = most stealthy
    bool         windows   = false;
    bool         linux_    = false;
    bool         macos     = false;
    bool         android   = false;
    std::string  prerequisites;
};

struct ErrorRefEntry {
    Error        code;
    std::string  name;
    std::string  cause;
    std::string  troubleshooting;
    std::string  recovery_example;
};

// ─────────────────────────────────────────────
//  Phase 32 — SDK Improvements types
// ─────────────────────────────────────────────

struct SdkSyncConfig {
    std::string  source_include_dir = "include";
    std::string  sdk_include_dir    = "../VanHooksSDK/include";
    std::string  lib_output_dir     = "lib";
    std::string  sdk_lib_dir        = "../VanHooksSDK/lib";
    bool         copy_libs          = true;
    bool         copy_headers       = true;
    std::string  tag;
};

struct SdkSyncReport {
    size_t  headers_copied   = 0;
    size_t  headers_skipped  = 0;
    size_t  libs_copied      = 0;
    std::vector<std::string> changed_files;
};

struct SdkVersionInfo {
    int          major;
    int          minor;
    int          patch;
    std::string  full_string;        // "0.2.0"
    bool         header_matches_lib; // runtime check result
};

struct SdkChangelogEntry {
    std::string  version;
    std::string  date;
    std::vector<std::string> added;
    std::vector<std::string> changed;
    std::vector<std::string> removed;
    std::vector<std::string> deprecated;
};

enum class SdkProfile : uint8_t {
    Full,           // all modules
    Minimal,        // core hooks only
    Analysis,       // core + analysis
    Stealth,        // core + vigil + stealth pack
};

struct SdkMinimalConfig {
    SdkProfile   profile         = SdkProfile::Minimal;
    bool         include_inject  = false;
    bool         include_vigil   = false;
    bool         include_analysis = false;
    bool         include_net     = false;
    std::string  tag;
};

enum class BindingLang : uint8_t {
    C,
    Python,
    Rust,
    CSharp,
};

struct BindingGenConfig {
    BindingLang  language;
    std::string  output_dir;
    bool         generate_tests  = true;
    std::string  tag;
};

struct BindingGenResult {
    BindingLang  language;
    size_t       functions_wrapped = 0;
    size_t       types_wrapped     = 0;
    std::vector<std::string> generated_files;
};

// ─────────────────────────────────────────────
//  Phase 33 — Examples & Tutorials types
// ─────────────────────────────────────────────

struct ExampleInfo {
    std::string  name;           // e.g. "quickstart"
    std::string  title;          // e.g. "Minimal Inline Hook"
    std::string  description;
    std::string  category;       // "core", "stealth", "analysis", "inject", "net", "cross-platform"
    std::string  source_path;    // relative path in examples/
    std::vector<std::string> demonstrates;  // API features shown
};

enum class ExampleCategory : uint8_t {
    Core,
    Stealth,
    Analysis,
    Inject,
    Net,
    CrossPlatform,
    GameIntegration,
};

struct ExampleBuildConfig {
    std::string  example_name;
    std::string  build_dir   = "build/examples";
    bool         run_after   = false;   // run the example after building
    std::string  tag;
};

struct ExampleBuildResult {
    std::string  example_name;
    bool         success      = false;
    std::string  output_path;
    double       build_sec    = 0.0;
    std::string  log;
};

// ─────────────────────────────────────────────
//  Phase 34 — Performance Pass types
// ─────────────────────────────────────────────

enum class BenchmarkTarget : uint8_t {
    HookInstall,        // time to install a single hook
    HookDispatch,       // per-call overhead through detour
    HookRemove,         // time to cleanly remove a hook
    BatchInstall,       // N hooks in one apply_queued cycle
    TrampolineAlloc,    // single trampoline allocation
    ArenaAlloc,         // arena-based bulk allocation
    LockContention,     // concurrent hook lookup latency
    CachePressure,      // hook table traversal under load
};

struct BenchmarkConfig {
    BenchmarkTarget target;
    size_t          iterations   = 10000;
    size_t          warmup       = 100;
    size_t          threads      = 1;       // for contention benchmarks
    uint32_t        timeout_ms   = 30000;
    std::string     tag;
};

struct BenchmarkResult {
    BenchmarkTarget target;
    double          min_ns       = 0.0;
    double          max_ns       = 0.0;
    double          avg_ns       = 0.0;
    double          median_ns    = 0.0;
    double          p99_ns       = 0.0;
    size_t          iterations   = 0;
    double          total_ms     = 0.0;
};

struct MemoryFootprint {
    size_t  engine_bytes       = 0;   // Engine struct + impl
    size_t  hooks_bytes        = 0;   // hook metadata table
    size_t  trampolines_bytes  = 0;   // allocated trampoline stubs
    size_t  vigil_bytes        = 0;   // vigil module state
    size_t  net_bytes          = 0;   // network capture buffers
    size_t  total_bytes        = 0;
};

struct ArenaConfig {
    size_t  initial_size    = 1 << 16;  // 64 KB
    size_t  max_size        = 1 << 24;  // 16 MB
    bool    executable      = true;     // VirtualAlloc with PAGE_EXECUTE_READWRITE
    void*   hint_address    = nullptr;  // prefer near this address
    std::string tag;
};

struct ArenaStats {
    size_t  allocated_bytes  = 0;
    size_t  used_bytes       = 0;
    size_t  free_bytes       = 0;
    size_t  alloc_count      = 0;
    size_t  arena_count      = 0;   // number of arena blocks
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

    // ══════════════════════════════════════════════
    //  Phase 21 — Hook Engine v2
    // ══════════════════════════════════════════════

    // ── Conditional hook ─────────────────────────
    // Installs a hook that fires only when opts.condition() returns true.
    // Uses a SoftBp/VEH dispatcher that evaluates the predicate per-call.

    [[nodiscard]]
    Result<HookHandle> hook_conditional(
        void*              target,
        void*              detour,
        void**             original_out = nullptr,
        ConditionalOptions opts = {}
    );

    template<typename Fn>
    [[nodiscard]]
    Result<HookHandle> hook_conditional(
        Fn*                target,
        Fn*                detour,
        Fn**               original_out = nullptr,
        ConditionalOptions opts = {})
    {
        return hook_conditional(reinterpret_cast<void*>(target),
                                reinterpret_cast<void*>(detour),
                                reinterpret_cast<void**>(original_out),
                                std::move(opts));
    }

    // ── Lazy hook ────────────────────────────────
    // Defers trampoline installation until first call.  An INT3/SoftBp at
    // the target captures the first hit, installs the real trampoline, removes
    // the breakpoint, and replays the call transparently.

    [[nodiscard]]
    Result<HookHandle> hook_lazy(
        void*        target,
        void*        detour,
        void**       original_out = nullptr,
        LazyOptions  opts = {}
    );

    template<typename Fn>
    [[nodiscard]]
    Result<HookHandle> hook_lazy(
        Fn*          target,
        Fn*          detour,
        Fn**         original_out = nullptr,
        LazyOptions  opts = {})
    {
        return hook_lazy(reinterpret_cast<void*>(target),
                         reinterpret_cast<void*>(detour),
                         reinterpret_cast<void**>(original_out),
                         std::move(opts));
    }

    // ── Function-exit hook ──────────────────────
    // Patches every RET/RETN site in the target function body (found via
    // control-flow analysis) so the callback fires on every return path.

    [[nodiscard]]
    Result<HookHandle> hook_exit(
        void*            target,
        ReturnCallback   callback,
        ExitHookOptions  opts = {}
    );

    // ── Atomic detour swap ──────────────────────
    // Replaces a hook's detour function in-place without a remove+add gap.
    // Supported for Trampoline, CallSite, and ThreadLocal hook kinds.
    // The old detour address is written to *old_detour_out if non-null.

    [[nodiscard]]
    Status swap_detour(HookHandle handle,
                       void*      new_detour,
                       void**     old_detour_out = nullptr);

    // ── Hook priority ───────────────────────────
    // Sets the numeric priority for ordering multiple hooks on the same
    // target.  Higher priority hooks fire first in the chain.

    [[nodiscard]]
    Status set_priority(HookHandle handle, int32_t priority);

    // ── Per-hook statistics ──────────────────────
    // Returns a snapshot of the hook's call statistics.
    // Statistics are only collected when the hook was installed with stats=true
    // or when stats were explicitly enabled via enable_stats().

    [[nodiscard]]
    std::optional<HookStatsSnapshot> stats(HookHandle handle) const;

    [[nodiscard]] Status enable_stats(HookHandle handle);
    [[nodiscard]] Status disable_stats(HookHandle handle);
    [[nodiscard]] Status reset_stats(HookHandle handle);

    // ── Thread-targeted hooks (expanded) ────────
    // Enable/disable a thread-local hook for a set of thread IDs at once.
    // Complements the single-thread thread_local_enable/disable().

    void thread_local_enable_set (HookHandle handle, std::span<const uint32_t> thread_ids);
    void thread_local_disable_set(HookHandle handle, std::span<const uint32_t> thread_ids);
    void thread_local_disable_all(HookHandle handle) noexcept;

    // ── Detour type safety ──────────────────────
    // Compile-time signature match: prevents silent calling-convention mismatch.
    //
    //   auto h = engine.hook_typed<int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT)>(
    //       MessageBoxA, MyMessageBoxA, &g_origMessageBoxA);

    template<typename Sig>
    [[nodiscard]]
    Result<HookHandle> hook_typed(Sig target, Sig detour, Sig* original_out = nullptr,
                                  TrampolineOptions opts = {})
    {
        static_assert(std::is_pointer_v<Sig> && std::is_function_v<std::remove_pointer_t<Sig>>,
                      "vh::hook_typed<Sig>: Sig must be a function pointer type");
        return hook_trampoline(reinterpret_cast<void*>(target),
                               reinterpret_cast<void*>(detour),
                               reinterpret_cast<void**>(original_out),
                               std::move(opts));
    }

    // ══════════════════════════════════════════════
    //  Phase 22 — Cross-Platform Hook Parity
    // ══════════════════════════════════════════════

    // ── macOS dyld interpose ─────────────────────
    // Registers a DYLD_INSERT_LIBRARIES interposition.
    // macOS only; returns Error::Unsupported on other platforms.

    [[nodiscard]]
    Result<HookHandle> hook_dyld_interpose(void* detour, DyldInterposeOptions opts);

    // ── macOS Mach-O import hook ─────────────────
    // Patches lazy/non-lazy symbol pointers in __DATA segments.
    // macOS only; returns Error::Unsupported on other platforms.

    [[nodiscard]]
    Result<HookHandle> hook_macho_import(void* detour, MachOImportOptions opts);

    // ── Hardware breakpoint hooks (Linux) ────────
    // Uses ptrace(POKEUSR) to set debug registers DR0-DR3.
    // Linux only; returns Error::Unsupported on other platforms.

    [[nodiscard]]
    Result<HookHandle> hook_hwbp_linux(
        void*        target,
        MidCallback  callback,
        HwBpOptions  opts = {}
    );

    // ── Hardware breakpoint hooks (macOS) ────────
    // Uses thread_set_state() on x86_DEBUG_STATE64.
    // macOS only; returns Error::Unsupported on other platforms.

    [[nodiscard]]
    Result<HookHandle> hook_hwbp_macos(
        void*        target,
        MidCallback  callback,
        HwBpOptions  opts = {}
    );

    // ══════════════════════════════════════════════
    //  Phase 23 — Injection Engine v2
    // ══════════════════════════════════════════════

    // ── Injection stealth recommendation ─────────
    // Surveys the target process against known AC signatures and returns
    // a ranked list of injection methods ordered by stealth score.

    [[nodiscard]]
    std::vector<InjectRecommendResult> inject_recommend(
        uint32_t pid,
        InjectPlatform platform = InjectPlatform::Auto
    );

    // ── Shellcode generator ──────────────────────
    // Generates position-independent shellcode from a raw code buffer,
    // applying arch-specific PIC transforms (RIP-relative → absolute, etc.).

    [[nodiscard]]
    Result<std::vector<uint8_t>> shellcode_generate(
        std::span<const uint8_t> code,
        ShellcodeGenOptions      opts = {}
    );

    // ══════════════════════════════════════════════
    //  Phase 24 — Advanced Hook Techniques
    // ══════════════════════════════════════════════

    // ── Inline hook relay ────────────────────────
    // Shared trampoline pool with direct jmp relay — saves one indirection
    // per call.  The relay pool is pre-allocated near the target.

    [[nodiscard]]
    Result<HookHandle> hook_relay(
        void*          target,
        void*          detour,
        void**         original_out = nullptr,
        RelayOptions   opts = {}
    );

    // ── Copy-on-write hook ──────────────────────
    // Creates a private CoW mapping of the target's .text page so the
    // hook patch is invisible to same-process integrity scans.

    [[nodiscard]]
    Result<HookHandle> hook_cow(
        void*           target,
        void*           detour,
        void**          original_out = nullptr,
        CowHookOptions  opts = {}
    );

    // ── Signal-based hook (Linux) ────────────────
    // SIGTRAP/SIGILL handler dispatch for breakpoint-free hooking.
    // Linux only; returns Error::Unsupported on other platforms.

    [[nodiscard]]
    Result<HookHandle> hook_signal(
        void*              target,
        MidCallback        callback,
        SignalHookOptions  opts = {}
    );

    // ── Exception-port hook (macOS) ──────────────
    // Mach exception port interception for breakpoint-free hooking.
    // macOS only; returns Error::Unsupported on other platforms.

    [[nodiscard]]
    Result<HookHandle> hook_exception_port(
        void*                target,
        MidCallback          callback,
        ExceptionPortOptions opts = {}
    );

    // ── JIT hook support ────────────────────────
    // Hooks dynamically generated code (V8, LuaJIT, .NET JIT) with
    // JIT code-cache monitoring and automatic re-patch on recompile.

    [[nodiscard]]
    Result<HookHandle> hook_jit(
        void*           target,
        void*           detour,
        void**          original_out = nullptr,
        JitHookOptions  opts = {}
    );

    // ── Phase 25 — Analysis Subsystem v2 ────────

    // ELF parser: parse an in-memory ELF image.
    // Returns sections, symbols, dynamic entries, and relocations.
    [[nodiscard]]
    Result<std::vector<ElfSection>> elf_sections(
        std::span<const uint8_t> elf_image);

    [[nodiscard]]
    Result<std::vector<ElfSymbol>> elf_symbols(
        std::span<const uint8_t> elf_image);

    [[nodiscard]]
    Result<std::vector<ElfDynEntry>> elf_dynamic(
        std::span<const uint8_t> elf_image);

    [[nodiscard]]
    Result<std::vector<ElfRelocation>> elf_relocations(
        std::span<const uint8_t> elf_image);

    // Mach-O parser: parse an in-memory Mach-O image.
    // Handles fat (universal) binaries via fat_slices().
    [[nodiscard]]
    Result<std::vector<MachOFatSlice>> macho_fat_slices(
        std::span<const uint8_t> macho_image);

    [[nodiscard]]
    Result<std::vector<MachOSection>> macho_sections(
        std::span<const uint8_t> macho_image);

    [[nodiscard]]
    Result<std::vector<MachOSymbol>> macho_symbols(
        std::span<const uint8_t> macho_image);

    [[nodiscard]]
    Result<std::vector<MachOLoadCommand>> macho_load_commands(
        std::span<const uint8_t> macho_image);

    // Control flow graph: build a CFG from a function's address.
    [[nodiscard]]
    Result<ControlFlowGraph> build_cfg(
        void* function_start,
        CfgBuildOptions opts = {});

    // Binary diffing: compare two module images function by function.
    [[nodiscard]]
    Result<BinaryDiffResult> binary_diff(
        std::span<const uint8_t> old_image,
        std::span<const uint8_t> new_image,
        BinaryDiffOptions opts = {});

    // Pattern scanner v2: compile and scan with wildcard rules.
    [[nodiscard]]
    Result<std::vector<PatternMatch>> pattern_scan(
        void* base, size_t size,
        std::span<const PatternRule> rules,
        PatternScanOptions opts = {});

    // String scanner: extract readable strings from a memory region.
    [[nodiscard]]
    Result<std::vector<ExtractedString>> string_scan(
        void* base, size_t size,
        StringScanOptions opts = {});

    // Type reconstruction: recover RTTI class info from a module.
    [[nodiscard]]
    Result<std::vector<RttiClassInfo>> rtti_scan(
        void* module_base);

    // Function boundary detection: heuristic function start/end.
    [[nodiscard]]
    Result<std::vector<FunctionBoundary>> detect_functions(
        void* base, size_t size,
        FunctionDetectOptions opts = {});

    // ── Phase 26 — Network Layer v2 ─────────────

    // Packet timing normalisation: add jitter to outgoing responses.
    [[nodiscard]]
    Result<void> net_set_packet_timing(PacketTimingConfig config);

    // DNS fingerprint awareness: scan for AC canary domains.
    [[nodiscard]]
    Result<std::vector<DnsFingerprint>> net_dns_fingerprint(
        std::string_view interface_name,
        uint32_t timeout_ms = 5000);

    // TLS fingerprint: capture JA3/JA4 fingerprints from traffic.
    [[nodiscard]]
    Result<std::vector<TlsFingerprint>> net_tls_fingerprint(
        std::string_view interface_name,
        uint32_t timeout_ms = 5000);

    // Traffic replay: replay a pcapng file on the network.
    [[nodiscard]]
    Result<void> net_replay(
        std::string_view pcapng_path,
        ReplayOptions opts = {});

    // Network interception: register inline packet modification rules.
    [[nodiscard]]
    Result<uint64_t> net_intercept_add(InterceptRule rule);

    [[nodiscard]]
    Result<void> net_intercept_remove(uint64_t rule_id);

    // Certificate pinning awareness: detect and map cert pins.
    [[nodiscard]]
    Result<std::vector<CertPinInfo>> net_cert_pin_scan(
        std::string_view hostname);

    // Winsock hook layer: install hooks on WSA* functions.
    // Windows only; returns Error::Unsupported on POSIX.
    [[nodiscard]]
    Result<void> net_winsock_hook(WinsockHookConfig config = {});

    [[nodiscard]]
    Result<void> net_winsock_unhook();

    // ── Phase 27 — VanTrace v2 ──────────────────

    // Initialise or reconfigure the trace subsystem.
    [[nodiscard]]
    Result<void> trace_init(TraceConfig config = {});

    // Shut down trace and flush buffers.
    [[nodiscard]]
    Result<void> trace_shutdown();

    // Apply a filter to the active trace session.
    [[nodiscard]]
    Result<void> trace_set_filter(TraceFilter filter);

    // Start a remote trace viewer server (named pipe or TCP).
    [[nodiscard]]
    Result<void> trace_remote_start(TraceRemoteConfig config = {});

    // Stop the remote trace viewer server.
    [[nodiscard]]
    Result<void> trace_remote_stop();

    // Register an ETW provider for Windows Performance Analyzer.
    // Windows only; returns Error::Unsupported on POSIX.
    [[nodiscard]]
    Result<void> trace_etw_register(TraceEtwConfig config = {});

    // Unregister the ETW provider.
    [[nodiscard]]
    Result<void> trace_etw_unregister();

    // Export collected trace data as a collapsed-stack flame graph file.
    [[nodiscard]]
    Result<std::vector<FlameGraphEntry>> trace_flame_export(
        std::string_view output_path);

    // Export trace data as an IDA Pro or Ghidra annotation script.
    [[nodiscard]]
    Result<void> trace_ida_export(TraceIdaExportOptions opts);

    // ── Phase 28 — Test Suite ───────────────────

    // Run the built-in self-test suite.
    [[nodiscard]]
    Result<TestSuiteResult> test_run(TestRunConfig config = {});

    // Run the concurrent stress test (hook/unhook from N threads).
    [[nodiscard]]
    Result<TestSuiteResult> test_stress(StressTestConfig config = {});

    // Run a single named test case and return its result.
    [[nodiscard]]
    Result<TestCaseResult> test_run_one(std::string_view test_name,
                                        uint32_t timeout_ms = 30000);

    // List all available test names.
    [[nodiscard]]
    Result<std::vector<std::string>> test_list();

    // ── Phase 29 — Fuzzing Infrastructure ───────

    // Start a fuzz session on the given target.
    [[nodiscard]]
    Result<void> fuzz_start(FuzzConfig config);

    // Stop the current fuzz session and return crash info.
    [[nodiscard]]
    Result<std::vector<FuzzCrashInfo>> fuzz_stop();

    // Get corpus statistics for the active/last fuzz session.
    [[nodiscard]]
    Result<CorpusStats> fuzz_corpus_stats();

    // Minimise the seed corpus, removing redundant inputs.
    [[nodiscard]]
    Result<CorpusStats> fuzz_corpus_minimise(std::string_view corpus_dir);

    // Check whether a sanitizer is available at runtime.
    [[nodiscard]]
    Result<bool> fuzz_sanitizer_available(SanitizerKind kind);

    // List available fuzz targets.
    [[nodiscard]]
    Result<std::vector<std::string>> fuzz_list_targets();

    // ── Phase 30 — CI/CD Pipeline ───────────────

    // Validate a CI workflow configuration.
    [[nodiscard]]
    Result<void> ci_validate_workflow(std::string_view workflow_path);

    // Run a single CI job configuration locally.
    [[nodiscard]]
    Result<CiJobResult> ci_run_job(CiJobConfig config);

    // Check SDK header sync: compare source headers against SDK copy.
    [[nodiscard]]
    Result<CiSdkSyncResult> ci_check_sdk_sync();

    // Generate a release archive from the current build.
    [[nodiscard]]
    Result<void> ci_release_build(CiReleaseConfig config);

    // Run code coverage and return a summary report.
    [[nodiscard]]
    Result<CiCoverageReport> ci_coverage_report();

    // Run static analysis and return results.
    [[nodiscard]]
    Result<CiStaticAnalysisResult> ci_static_analysis(
        std::string_view tool_name = "clang-tidy");

    // Measure binary sizes for the current build.
    [[nodiscard]]
    Result<std::vector<CiBinarySizeEntry>> ci_binary_sizes();

    // ── Phase 31 — API Documentation ────────────

    // Generate API documentation from header doc-comments.
    [[nodiscard]]
    Result<void> doc_generate(DocGenerateConfig config = {});

    // Get documentation info for a specific module.
    [[nodiscard]]
    Result<DocModuleInfo> doc_module_info(std::string_view module_name);

    // List all documented modules with their categories.
    [[nodiscard]]
    Result<std::vector<DocModuleInfo>> doc_list_modules();

    // Get hook kind documentation: when to use, platforms, performance.
    [[nodiscard]]
    Result<std::vector<HookKindInfo>> doc_hook_kinds();

    // Get injection technique documentation: stealth ranking, platforms.
    [[nodiscard]]
    Result<std::vector<InjectionTechniqueInfo>> doc_injection_techniques();

    // Get error reference: causes, troubleshooting, recovery examples.
    [[nodiscard]]
    Result<std::vector<ErrorRefEntry>> doc_error_reference();

    // ── Phase 32 — SDK Improvements ─────────────

    // Sync public headers and libs from source to SDK directory.
    [[nodiscard]]
    Result<SdkSyncReport> sdk_sync(SdkSyncConfig config = {});

    // Get SDK version info and check header/lib match.
    [[nodiscard]]
    Result<SdkVersionInfo> sdk_version();

    // Get SDK changelog entries.
    [[nodiscard]]
    Result<std::vector<SdkChangelogEntry>> sdk_changelog();

    // Build a minimal SDK with only the selected modules.
    [[nodiscard]]
    Result<void> sdk_build_minimal(SdkMinimalConfig config = {});

    // Generate language bindings (C, Python, Rust, C#).
    [[nodiscard]]
    Result<BindingGenResult> sdk_generate_bindings(BindingGenConfig config);

    // ── Phase 33 — Examples & Tutorials ─────────

    // List all available examples with metadata.
    [[nodiscard]]
    Result<std::vector<ExampleInfo>> example_list();

    // Get info for a specific example by name.
    [[nodiscard]]
    Result<ExampleInfo> example_get(std::string_view name);

    // Build (and optionally run) an example.
    [[nodiscard]]
    Result<ExampleBuildResult> example_build(ExampleBuildConfig config);

    // ── Phase 34 — Performance Pass ─────────────

    // Run a specific micro-benchmark.
    [[nodiscard]]
    Result<BenchmarkResult> perf_benchmark(BenchmarkConfig config);

    // Get the current memory footprint of the engine and all modules.
    [[nodiscard]]
    Result<MemoryFootprint> perf_memory_footprint();

    // Initialise the trampoline arena allocator.
    [[nodiscard]]
    Result<void> perf_arena_init(ArenaConfig config = {});

    // Get arena allocator statistics.
    [[nodiscard]]
    Result<ArenaStats> perf_arena_stats();

    // Destroy the arena allocator and free all arena blocks.
    [[nodiscard]]
    Result<void> perf_arena_destroy();

    // Run all benchmarks and return a summary vector.
    [[nodiscard]]
    Result<std::vector<BenchmarkResult>> perf_benchmark_all(
        size_t iterations = 10000, uint32_t timeout_ms = 60000);

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
