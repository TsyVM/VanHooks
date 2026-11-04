#pragma once

/**
 * vh/vigil/ac_profile.vh — Anti-cheat engine profiling & detection
 *
 * Detects which anti-cheat engines are active in the current process
 * or on the system, queries their known capabilities, and recommends
 * which VanHooks evasion modules to activate.
 *
 * Supported engines
 * ─────────────────
 *
 *   EAC         Easy Anti-Cheat (EpicGames / Kamu)
 *   BattlEye    BattlEye GmbH — kernel driver + user-mode service
 *   XignCode3   Wellbia.com — kernel driver + heartbeat
 *   Vanguard    Riot Games — always-on kernel driver (boots with OS)
 *   GameGuard   nProtect (INCA Internet) — kernel driver + heartbeat
 *   PunkBuster  Even Balance — user-mode, screenshot-based
 *   Ricochet    Activision — kernel driver (HGWC)
 *   Hyperion    Byfron (Roblox) — user-mode + kernel
 *   Mhyprot     HoYoverse — kernel driver (mhyprot2.sys)
 *   Warden      Blizzard — user-mode scanner
 *   FairFight   i3D.net — server-side statistical (no client component)
 *   Arxan       Irdeto — code virtualisation / anti-tamper
 *   EQU8        EQU8 — kernel driver + heartbeat
 *   Nexon       Nexon Game Security — kernel driver + heartbeat
 *   FACEIT      FACEIT Anti-Cheat — kernel driver + client
 *   VAC         Valve Anti-Cheat — user-mode scanner (Steam)
 *
 * Detection is passive — no registry writes, no file creation, no
 * network activity.  Pure observation of loaded modules, running
 * services, device objects, and known memory signatures.
 *
 * Platform: Windows (full), Linux (partial — EAC/BattlEye Proton).
 *           macOS returns Engine::Unknown.
 *
 * Requires: VH_ENABLE_AC_PROFILE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>

#include <cstdint>
#include <span>
#include <string_view>

namespace vh::ac {

// ─────────────────────────────────────────────────────────────────────────────
//  Engine identification
// ─────────────────────────────────────────────────────────────────────────────

enum class Engine : uint32_t {
    Unknown       = 0,
    EAC           = 1,    // Easy Anti-Cheat
    BattlEye      = 2,    // BattlEye
    XignCode3     = 3,    // Wellbia XIGNCODE3
    Vanguard      = 4,    // Riot Vanguard (vgk.sys)
    GameGuard     = 5,    // nProtect GameGuard
    PunkBuster    = 6,    // Even Balance PunkBuster
    Ricochet      = 7,    // Activision RICOCHET (atvi driver)
    Hyperion      = 8,    // Byfron / Roblox
    Mhyprot       = 9,    // HoYoverse mhyprot2
    Warden        = 10,   // Blizzard Warden
    FairFight     = 11,   // i3D.net (server-side only)
    Arxan         = 12,   // Irdeto Arxan
    EQU8          = 13,   // EQU8 anti-cheat
    Nexon         = 14,   // Nexon Game Security (BlackCipher)
    FACEIT        = 15,   // FACEIT Anti-Cheat (kernel driver)
    VAC           = 16,   // Valve Anti-Cheat (Steam)
};

constexpr uint32_t kEngineCount = 17;

VH_API std::string_view engine_name(Engine e) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Capability flags — what a given AC is known to check
// ─────────────────────────────────────────────────────────────────────────────

struct Capabilities {
    bool kernel_driver;       // Ring-0 component (minifilter, callbacks)
    bool always_on;           // Runs from boot, not just when game launches
    bool heartbeat;           // Periodic keepalive to game server
    bool memory_scan;         // Scans process virtual memory pages
    bool module_walk;         // Enumerates loaded modules (PEB.Ldr / NtQuerySystemInformation)
    bool integrity_check;     // Hashes .text sections against known-good
    bool stack_walk;          // Inspects thread call stacks for anomalies
    bool timing_analysis;     // Behavioural timing / statistical anomaly detection
    bool hypervisor;          // Uses VBS, trustlet, or custom hypervisor
    bool screenshot;          // Captures screen frames for server-side review
    bool driver_signing;      // Enforces driver signature requirements
    bool minifilter;          // Filesystem minifilter (blocks file access)
    bool etw_consumer;        // Registers as ETW real-time consumer
    bool cfg_enforced;        // Validates CFG bitmap on dispatches
    bool handle_trace;        // Monitors NtOpenProcess / NtReadVirtualMemory
    bool thread_creation;     // Monitors thread creation via PsSetCreateThreadNotifyRoutine
    bool image_load;          // Monitors image loads via PsSetLoadImageNotifyRoutine
    bool object_callback;     // ObRegisterCallbacks on process/thread objects
    bool registry_callback;   // CmRegisterCallback for registry access
    bool debug_object;        // Detects debug objects attached to process
    bool user_input_check;    // Validates input legitimacy (GetAsyncKeyState origin)
};

VH_API Capabilities capabilities(Engine e) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Detection — which engines are active right now
// ─────────────────────────────────────────────────────────────────────────────

/// A single detection result for one engine.
struct Detection {
    Engine              engine;
    uint32_t            confidence;    // 0–100  (% certainty)
    std::string_view    evidence;      // human-readable: "BEService.exe running"
};

/// Scan the environment and return all detected anti-cheat engines.
/// Results are sorted by confidence (highest first).
/// The returned span is valid until the next call to detect().
VH_API std::span<const Detection> detect() noexcept;

/// Quick check: is a specific engine present?  (Runs a targeted scan.)
VH_API bool is_present(Engine e) noexcept;

/// Detect the primary (highest-confidence) engine.
VH_API Engine primary() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Evasion strategy recommendation
// ─────────────────────────────────────────────────────────────────────────────

/// Techniques that VanHooks can apply, mapped to vigil module headers.
enum class Technique : uint32_t {
    PolymorphicTrampolines,     // core/polymorphic.vh
    EncryptedEngineState,       // core/engine_crypt.vh
    TamperDetection,            // core/tamper_detect.vh
    AutoRehook,                 // core/auto_rehook.vh
    ShadowPage,                 // vigil/shadow_page.vh
    CfgBypass,                  // vigil/cfg_bypass.vh
    InstrumentationCb,          // vigil/instrumentation_cb.vh
    TimingNormal,               // vigil/timing_normal.vh
    StackSpoof,                 // vigil/stack_spoof.vh
    CallstackSpoof,             // vigil/callstack_spoof.vh
    EtwtiBlind,                 // vigil/etwti_blind.vh
    PebMask,                    // vigil/peb_mask.vh
    ModuleStomp,                // vigil/module_stomp.vh
    ThreadHide,                 // vigil/thread_hide.vh
    SleepObf,                   // vigil/sleep_obf.vh
    HeapCrypt,                  // vigil/heap_crypt.vh
    MemGuard,                   // vigil/mem_guard.vh
    Unhook,                     // vigil/unhook.vh
    Syscalls,                   // vigil/syscalls.vh
    ApiHash,                    // vigil/api_hash.vh
    EptHook,                    // hooks/ept_hook.vh
    DriverFence,                // vigil/driver_fence.vh  (new)
    AcHeartbeat,                // vigil/ac_heartbeat.vh  (new)
    MemCloak,                   // vigil/mem_cloak.vh     (new)
};

/// Safety rating for a technique against a specific engine.
enum class Safety : uint8_t {
    Safe,           // No known detection vector
    Caution,        // Works but has edge-case detection risk
    Risky,          // Known partial detection — use with mitigations
    Detected,       // Known signatured — do not use
    NotApplicable,  // Technique is irrelevant to this engine
};

VH_API Safety is_safe(Engine e, Technique t) noexcept;

/// A recommended strategy: ordered list of techniques to activate.
struct Strategy {
    Engine      engine;
    uint8_t     count;
    struct Entry {
        Technique   technique;
        Safety      safety;
        uint8_t     priority;    // 1 = must-have, 2 = recommended, 3 = nice-to-have
    };
    Entry       entries[32];
};

VH_API Strategy recommend(Engine e) noexcept;

/// Convenience: apply all priority-1 and priority-2 techniques from
/// the recommended strategy.  Returns the number of modules activated.
/// Requires source license — SDK users call individual modules manually.
VH_API vh::Result<uint32_t> apply_strategy(Engine e) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Fingerprint database version
// ─────────────────────────────────────────────────────────────────────────────

struct Version {
    uint16_t    major;
    uint16_t    minor;
    uint16_t    patch;
    uint32_t    signature_count;    // total fingerprints across all engines
};

VH_API Version database_version() noexcept;

} // namespace vh::ac
