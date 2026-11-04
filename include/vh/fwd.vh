#pragma once

/**
 * vh/fwd.vh
 * Forward declarations for the vh:: public API.
 * Include this for fast compilation when only types need to be named.
 */

#include <vh/export.vh>

namespace vh {

class Hook;
class Group;
class HookRegistry;
class scoped_hook;
class Injection;
enum class InjectMethod : unsigned char;

// disasm types are aliases of vanhooks::disasm:: — see vh/disasm.vh
namespace disasm {}

// symbols types are aliases of vanhooks::symbols:: — see vh/symbols.vh
namespace symbols {}

namespace config {
    struct Trampoline;
    struct API;
    struct IAT;
    struct PLT;
    struct GOT;
    struct VTable;
    struct Mid;
    struct HwBp;
    struct PageGuard;
    struct IC;
    struct EAT;
    struct Syscall;
    struct TlsCallback;
    struct Exception;
    struct ThreadLocal;
    struct SoftBp;
    struct Inject;
} // namespace config

// CallSiteOptions lives in vanhooks:: (the internal namespace) so forward-declare
// it there.  vh/vh.vh pulls in the full definition via vanhooks/vanhooks.vh.
} // namespace vh
namespace vanhooks { struct CallSiteOptions; }
namespace vh {

// pe types are aliases of vanhooks::pe:: — see vh/pe.vh
namespace pe {}

// breakpoint types are aliases of vanhooks::breakpoint:: — see vh/breakpoint.vh
namespace breakpoint {}

// callstack types are aliases of vanhooks::callstack:: — see vh/callstack.vh
namespace callstack {}

// advanced::Engine is a using alias — see vh/advanced.vh
namespace advanced {}

namespace unhook          { struct DiffRegion; struct DiffReport; struct RestoreReport; struct Options; }
namespace syscalls        { struct SsnResult; enum class ResolveMode : uint8_t; enum class StubKind : uint8_t; }
namespace api_hash        { template<uint32_t, uint32_t> struct Resolver; }
namespace telemetry       { struct PatchOutcome; }
namespace sleep_obf       { struct Options; }
namespace callstack_spoof { namespace detail { class ScopedSpoof; } }
namespace thread_hide     { }
namespace peb_mask        { enum Flags : uint32_t; }
namespace module_stomp    { struct Stomp; struct Options; }
namespace veh_hook        { struct Handle; struct Options; }

// ── Extended injection catalogue ──────────────────────────────────────────────
namespace inject_ex       { struct RemoteHandle; }

// ── Phase 39: macOS deep support ─────────────────────────────────────────────
namespace macho_vigil     { struct DyldImageInfo; struct SectionInfo; }
namespace sip_aware       { struct SipInfo; }
namespace hardened_runtime { struct RuntimeInfo; }
namespace kext_enum       { struct KextInfo; }
namespace pac_aware       { struct PacInfo; }

// ── Phase 40: Linux deep support ─────────────────────────────────────────────
namespace linux_vigil     { struct ModuleInfo; struct MemoryRegion; struct ThreadInfo; }
namespace procfs_vigil    { struct FdInfo; struct CgroupInfo; struct NamespaceInfo; }
namespace ebpf_aware      { struct BpfProgInfo; struct BpfMapInfo; }
namespace landlock_aware  { struct LandlockInfo; }
namespace proton_aware    { struct WineInfo; }
namespace selinux_aware   { struct MacInfo; }

// ── Phase 41: Mobile support ─────────────────────────────────────────────────
namespace android_hook    { struct NativeHookInfo; struct ArtMethodInfo; }
namespace android_inject  { struct InjectionResult; }
namespace android_ac_aware { struct SafetyNetInfo; struct RootDetectionInfo; struct AcModuleInfo; }
namespace ios_research    { struct JailbreakInfo; struct ObjcMethodInfo; }

} // namespace vh
