#pragma once

/**
 * vh/fwd.hpp
 * Forward declarations for the vh:: public API.
 * Include this for fast compilation when only types need to be named.
 */

namespace vh {

class Hook;
class Group;
class HookRegistry;
class Injection;
enum class InjectMethod : unsigned char;

namespace disasm {
    enum class Arch : unsigned char;
    enum class InsnKind : unsigned char;
    struct Instruction;
    class Disassembler;
    struct RewriteResult;
} // namespace disasm

namespace symbols {
    struct Symbol;
    struct SourceLocation;
} // namespace symbols

namespace config {
    struct Trampoline;
    struct API;
    struct IAT;
    struct PLT;
    struct VTable;
    struct Mid;
    struct Inject;
} // namespace config

namespace pe {
    struct Section;
    struct Export;
    struct Import;
    struct CodeCave;
    class  PeView;
} // namespace pe

namespace breakpoint {
    class  Breakpoint;
    enum class Action      : uint8_t;
    enum class HwCondition : uint8_t;
    enum class HwSize      : uint8_t;
} // namespace breakpoint

namespace callstack {
    struct Frame;
} // namespace callstack

namespace advanced {
    class Engine;
} // namespace advanced

} // namespace vh
