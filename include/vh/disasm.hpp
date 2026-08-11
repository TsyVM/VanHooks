#pragma once

/**
 * vh/disasm.hpp — Disassembler public API
 *
 * Exposes the VanHooks embedded Zydis-backed disassembler to end users.
 * The types live in vanhooks::disasm::; this header brings them into vh::disasm::
 * via using-declarations and adds ergonomic free-function wrappers.
 *
 * Quick start:
 * ────────────
 *   #include <vh/disasm.hpp>
 *
 *   // Decode one instruction at a known runtime address:
 *   vh::disasm::Disassembler dis;
 *   auto insn = dis.decode_one(code_span, runtime_address);
 *   if (insn) {
 *       printf("%s  (%u bytes)\n", insn->mnemonic.c_str(), insn->length);
 *   }
 *
 *   // Print a function's prologue until the first branch:
 *   for (auto& i : vh::disasm::decode_until_branch(fn_ptr, 128)) {
 *       printf("  %016llx  %s\n", (unsigned long long)i.address,
 *              i.mnemonic.c_str());
 *   }
 *
 *   // Rewrite prologue bytes to a new location:
 *   auto rr = vh::disasm::rewrite(insns, original_va, new_va);
 *   if (rr && rr->clean) {
 *       // rr->code is ready to write to the new location
 *   }
 *
 * Architecture note:
 *   x86 / x64 — Zydis (accurate EVEX/VEX-aware decoder).
 *   ARM64      — internal fixed-width decoder (4-byte instructions).
 *   The active architecture is auto-detected from the running CPU; pass an
 *   explicit vh::disasm::Arch to override.
 */

#include <cstdint>
#include <cstddef>
#include <span>
#include <vector>
#include <string>

#include <vanhooks/disasm.hpp>
#include "result.hpp"

namespace vh::disasm {

// ─────────────────────────────────────────────
//  Re-export core types from vanhooks::disasm
// ─────────────────────────────────────────────

using Arch         = vanhooks::disasm::Arch;
using InsnKind     = vanhooks::disasm::InsnKind;
using Instruction  = vanhooks::disasm::Instruction;
using Disassembler = vanhooks::disasm::Disassembler;
using RewriteResult = vanhooks::disasm::RewriteResult;

[[nodiscard]] inline Arch detect_arch() noexcept {
    return vanhooks::disasm::detect_arch();
}

// ─────────────────────────────────────────────
//  rewrite — relocate a decoded instruction sequence
// ─────────────────────────────────────────────

/**
 * Rewrite @insns so that all RIP/PC-relative references remain valid after
 * the bytes are placed at @new_base instead of @original_base.
 *
 * This is the primary tool for building trampolines — copy prologue bytes to
 * a stub region, call rewrite() on them, then patch the stub in.
 *
 * @param insns         Instruction sequence decoded from @original_base.
 * @param original_base VA where the instructions currently live.
 * @param new_base      VA where the rewritten bytes will be placed.
 * @param arch          Override architecture; defaults to running CPU.
 * @returns             RewriteResult with patched bytes, or an error.
 */
[[nodiscard]]
inline Result<RewriteResult> rewrite(
    const std::vector<Instruction>& insns,
    uint64_t original_base,
    uint64_t new_base,
    Arch arch = vanhooks::disasm::detect_arch())
{
    return vanhooks::disasm::rewrite_for_relocation(insns, original_base, new_base, arch);
}

// ─────────────────────────────────────────────
//  Convenience free functions
// ─────────────────────────────────────────────

/**
 * Decode @count_bytes bytes starting at @code_ptr, stopping early at the
 * first terminal (unconditional jump or return) instruction.
 *
 * Returns all decoded instructions up to and including the terminal (or all
 * of @count_bytes if no terminal is found within that window).
 *
 * Useful for printing a function's prologue or computing trampoline size.
 */
[[nodiscard]]
inline std::vector<Instruction> decode_until_branch(
    const void* code_ptr,
    size_t      count_bytes,
    uint64_t    runtime_address = 0,
    Arch        arch = vanhooks::disasm::detect_arch())
{
    if (!code_ptr || count_bytes == 0) return {};

    if (runtime_address == 0)
        runtime_address = reinterpret_cast<uint64_t>(code_ptr);

    Disassembler dis(arch);
    auto code = std::span<const uint8_t>(
        static_cast<const uint8_t*>(code_ptr), count_bytes);

    std::vector<Instruction> result;
    size_t offset = 0;

    while (offset < count_bytes) {
        auto sub = code.subspan(offset);
        auto r   = dis.decode_one(sub, runtime_address + offset);
        if (!r) break;

        bool terminal = r->is_terminal();
        result.push_back(std::move(*r));
        offset += result.back().length;
        if (terminal) break;
    }
    return result;
}

/**
 * Decode at least @min_bytes of prologue from @code_ptr, never splitting
 * an instruction boundary — the minimal safe trampoline copy length.
 *
 * Returns an error if decoding fails before @min_bytes are accumulated.
 */
[[nodiscard]]
inline Result<std::vector<Instruction>> decode_prologue(
    const void* code_ptr,
    size_t      min_bytes,
    uint64_t    runtime_address = 0,
    Arch        arch = vanhooks::disasm::detect_arch())
{
    if (!code_ptr)
        return std::unexpected(vanhooks::Error::InvalidArgument);

    if (runtime_address == 0)
        runtime_address = reinterpret_cast<uint64_t>(code_ptr);

    // Give ourselves some headroom — a single x86 instruction is at most 15 bytes.
    size_t window = min_bytes + 64;
    auto code = std::span<const uint8_t>(
        static_cast<const uint8_t*>(code_ptr), window);

    Disassembler dis(arch);
    return dis.decode_min_bytes(code, runtime_address, min_bytes);
}

/**
 * Compute the minimum byte count that safely covers @min_bytes without
 * splitting an instruction (i.e., rounds up to the next instruction boundary).
 *
 * Returns the rounded-up byte count, or an error if decoding fails.
 */
[[nodiscard]]
inline Result<size_t> safe_copy_length(
    const void* code_ptr,
    size_t      min_bytes,
    uint64_t    runtime_address = 0,
    Arch        arch = vanhooks::disasm::detect_arch())
{
    if (!code_ptr)
        return std::unexpected(vanhooks::Error::InvalidArgument);

    if (runtime_address == 0)
        runtime_address = reinterpret_cast<uint64_t>(code_ptr);

    size_t window = min_bytes + 64;
    auto code = std::span<const uint8_t>(
        static_cast<const uint8_t*>(code_ptr), window);

    return vanhooks::disasm::find_safe_patch_point(code, runtime_address, min_bytes, arch);
}

/**
 * Format a decoded instruction as "ADDR: BYTES  MNEMONIC" for logging.
 *
 * Example output:
 *   0x7ff8a3c04010: 48 89 5c 24 08  mov qword ptr [rsp+0x8], rbx
 */
[[nodiscard]]
inline std::string format_insn(const Instruction& insn) {
    char buf[256];

    // Address
    int pos = std::snprintf(buf, sizeof(buf), "0x%016llx: ",
        static_cast<unsigned long long>(insn.address));

    // Raw bytes (up to 8, then ".. " for longer instructions)
    int show = std::min<int>(insn.length, 8);
    for (int i = 0; i < show && pos < static_cast<int>(sizeof(buf)) - 4; ++i) {
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, "%02x ", insn.bytes[i]);
    }
    if (insn.length > 8)
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, ".. ");

    // Pad to a fixed column
    while (pos < 50 && pos < static_cast<int>(sizeof(buf)) - 2)
        buf[pos++] = ' ';

    // Mnemonic
    std::snprintf(buf + pos, sizeof(buf) - pos, "%s", insn.mnemonic.c_str());

    return std::string(buf);
}

/**
 * Format an entire instruction sequence, one line per instruction.
 */
[[nodiscard]]
inline std::string format_listing(const std::vector<Instruction>& insns) {
    std::string out;
    out.reserve(insns.size() * 60);
    for (auto& i : insns) {
        out += format_insn(i);
        out += '\n';
    }
    return out;
}

} // namespace vh::disasm
