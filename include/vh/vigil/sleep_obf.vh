#pragma once

/**
 * vh/sleep_obf.vh — Sleep obfuscation.
 *
 * Encrypts a caller-specified memory region for the duration of a sleep so
 * an EDR / process-scanner walking committed pages during the sleep window
 * sees ciphertext instead of your code / heap.
 *
 * Mechanism
 * ---------
 *
 * The caller thread encrypts the region in place with ``SystemFunction032``
 * (RC4, exported from advapi32) and blocks on a manual-reset event.  A
 * timer-queue worker fires ``ms`` milliseconds later, decrypts the region,
 * and signals the event.  The caller wakes and returns.
 *
 * The decrypt runs on a Windows thread-pool worker thread whose stack is
 * outside the encrypted region, so the caller's own ``.text`` and heap can
 * safely be inside it.  The single hard constraint:
 *
 *   **The encrypted region must not contain any code any thread executes
 *   during the sleep window.**  For beacon-style payloads that's your
 *   beacon's ``.text`` and its own heap slices — never VanHooks' own code.
 *
 * A 16-byte fresh RC4 key is generated per sleep cycle via
 * ``BCryptGenRandom`` and never persisted.
 *
 * Quick start
 * -----------
 *
 *   #include <vh/vh.vh>
 *
 *   // Sleep 3 seconds with our main-module .text encrypted.
 *   HMODULE self = GetModuleHandleW(nullptr);
 *   MODULEINFO mi{}; GetModuleInformation(GetCurrentProcess(), self, &mi, sizeof(mi));
 *   vh::sleep_obf::sleep_encrypted(3000, mi.lpBaseOfDll, mi.SizeOfImage);
 *
 *   // For a single logical region (e.g. just .text of a specific module):
 *   vh::sleep_obf::sleep_encrypted(3000, {region_ptr, region_size});
 *
 * Platform: Windows.  POSIX returns ``Unsupported``.
 */

#include <vh/result.vh>
#include <vanhooks/vanhooks.vh>

#include <cstddef>
#include <cstdint>
#include <span>

namespace vh::sleep_obf {

/// Options for :cpp:func:`sleep_encrypted`.
struct Options {
    /// Change page protection to ``PAGE_READWRITE`` before encrypting and back
    /// to the original on decrypt (default).  Set to ``false`` if the region
    /// is already RW — one fewer syscall per cycle.
    bool toggle_protection = true;

    /// Optional caller-supplied key.  Default: fresh 16-byte random key each
    /// call, generated with ``BCryptGenRandom``.
    std::span<const std::uint8_t> key;

    /// Set an EXECUTE flag on the restored region.  Default: match the
    /// pre-sleep protection.  Set true if the region is executable and the
    /// caller wants to force the RX/RWX flag back.
    bool restore_executable_hint = true;
};

/**
 * Sleep for ``ms`` milliseconds with ``region`` encrypted for the whole
 * window.  Blocking; returns after the region has been decrypted and
 * original protection restored.
 */
[[nodiscard]] vh::Result<void>
sleep_encrypted(std::uint32_t ms, void* region, std::size_t size,
                Options opts = {}) noexcept;

/// span overload.
[[nodiscard]] inline vh::Result<void>
sleep_encrypted(std::uint32_t ms, std::span<std::uint8_t> region,
                Options opts = {}) noexcept
{
    return sleep_encrypted(ms, region.data(), region.size(), opts);
}

/**
 * Convenience — encrypt this process' main module ``.text`` for the sleep
 * window.  Useful for beacon-style payloads that live in the main image.
 */
[[nodiscard]] vh::Result<void>
sleep_encrypted_main_text(std::uint32_t ms, Options opts = {}) noexcept;

} // namespace vh::sleep_obf
