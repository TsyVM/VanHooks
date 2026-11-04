#pragma once

/**
 * vh/vigil/firmware_fence.vh — Firmware / UEFI awareness
 *
 * Advanced cheat tools persist at the firmware level:
 *
 *   * UEFI runtime driver implants
 *   * Secure Boot bypass / self-signed UEFI modules
 *   * SPI flash modification for persistent rootkits
 *   * ACPI table manipulation
 *   * SMM-based execution
 *
 * Anti-cheat engines verify firmware integrity via:
 *
 *   * Secure Boot state verification
 *   * UEFI variable enumeration
 *   * SMBIOS / firmware table analysis
 *   * TPM attestation chain checking
 *   * Boot log integrity verification
 *
 * This module provides:
 *
 *   1. Per-engine firmware verification profiles.
 *   2. Firmware check awareness — what each engine verifies.
 *   3. Secure Boot / TPM state querying.
 *
 * Platform: WIN32 for firmware table queries, stubs on POSIX.
 *
 * Requires: VH_ENABLE_FIRMWARE_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>

namespace vh::ac::firmware_fence {

enum class FirmwareCheck : uint32_t {
    SecureBootVerify    = 1u << 0,  // check Secure Boot state
    UEFIVariableEnum    = 1u << 1,  // enumerate UEFI variables
    SMBIOSAnalysis      = 1u << 2,  // analyse SMBIOS tables
    TPMAttestation      = 1u << 3,  // TPM PCR attestation
    BootLogIntegrity    = 1u << 4,  // Windows boot log (Measured Boot)
    ACPITableCheck      = 1u << 5,  // ACPI table verification
    FirmwareVersion     = 1u << 6,  // BIOS/UEFI version fingerprint
    DriverSigningPolicy = 1u << 7,  // kernel driver signing enforcement
    CodeIntegrityCheck  = 1u << 8,  // HVCI / CI policy verification
    VBSCheck            = 1u << 9,  // virtualisation-based security
};

struct FirmwareProfile {
    ac::Engine  engine;
    uint32_t    checks;             // bitmask of FirmwareCheck
    bool        requires_secure_boot;
    bool        requires_tpm;
    bool        requires_hvci;
};

struct SecureBootState {
    bool        supported;
    bool        enabled;
    bool        uefi_mode;          // true = UEFI, false = Legacy BIOS
};

/// Get the firmware verification profile for a specific AC engine.
VH_API FirmwareProfile profile_for(ac::Engine engine) noexcept;

/// Bitmask of firmware checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

/// Query the current Secure Boot state.
VH_API SecureBootState query_secure_boot() noexcept;

} // namespace vh::ac::firmware_fence
