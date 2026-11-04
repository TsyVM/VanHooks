#pragma once

/**
 * vh/vigil/cert_fence.vh — Code signing & certificate awareness
 *
 * Anti-cheat engines verify digital signatures on loaded modules:
 *
 *   * Authenticode signature validation (WinVerifyTrust)
 *   * Certificate chain trust anchors (Microsoft, game publisher)
 *   * Catalog-signed system DLLs (CryptCATAdminCalcHashFromFileHandle)
 *   * Unsigned / self-signed module detection
 *   * Certificate pinning for AC's own binaries
 *
 * This module provides:
 *
 *   1. Per-engine signing enforcement profiles.
 *   2. Module signature audit — check loaded modules' trust state.
 *   3. Certificate detail extraction.
 *
 * Platform: Windows.  POSIX returns Unsupported.
 *
 * Requires: VH_ENABLE_CERT_FENCE  (CMake option, default ON)
 */

#include <vh/export.vh>
#include <vh/result.vh>
#include <vh/vigil/ac_profile.vh>

#include <cstdint>
#include <string>
#include <vector>

namespace vh::ac::cert_fence {

// ─────────────────────────────────────────────────────────────────────────────
//  Signature trust state
// ─────────────────────────────────────────────────────────────────────────────

enum class TrustState : uint8_t {
    Signed,             // valid Authenticode or catalog signature
    SignedMicrosoft,     // signed by Microsoft root
    SignedPublisher,     // signed by a known game publisher
    SelfSigned,         // self-signed certificate
    Unsigned,           // no signature at all
    InvalidSignature,   // signature present but broken / revoked
    CatalogSigned,      // not embedded, but present in a system catalog
};

struct CertInfo {
    std::string     subject;        // CN from leaf certificate
    std::string     issuer;         // CN from issuing CA
    std::string     serial;         // hex serial number
    std::string     thumbprint;     // SHA1 thumbprint hex
    uint64_t        not_before;     // FILETIME as uint64
    uint64_t        not_after;
    bool            is_expired;
};

struct ModuleSignature {
    std::string     module_name;
    std::string     module_path;
    TrustState      trust;
    CertInfo        cert;           // populated if Signed*
    bool            is_system;      // lives in System32/SysWOW64
    bool            is_ac_module;   // belongs to a known AC engine
};

/// Check the signing state of a specific loaded module.
VH_API vh::Result<ModuleSignature> check_module(std::string_view module_name) noexcept;

/// Audit all loaded modules for signing state.
VH_API vh::Result<std::vector<ModuleSignature>> audit_all() noexcept;

/// Quick check: is a specific module unsigned?
VH_API bool is_unsigned(std::string_view module_name) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-engine signing enforcement
// ─────────────────────────────────────────────────────────────────────────────

enum class CertCheck : uint32_t {
    AuthenticodeVerify  = 1u << 0,
    CatalogLookup       = 1u << 1,
    CertChainWalk       = 1u << 2,
    PinCheck            = 1u << 3,  // AC pins its own cert
    UnsignedBlock       = 1u << 4,  // block unsigned modules
    SelfSignedBlock     = 1u << 5,
    TimestampVerify     = 1u << 6,
    RevocationCheck     = 1u << 7,
};

/// Bitmask of cert checks a specific AC engine performs.
VH_API uint32_t checks_by(ac::Engine engine) noexcept;

} // namespace vh::ac::cert_fence
