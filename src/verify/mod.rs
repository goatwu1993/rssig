//! Authenticate parsed containers using explicit time, trust, and revocation policy.
//!
//! Parsing alone never establishes integrity or trust. Existing byte-oriented
//! entry points remain available; [`verify_parsed_pe`] reuses a parsed PE layout.

mod appx;
mod authenticode;
mod container;
mod integrity;
pub(crate) mod timestamp;

use crate::domain::*;
use crate::{
    appx::Appx,
    cab::Cab,
    format::{self, Format},
    msi::Msi,
    navx::Navx,
    pe::Pe,
    powershell::Powershell,
    trust::TrustStore,
    wsh::{Kind, Wsh},
};
use anyhow::Result;
use authenticode::verify_container;
use container::Container;

/// Explicit policy for verification; the engine never reads the clock or loads roots.
pub struct VerifyOptions<'a> {
    /// Configured trust anchors and CRLs. `None` explicitly selects integrity-only
    /// verification, reported without a trusted-chain claim.
    pub trust: Option<&'a TrustStore>,
    /// Require supplied CRLs when validating a trust chain.
    pub check_revocation: bool,
    /// Permit SHA-1 content/signature digests, never SHA-1 certificate/CRL chains.
    pub allow_sha1: bool,
    /// Caller-supplied validation time in Unix seconds.
    pub now: u64,
}

pub fn verify_pe(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Pe).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Detect the signed container from its bytes; file extensions are not trusted.
pub fn verify(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_detected(bytes, None, options)
}

/// Filename hints select ambiguous text formats; binary magic always wins.
pub(crate) fn verify_detected(
    bytes: &[u8],
    path: Option<&std::path::Path>,
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, format::detect(bytes, path)?).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify an MSI installer or MSP patch's embedded Authenticode signature.
///
/// Both use the MSI SIP and report `msi_authenticode`. An MSP is verified on its
/// own; this does not check applicability to an installation or apply the patch.
pub fn verify_msi(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Msi).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify a Microsoft Dynamics NAVX package with an embedded Authenticode signature.
pub fn verify_navx(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Navx).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

pub fn verify_cab(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Cab).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify a hash-comment PowerShell script with an embedded Authenticode block.
pub fn verify_powershell(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Powershell).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify XML-comment PowerShell Authenticode (.ps1xml), not XMLDSig.
pub fn verify_powershell_xml(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::PowershellXml).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify a detached CMS signature over the explicitly scoped RDP settings.
pub fn verify_rdp(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    crate::rdp::verify(bytes, options).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify an embedded-signature MSIX/AppX package or bundle and its embedded packages.
pub fn verify_appx(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Appx).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify Windows Script Host Authenticode, detecting the signature comment style.
pub fn verify_wsh(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    let kind = crate::wsh::detect(bytes)
        .map_err(|e| VerificationError::from_internal(e, ErrorCode::InvalidWsh, Stage::Wsh))?;
    verify_wsh_as(bytes, kind, options)
}
pub(crate) fn verify_wsh_as(
    bytes: &[u8],
    kind: Kind,
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Wsh(kind)).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

fn tagged<T>(result: Result<T>, code: ErrorCode, stage: Stage) -> Result<T> {
    result.map_err(|e| VerificationError::from_internal(e, code, stage).into())
}

fn verify_inner(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
    format: Format,
) -> Result<VerificationBundle> {
    let container = match format {
        Format::Rdp => return crate::rdp::verify(bytes, options),
        Format::Wsh(kind) => Container::Wsh(tagged(
            Wsh::parse(bytes, kind),
            ErrorCode::InvalidWsh,
            Stage::Wsh,
        )?),
        Format::Appx => Container::Appx(Box::new(tagged(
            Appx::parse(bytes),
            ErrorCode::InvalidAppx,
            Stage::Appx,
        )?)),
        Format::PowershellXml => Container::Powershell(tagged(
            Powershell::parse_xml(bytes),
            ErrorCode::InvalidPowershell,
            Stage::Powershell,
        )?),
        Format::Powershell => Container::Powershell(tagged(
            Powershell::parse(bytes),
            ErrorCode::InvalidPowershell,
            Stage::Powershell,
        )?),
        Format::Msi => Container::Msi(Box::new(Msi::parse(bytes)?)),
        Format::Pe => Container::Pe(Pe::parse(bytes).map_err(VerificationError::from)?),
        Format::Navx => Container::Navx(tagged(
            Navx::parse(bytes),
            ErrorCode::InvalidNavx,
            Stage::Navx,
        )?),
        Format::Cab => Container::Cab(tagged(
            Cab::parse(bytes),
            ErrorCode::InvalidCab,
            Stage::Cab,
        )?),
    };
    verify_container(bytes, options, format, container)
}

/// Verify a parsed PE without reparsing its headers. All hashes, CMS signatures,
/// timestamps, trust chains, and configured CRLs are still checked.
///
/// The parsed value has private fields and borrows immutable bytes, so it
/// cannot substitute altered bytes or caller-supplied verification assertions.
///
/// ```
/// use rssig::{parse::Pe, verify::{VerifyOptions, verify_parsed_pe}};
/// # let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/good-pe64.exe"));
/// let pe = Pe::parse(bytes)?;
/// // Explicit integrity-only policy. Supply a TrustStore for trusted verification.
/// let options = VerifyOptions {
///     trust: None, check_revocation: false, allow_sha1: false, now: 1800000000,
/// };
/// let report = verify_parsed_pe(pe, &options)?;
/// assert!(!report.signatures[0].chain_trusted);
/// # Ok::<(), rssig::VerificationError>(())
/// ```
pub fn verify_parsed_pe(
    pe: crate::parse::Pe<'_>,
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_container(pe.data, options, Format::Pe, Container::Pe(pe)).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}
