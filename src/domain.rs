//! Serializable public results. Machine consumers match codes, never error prose.
use alloc::collections::BTreeMap;
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::fmt;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidPe,
    InvalidMsi,
    InvalidCab,
    InvalidNavx,
    NavxDigestMismatch,
    InvalidPowershell,
    InvalidWsh,
    InvalidRdp,
    InvalidAppx,
    UnsupportedAppx,
    AppxDigestMismatch,
    BlockHashMismatch,
    AppxPublisherMismatch,
    UnsupportedRdpScope,
    ScriptDigestMismatch,
    CabDigestMismatch,
    PackageDigestMismatch,
    ExtendedDigestMismatch,
    Unsigned,
    InvalidCertificateTable,
    MalformedCms,
    ResourceLimitExceeded,
    UnsupportedAlgorithm,
    WeakAlgorithm,
    ImageDigestMismatch,
    PageHashMismatch,
    InvalidSignature,
    AmbiguousSignerCertificate,
    ContentDigestMismatch,
    InvalidTimestamp,
    TimestampImprintMismatch,
    TimestampInFuture,
    CertificateExpired,
    CertificateNotYetValid,
    UntrustedRoot,
    InvalidEku,
    InvalidKeyUsage,
    CertificateRevoked,
    CrlExpired,
    CrlNotYetValid,
    InvalidCrlSignature,
    RevocationUnknown,
    CrlFetchFailed,
    CrlFetchDenied,
    InvalidCrl,
    InvalidCertificate,
    CertificateChainInvalid,
    ReadFailed,
    InvalidArguments,
    Configuration,
    InvalidTestSuite,
    TestAssertionFailed,
    InternalError,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Input,
    Pe,
    CertificateTable,
    Cms,
    ImageDigest,
    Msi,
    Cab,
    Navx,
    Powershell,
    Wsh,
    Rdp,
    Appx,
    BlockMap,
    ScriptDigest,
    PackageDigest,
    PageHashes,
    Timestamp,
    Certificate,
    CertificateChain,
    Revocation,
    Configuration,
    Arguments,
    TestSuite,
}

/// RFC 9457 members shared by error objects and failed command documents.
/// CLI output has no HTTP status or occurrence URI, so those optional members
/// are omitted. The type URI is the primary machine-readable identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub detail: String,
}
impl ProblemDetails {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        let code_name = serde_json::to_value(code).expect("error code serializes");
        Self {
            type_uri: format!(
                "https://github.com/goatwu1993/rssig/blob/main/docs/problems.md#{}",
                code_name.as_str().expect("error code is a string")
            ),
            title: code.title().into(),
            detail: detail.into(),
        }
    }
}
impl ErrorCode {
    pub fn title(self) -> &'static str {
        match self {
            Self::InvalidAppx => "Invalid MSIX/AppX package",
            Self::UnsupportedAppx => "Unsupported MSIX/AppX package",
            Self::AppxDigestMismatch => "MSIX/AppX package digest mismatch",
            Self::BlockHashMismatch => "Block-map hash mismatch",
            Self::AppxPublisherMismatch => "Package publisher mismatch",
            Self::InvalidRdp => "Invalid RDP file",
            Self::UnsupportedRdpScope => "Unsupported RDP signature scope",
            Self::InvalidWsh => "Invalid Windows Script Host file",
            Self::InvalidPowershell => "Invalid PowerShell script",
            Self::ScriptDigestMismatch => "Script digest mismatch",
            Self::InvalidNavx => "Invalid NAVX container",
            Self::NavxDigestMismatch => "NAVX digest mismatch",
            Self::InvalidCab => "Invalid CAB container",
            Self::CabDigestMismatch => "CAB digest mismatch",
            Self::InvalidMsi => "Invalid MSI container",
            Self::PackageDigestMismatch => "MSI package digest mismatch",
            Self::ExtendedDigestMismatch => "MSI extended digest mismatch",
            Self::InvalidPe => "Invalid PE image",
            Self::Unsigned => "Missing embedded signature",
            Self::InvalidCertificateTable => "Invalid certificate table",
            Self::ResourceLimitExceeded => "Verification resource limit exceeded",
            Self::MalformedCms => "Malformed CMS data",
            Self::UnsupportedAlgorithm => "Unsupported algorithm",
            Self::WeakAlgorithm => "Weak algorithm disallowed",
            Self::ImageDigestMismatch => "PE image digest mismatch",
            Self::PageHashMismatch => "Page hash mismatch",
            Self::AmbiguousSignerCertificate => "Ambiguous signer certificate",
            Self::InvalidSignature => "Invalid signature",
            Self::ContentDigestMismatch => "Content digest mismatch",
            Self::InvalidTimestamp => "Invalid timestamp",
            Self::TimestampImprintMismatch => "Timestamp imprint mismatch",
            Self::TimestampInFuture => "Timestamp is in the future",
            Self::CertificateExpired => "Certificate expired",
            Self::CertificateNotYetValid => "Certificate not yet valid",
            Self::UntrustedRoot => "Untrusted root certificate",
            Self::InvalidEku => "Invalid extended key usage",
            Self::InvalidKeyUsage => "Invalid key usage",
            Self::CertificateRevoked => "Certificate revoked",
            Self::CrlExpired => "CRL expired",
            Self::CrlNotYetValid => "CRL not yet valid",
            Self::InvalidCrlSignature => "Invalid CRL signature",
            Self::CrlFetchFailed => "CRL retrieval failed",
            Self::CrlFetchDenied => "CRL retrieval denied",
            Self::RevocationUnknown => "Revocation status unknown",
            Self::InvalidCrl => "Invalid CRL",
            Self::InvalidCertificate => "Invalid certificate",
            Self::CertificateChainInvalid => "Invalid certificate chain",
            Self::ReadFailed => "Input read failed",
            Self::InvalidArguments => "Invalid arguments",
            Self::Configuration => "Invalid configuration",
            Self::InvalidTestSuite => "Invalid testcase suite",
            Self::TestAssertionFailed => "Testcase assertions failed",
            Self::InternalError => "Internal error",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationError {
    #[serde(flatten)]
    pub problem: Box<ProblemDetails>,
    pub code: ErrorCode,
    pub stage: Stage,
    pub message: String,
    pub details: BTreeMap<String, Value>,
    pub causes: Vec<String>,
}
impl VerificationError {
    pub fn new(code: ErrorCode, stage: Stage, message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            problem: Box::new(ProblemDetails::new(code, &message)),
            code,
            stage,
            message,
            details: BTreeMap::new(),
            causes: Vec::new(),
        }
    }
    pub fn detail(mut self, key: &str, value: impl Serialize) -> Self {
        self.details.insert(
            key.into(),
            serde_json::to_value(value).expect("domain detail serializes"),
        );
        self
    }
    /// Preserve explicitly typed causes across internal anyhow contexts.
    pub fn from_internal(error: anyhow::Error, code: ErrorCode, stage: Stage) -> Self {
        let error = match error.downcast::<crate::parse::Error>() {
            Ok(error) => return error.into(),
            Err(error) => error,
        };
        if let Some(typed) = error.chain().find_map(|e| e.downcast_ref::<Self>()) {
            let mut typed = typed.clone();
            typed.causes = error.chain().map(ToString::to_string).collect();
            return typed;
        }
        let mut result = Self::new(code, stage, format!("{error:#}"));
        result.causes = error.chain().map(ToString::to_string).collect();
        result
    }
}
impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl core::error::Error for VerificationError {}

// Keep report policy at the verification boundary; the parser has no dependency
// on domain types or serialization. Preserve the existing CLI error contract.
impl From<crate::parse::Error> for VerificationError {
    fn from(error: crate::parse::Error) -> Self {
        use crate::parse::ErrorKind;
        let (code, stage) = match error.kind() {
            ErrorKind::InvalidMsi => (ErrorCode::InvalidMsi, Stage::Msi),
            ErrorKind::UnsignedMsi => (ErrorCode::Unsigned, Stage::Msi),
            ErrorKind::InvalidAppx => (ErrorCode::InvalidAppx, Stage::Appx),
            ErrorKind::UnsupportedAppx => (ErrorCode::UnsupportedAppx, Stage::Appx),
            ErrorKind::UnsignedAppx => (ErrorCode::Unsigned, Stage::Appx),
            ErrorKind::InvalidPowershell => (ErrorCode::InvalidPowershell, Stage::Powershell),
            ErrorKind::UnsignedPowershell => (ErrorCode::Unsigned, Stage::Powershell),
            ErrorKind::InvalidWsh | ErrorKind::UnsupportedWsfXml => {
                (ErrorCode::InvalidWsh, Stage::Wsh)
            }
            ErrorKind::UnsignedWsh => (ErrorCode::Unsigned, Stage::Wsh),
            ErrorKind::InvalidRdp => (ErrorCode::InvalidRdp, Stage::Rdp),
            ErrorKind::UnsignedRdp => (ErrorCode::Unsigned, Stage::Rdp),
            ErrorKind::UnsupportedRdpScope => (ErrorCode::UnsupportedRdpScope, Stage::Rdp),
            ErrorKind::InvalidPe => (ErrorCode::InvalidPe, Stage::Pe),
            ErrorKind::Unsigned => (ErrorCode::Unsigned, Stage::Pe),
            ErrorKind::InvalidCab => (ErrorCode::InvalidCab, Stage::Cab),
            ErrorKind::UnsignedCab => (ErrorCode::Unsigned, Stage::Cab),
            ErrorKind::InvalidNavx => (ErrorCode::InvalidNavx, Stage::Navx),
            ErrorKind::UnsignedNavx => (ErrorCode::Unsigned, Stage::Navx),
            ErrorKind::InvalidCertificateTable => {
                (ErrorCode::InvalidCertificateTable, Stage::CertificateTable)
            }
            ErrorKind::MalformedCms | ErrorKind::InspectionLimit => {
                (ErrorCode::MalformedCms, Stage::Cms)
            }
        };
        let scope = error.rdp_scope_entry().map(ToOwned::to_owned);
        let mut result = Self::from_internal(error.inner, code, stage);
        if let Some(scope) = scope {
            result = result.detail("scope", scope);
        }
        result
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NameAttribute {
    pub oid: String,
    pub name: Option<String>,
    pub value: Option<String>,
    pub asn1_tag: String,
    pub raw_value_hex: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistinguishedName {
    pub display: String,
    pub common_names: Vec<String>,
    pub organizations: Vec<String>,
    pub organizational_units: Vec<String>,
    pub countries: Vec<String>,
    /// Preserves RDN grouping, order, duplicate attributes, and unknown OIDs.
    pub rdns: Vec<Vec<NameAttribute>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidReport {
    pub oid: String,
    pub name: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EkuReport {
    pub critical: bool,
    pub usages: Vec<OidReport>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyUsageReport {
    pub critical: bool,
    pub usages: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicConstraintsReport {
    pub critical: bool,
    pub ca: bool,
    pub path_length: Option<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtensionReport {
    pub oid: String,
    pub critical: bool,
    pub value_der_hex: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateReport {
    pub sha256: String,
    pub der_hex: String,
    pub serial_number: String,
    pub version: u8,
    pub subject: DistinguishedName,
    pub issuer: DistinguishedName,
    pub not_before: u64,
    pub not_after: u64,
    pub public_key_algorithm: OidReport,
    pub signature_algorithm: OidReport,
    pub extended_key_usage: Option<EkuReport>,
    pub key_usage: Option<KeyUsageReport>,
    pub basic_constraints: Option<BasicConstraintsReport>,
    pub extensions: Vec<ExtensionReport>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokedCertificateReport {
    pub serial_number: String,
    pub revocation_time: u64,
    pub extensions: Vec<ExtensionReport>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrlReport {
    pub sha256: String,
    pub der_hex: String,
    pub issuer: DistinguishedName,
    pub this_update: u64,
    pub next_update: Option<u64>,
    pub signature_algorithm: OidReport,
    /// A supplied artifact is not necessarily selected by path validation.
    pub role: String,
    pub revoked_certificates: Vec<RevokedCertificateReport>,
    pub extensions: Vec<ExtensionReport>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    Good,
    NotChecked,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationReport {
    pub status: RevocationStatus,
    pub method: Option<String>,
    pub crls: Vec<CrlReport>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustReport {
    pub validation_time: u64,
    pub required_eku: OidReport,
    pub chain: Vec<CertificateReport>,
    pub revocation: RevocationReport,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnverifiedCertificateChoice {
    /// The context-specific ASN.1 tag (160 through 163), including constructed bit.
    pub tag: u8,
    /// Complete original DER, hex encoded. Not authenticated or used for trust.
    pub der: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimestampReport {
    /// Exact decimal digits after the seconds, without a leading decimal point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fractional_seconds: Option<String>,
    pub kind: String,
    pub signing_time: u64,
    pub certificate: CertificateReport,
    pub trust: Option<TrustReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unverified_certificate_choices: Vec<UnverifiedCertificateChoice>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DigestReport {
    pub algorithm: String,
    pub expected: String,
    pub computed: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureReport {
    pub subject: String,
    pub digest_algorithm: String,
    pub certificate_sha256: String,
    pub timestamp: Option<u64>,
    pub chain_trusted: bool,
    pub revocation_checked: bool,
    pub nested_depth: usize,
    pub certificate: CertificateReport,
    pub embedded_certificates: Vec<CertificateReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unverified_certificate_choices: Vec<UnverifiedCertificateChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<DigestReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_digest: Option<DigestReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_digest: Option<DigestReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_digest: Option<DigestReport>,
    pub page_hashes: Option<DigestReport>,
    pub trust: Option<TrustReport>,
    pub timestamp_verification: Option<TimestampReport>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RdpValueType {
    #[serde(rename = "s")]
    String,
    #[serde(rename = "i")]
    Integer,
    #[serde(rename = "b")]
    Binary,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RdpSetting {
    pub name: String,
    pub value_type: RdpValueType,
    pub value: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RdpCoverage {
    pub full_file_signed: bool,
    pub signscope: Vec<String>,
    pub signed_settings: Vec<RdpSetting>,
    pub unsigned_settings: Vec<RdpSetting>,
    pub canonical_sha256: String,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppxKind {
    #[default]
    Package,
    Bundle,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppxIdentity {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub processor_architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppxBlockMapReport {
    pub algorithm: String,
    pub files_verified: usize,
    pub blocks_verified: usize,
    pub uncompressed_bytes: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppxComponentReport {
    pub component: String,
    pub digest: DigestReport,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppxCatalogReport {
    pub sha256: String,
    pub signature_verified: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppxBundlePackageReport {
    pub file_name: String,
    pub package_type: String,
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    pub version: String,
    pub offset: usize,
    pub size: usize,
    pub verification: Box<VerificationBundle>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppxReport {
    #[serde(default)]
    pub kind: AppxKind,
    pub identity: AppxIdentity,
    pub block_map: AppxBlockMapReport,
    pub components: Vec<AppxComponentReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_integrity_catalog: Option<AppxCatalogReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_packages: Option<Vec<AppxBundlePackageReport>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrlRetrievalArtifact {
    pub url: String,
    pub final_url: String,
    pub sha256: String,
    pub bytes: usize,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrlRetrievalReport {
    /// Retrieved artifacts are untrusted evidence; this is not per-CRL verification status.
    pub artifacts: Vec<CrlRetrievalArtifact>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationBundle {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_retrieval: Option<CrlRetrievalReport>,
    pub format: String,
    pub validation_time: u64,
    pub file_sha256: String,
    pub signatures: Vec<SignatureReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdp: Option<RdpCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appx: Option<Box<AppxReport>>,
}
// Preserve convenient library indexing while returning a named domain bundle.
impl core::ops::Deref for VerificationBundle {
    type Target = [SignatureReport];
    fn deref(&self) -> &Self::Target {
        &self.signatures
    }
}
#[cfg(feature = "std")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileSuccess {
    pub file: std::path::PathBuf,
    pub ok: bool,
    #[serde(flatten)]
    pub verification: VerificationBundle,
}
/// Inspection metadata only. No field in this report establishes integrity or trust.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParseReport {
    /// `pe` for an embedded PE envelope, or `cms` for standalone DER SignedData.
    pub format: String,
    pub verification_performed: bool,
    pub signatures: Vec<ParsedCmsReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedCmsReport {
    pub version_der: String,
    pub content_type: String,
    pub content_der: Option<String>,
    pub digest_algorithms: Vec<ParsedAlgorithmReport>,
    pub certificate_choices: Vec<ParsedCertificateChoice>,
    /// Raw, untrusted revocation choices, not validated or configured CRLs.
    pub revocation_choices_der: Vec<String>,
    /// Raw SignerInfo bodies; recursive metadata is separate in `inspection`.
    pub signer_infos_der: Vec<String>,
    /// Bounded, unauthenticated recursive inspection.
    pub inspection: ParsedCmsInspection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedAlgorithmReport {
    pub oid: String,
    pub der: String,
    pub parameters_der: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedCertificateChoice {
    pub tag: u8,
    pub der: String,
    /// Decoded metadata for X.509 choices; opaque alternatives remain raw DER.
    pub certificate: Option<CertificateReport>,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParseFileSuccess {
    pub file: std::path::PathBuf,
    pub ok: bool,
    #[serde(flatten)]
    pub parse: ParseReport,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileFailure {
    pub file: std::path::PathBuf,
    pub ok: bool,
    pub error: VerificationError,
}
#[cfg(feature = "std")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FileResult {
    Success(FileSuccess),
    Failure(FileFailure),
}
/// Per-file inspection outcome, separate from authenticated verification results.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParseFileResult {
    Success(ParseFileSuccess),
    Failure(FileFailure),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandReport<T> {
    #[serde(flatten)]
    pub problem: Option<ProblemDetails>,
    pub schema_version: u32,
    pub command: String,
    pub ok: bool,
    pub results: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<VerificationError>,
}
impl<T> CommandReport<T> {
    pub fn failure(command: impl Into<String>, error: VerificationError) -> Self {
        Self {
            problem: Some(error.problem.as_ref().clone()),
            schema_version: 1,
            command: command.into(),
            ok: false,
            results: vec![],
            error: Some(error),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationReport {
    pub schema_version: u32,
    pub command: String,
    pub ok: bool,
    pub text: String,
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Recursive structural metadata; no field establishes a verified signing time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedCmsInspection {
    pub signers: Vec<ParsedSignerInspection>,
    pub tst_info: Option<ParsedTstInfo>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedSignerInspection {
    pub der: String,
    pub children: Vec<ParsedChildInspection>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedChildInspection {
    pub kind: String,
    pub value_der: String,
    pub cms: Option<Box<ParsedCmsReport>>,
    pub countersigner: Option<ParsedSignerInspection>,
    pub parsed_time: Option<ParsedTimeReport>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedTimeReport {
    pub der: String,
    pub unix_seconds: u64,
    pub fractional_seconds: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedTstInfo {
    pub der: String,
    pub policy: String,
    pub imprint_algorithm: ParsedAlgorithmReport,
    pub imprint: String,
    pub serial_number_der: String,
    pub parsed_time: ParsedTimeReport,
    pub optional_fields_der: Vec<String>,
}
