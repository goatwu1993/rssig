//! Serializable public results. Machine consumers match codes, never error prose.
use alloc::collections::BTreeMap;
use alloc::{
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
    CrlFetchAborted,
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
            Self::CrlFetchAborted => "CRL retrieval aborted",
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
    ///
    /// The outermost typed layer of the chain is the result, whether it is
    /// the error, a context added to it or another error's `source()`: a
    /// `VerificationError` as it is, a `parse::Error` with the code and stage
    /// of its kind (CLI candidate rule `typed-layer`). A parser error's kind is
    /// the default for its own chain: a typed layer in it decides instead, as
    /// `parse::Error::new` lets a nested parser error's kind stand. `code` and
    /// `stage` are used only when the chain has no typed layer. A context is found in
    /// `error` and in a parser error's own chain; one inside an anyhow error
    /// that another error type holds is out of anyhow's reach.
    pub(crate) fn from_internal(error: anyhow::Error, code: ErrorCode, stage: Stage) -> Self {
        Self::from_chain(&error, code, stage, Vec::new(), None)
    }

    /// `causes` holds the messages of the layers above `error`. They come
    /// first, then the typed layer's causes: an earlier conversion's, or its
    /// message when none did (a `VerificationError` has no source), or a
    /// parser error's own; then, below a typed context, the message of each
    /// entry of the error it was added to. The summary of the parser error
    /// that decides is not a cause, as when it is converted directly.
    /// `scope` is an unsupported RDP signscope parser error's `details.scope`,
    /// added only when its own kind decides.
    fn from_chain(
        error: &anyhow::Error,
        code: ErrorCode,
        stage: Stage,
        mut causes: Vec<String>,
        scope: Option<&str>,
    ) -> Self {
        // anyhow finds a context by type but not its place in the chain.
        let typed_context = error.downcast_ref::<Self>();
        let parser_context = error.downcast_ref::<crate::parse::Error>();
        let mut chain = error.chain();
        while let Some(cause) = chain.next() {
            let typed = cause
                .downcast_ref::<Self>()
                .or_else(|| typed_context.filter(|c| context_entry(cause, *c)));
            if let Some(typed) = typed {
                let mut typed = typed.clone();
                if typed.causes.is_empty() {
                    causes.push(typed.message.clone());
                } else {
                    causes.append(&mut typed.causes);
                }
                causes.extend(chain.map(ToString::to_string));
                typed.causes = causes;
                return typed;
            }
            let (parser, below) = match cause.downcast_ref::<crate::parse::Error>() {
                // Its source is its own chain, which converting it walks.
                Some(parser) => (parser, Vec::new()),
                None => match parser_context.filter(|c| context_entry(cause, *c)) {
                    Some(parser) => (parser, chain.map(ToString::to_string).collect()),
                    None => {
                        causes.push(cause.to_string());
                        continue;
                    }
                },
            };
            let mut result = Self::from_parser(parser, causes);
            result.causes.extend(below);
            return result;
        }
        let mut result = Self::new(code, stage, format!("{error:#}"));
        result.causes = causes;
        if let Some(scope) = scope {
            result = result.detail("scope", scope);
        }
        result
    }

    fn from_parser(error: &crate::parse::Error, causes: Vec<String>) -> Self {
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
        let scope = (error.kind() == ErrorKind::UnsupportedRdpScope)
            .then(|| error.rdp_scope_entry())
            .flatten();
        Self::from_chain(&error.inner, code, stage, causes, scope)
    }
}

/// Whether `entry` is the chain entry anyhow shows for the context `value`.
/// anyhow keeps a context inside its entry, beside the error it was added to
/// (held inline, or pointed to), so the entry that holds `value` while its
/// source does not is that context's. The unit test
/// `a_verification_error_attached_as_a_context_is_recognised` fails if anyhow
/// stops storing contexts this way.
fn context_entry<T>(entry: &dyn core::error::Error, value: &T) -> bool {
    let at = core::ptr::from_ref(value).addr();
    let holds = |entry: &dyn core::error::Error| {
        let start = core::ptr::from_ref(entry).cast::<u8>().addr();
        (start..start + core::mem::size_of_val(entry)).contains(&at)
    };
    holds(entry) && !entry.source().is_some_and(holds)
}
impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl core::error::Error for VerificationError {}

// Keep report construction at the verification boundary; the parser has no dependency
// on domain types or serialization. Preserve the existing CLI error contract.
impl From<crate::parse::Error> for VerificationError {
    fn from(error: crate::parse::Error) -> Self {
        Self::from_parser(&error, Vec::new())
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
/// An extension the certificate report decodes (basicConstraints, keyUsage or
/// extKeyUsage) and could not. The report's field for it is `None`, and each
/// instance stays in `extensions` as DER (PATH-015). The report judges nothing:
/// PATH-013 and PATH-014 fail a path certificate that has one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndecodedExtension {
    pub oid: String,
    pub reason: UndecodedReason,
}
/// Why the report could not decode an extension. The names are those of
/// `details.reason` in a PATH-013 or PATH-014 failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UndecodedReason {
    /// The value does not decode as the extension.
    MalformedExtension,
    /// The certificate carries the extension more than once, so no one
    /// instance is its value; none is decoded.
    RepeatedExtension,
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
    /// The extensions among the three above that are present and could not
    /// be decoded, basicConstraints first, then keyUsage, then extKeyUsage;
    /// left out when there is none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undecoded_extensions: Vec<UndecodedExtension>,
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
    /// Whole-second time at which the selected chain was validated.
    pub validation_time: u64,
    /// The signer has the lifetime-signing EKU, so its chain was validated at
    /// the validation time rather than at the timestamp.
    pub lifetime_signing: bool,
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
    /// The certificate the source was asked about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha256: Option<String>,
    /// Where the source obtained it, when from a URL that normalizes to one
    /// of the request's points and passes screening, as the source spelled
    /// it (`fetch_each` spells it as listed); a URL outside the request is
    /// not recorded (CRL-049).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Where it actually came from: `url` unless a redirect, or the source's
    /// own choice such as a mirror, changed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    pub sha256: String,
    pub bytes: usize,
}
/// How a CRL source reports a request that produced no CRL. The source
/// chooses; the engine decides what each means for the run.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CrlSourceErrorKind {
    /// The source refused this URL by its policy (`crl_fetch_denied`).
    Denied,
    /// The request was made and did not produce a response
    /// (`crl_fetch_failed`).
    Failed,
    /// The source can do no more work in this verification, for example its
    /// time or byte budget is spent or it was cancelled (`crl_fetch_aborted`).
    /// No further URL is requested.
    Abort,
    /// Anything else the source cannot classify (`crl_fetch_failed`).
    Unknown,
}
impl CrlSourceErrorKind {
    /// The error code a failure of this kind is reported with.
    pub fn code(self) -> ErrorCode {
        match self {
            Self::Denied => ErrorCode::CrlFetchDenied,
            Self::Failed | Self::Unknown => ErrorCode::CrlFetchFailed,
            Self::Abort => ErrorCode::CrlFetchAborted,
        }
    }
}
/// A listed distribution point that yielded no evidence, with the error that
/// explains it. Usually `crl_fetch_denied` (not discovered, `url` absent, or
/// denied by transport policy), `crl_fetch_failed` or `crl_fetch_aborted`
/// (from the source; `source_error` then says which kind it reported), but
/// other codes are possible: `invalid_crl` for a response that is not a CRL,
/// `invalid_certificate` for a malformed cRLDistributionPoints extension, or
/// `resource_limit_exceeded` for one of the engine's own retrieval limits,
/// named by `details.resource`: a response body over its size cap or the
/// request's allowance (`crl_response_bytes`; with `fetch_each`, only the
/// first such body of a request reaches the engine, later ones are the
/// source's `failed`), a certificate not asked because the store holds all
/// the bytes it may retain (`retrieval_trust_bytes`), a response with more
/// entries than allowed (`crl_response_entries`), a body that would take the
/// retained CRLs past their cap or a certificate not asked because the store
/// already holds as many CRLs as it may (`retrieval_crl_artifacts`), or the entry
/// counting a certificate's further failures (`crl_failure_entries`). None of
/// these ends the run. A source's own limits (the built-in HTTP source's
/// response size, header size or redirect count) are that source's failures:
/// `crl_fetch_failed` with `details.resource` naming the limit. Verification
/// still decides whether the missing evidence mattered.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrlRetrievalFailure {
    /// RFC 7807 `type`, `title` and `detail`, as on every serialized error.
    #[serde(flatten)]
    pub problem: Box<ProblemDetails>,
    /// SHA-256 of the certificate that lists the point.
    pub certificate_sha256: String,
    pub url: Option<String>,
    pub code: ErrorCode,
    pub stage: Stage,
    pub message: String,
    pub details: BTreeMap<String, Value>,
    pub causes: Vec<String>,
    /// The kind a `CrlSource` reported, when the failure came from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_error: Option<CrlSourceErrorKind>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrlRetrievalReport {
    /// Retrieved artifacts are untrusted evidence; this is not per-CRL verification status.
    pub artifacts: Vec<CrlRetrievalArtifact>,
    /// Listed points that yielded no evidence, grouped by the certificate
    /// they were asked for, in request order. Within a request: points
    /// refused before asking, then the source's own failures in response
    /// order, then bodies rejected on load, then points it did not answer
    /// (after an abort, the points not tried, as `crl_fetch_aborted`). The
    /// first failure naming no URL, while a listed point is still unanswered,
    /// is the exception: it may answer those points, so it waits for the
    /// bodies and comes after those rejected on load, recorded for each point
    /// left or, when it answers none, as it is, before the points still
    /// unanswered (CRL-049). A whole-request error naming a listed point is
    /// recorded for every other point, in listed order, then for that one;
    /// naming no listed point (a URL outside the request counts as none),
    /// for every point in listed order, or once, without a URL, when the
    /// request lists none. A failure or body in a response naming a URL
    /// outside the request is recorded in its place, without that URL (a
    /// body without its redirect target too), and answers no point; such a
    /// body is no answer by certificate. Last,
    /// for a failed retrieval, the points a source answering by certificate
    /// left unused for a certificate still without a usable CRL, in the
    /// order those certificates were asked about.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<CrlRetrievalFailure>,
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

#[cfg(test)]
mod tests {
    use super::{ErrorCode, Stage, VerificationError};
    use crate::parse::{Error, ErrorKind};
    use alloc::{borrow::ToOwned, vec};

    /// A parser error under contexts reports those contexts in front of its own
    /// causes, whether the contexts were added to an `anyhow::Error` holding it or
    /// to a `Result` carrying it; its code, stage and message are unchanged
    /// (CLI candidate rule `causes`, CLI-T005).
    #[test]
    fn the_contexts_above_a_parser_error_come_first_in_its_causes() {
        use anyhow::Context;
        let convert =
            |error| VerificationError::from_internal(error, ErrorCode::InternalError, Stage::Input);
        let parser = || {
            Error::new(
                ErrorKind::InvalidPe,
                anyhow::anyhow!("leaf").context("inner"),
            )
        };
        let alone = convert(anyhow::Error::new(parser()));
        assert_eq!(alone.causes, vec!["inner", "leaf"]);
        let held = convert(
            anyhow::Error::new(parser())
                .context("middle")
                .context("outer"),
        );
        let carried = convert(
            Err::<(), _>(parser())
                .context("middle")
                .context("outer")
                .unwrap_err(),
        );
        for error in [held, carried] {
            assert_eq!(error.code, ErrorCode::InvalidPe);
            assert_eq!(error.stage, Stage::Pe);
            assert_eq!(error.message, alone.message);
            assert_eq!(error.causes, vec!["outer", "middle", "inner", "leaf"]);
        }
    }

    /// A parser error that is another error's `source()` keeps the code and
    /// stage of its kind and its `scope` detail, instead of taking the caller's
    /// defaults; the outer error's message comes first in `causes`, then the
    /// parser error's own causes (CLI candidate rule `typed-layer`, CLI-T005).
    #[test]
    fn a_parser_error_that_is_another_errors_source_keeps_its_code_and_scope() {
        #[derive(Debug)]
        struct Outer(Error);
        impl core::fmt::Display for Outer {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("outer")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let scope = || {
            Error::new(
                ErrorKind::UnsupportedRdpScope,
                anyhow::Error::from(crate::parse::rdp::UnsupportedScope {
                    entry: "Bogus Setting".into(),
                })
                .context("signscope"),
            )
        };
        let direct = VerificationError::from(scope());
        let error = VerificationError::from_internal(
            anyhow::Error::new(Outer(scope())).context("usage"),
            ErrorCode::InternalError,
            Stage::Input,
        );
        assert_eq!(error.code, ErrorCode::UnsupportedRdpScope);
        assert_eq!(error.stage, Stage::Rdp);
        assert_eq!(error.message, direct.message);
        assert_eq!(error.details["scope"], "Bogus Setting");
        assert_eq!(error.details, direct.details);
        let mut causes = vec!["usage".to_owned(), "outer".to_owned()];
        causes.extend(direct.causes);
        assert_eq!(error.causes, causes);
    }

    /// A parser error's kind is the default for its own chain: a typed layer in
    /// it, a `VerificationError` or a parser error that is a source there,
    /// decides instead, as `parse::Error::new` lets a nested parser error's
    /// kind stand (CLI candidate rule `typed-layer`).
    #[test]
    fn a_typed_layer_inside_a_parser_errors_chain_decides() {
        #[derive(Debug)]
        struct Outer(Error);
        impl core::fmt::Display for Outer {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("outer")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let nested = Error::new(ErrorKind::InvalidCab, anyhow::anyhow!("cab leaf"));
        let msi = Error::new(ErrorKind::InvalidMsi, anyhow::Error::new(Outer(nested)));
        let error = VerificationError::from(msi);
        assert_eq!(error.code, ErrorCode::InvalidCab);
        assert_eq!(error.stage, Stage::Cab);
        assert_eq!(error.causes, vec!["outer", "cab leaf"]);
        let typed = VerificationError::new(ErrorCode::InvalidSignature, Stage::Cms, "typed");
        let msi = Error::new(
            ErrorKind::InvalidMsi,
            anyhow::Error::new(typed).context("msi"),
        );
        let error = VerificationError::from(msi);
        assert_eq!(error.code, ErrorCode::InvalidSignature);
        assert_eq!(error.causes, vec!["msi", "typed"]);
        // The outer parser error's `scope` stays with its own kind.
        let typed = VerificationError::new(ErrorCode::InvalidSignature, Stage::Cms, "typed");
        let scoped = Error::new(
            ErrorKind::UnsupportedRdpScope,
            anyhow::Error::from(crate::parse::rdp::UnsupportedScope {
                entry: "Bogus Setting".into(),
            })
            .context(typed),
        );
        let error = VerificationError::from(scoped);
        assert_eq!(error.code, ErrorCode::InvalidSignature);
        assert!(error.details.is_empty());
        // `scope` belongs to an unsupported signscope, not to another kind.
        let invalid = Error::new(
            ErrorKind::InvalidRdp,
            anyhow::Error::from(crate::parse::rdp::UnsupportedScope {
                entry: "Bogus Setting".into(),
            }),
        );
        let error = VerificationError::from(invalid);
        assert_eq!(error.code, ErrorCode::InvalidRdp);
        assert!(error.details.is_empty());
    }

    /// A `VerificationError` attached as an anyhow context is the result, as it is
    /// when it is the error or a source: its code, stage, message and details,
    /// with the contexts above it first in `causes`, then its own causes (or its
    /// message), then the error it was attached to (CLI candidate rule
    /// `typed-layer`, CLI-T005).
    #[test]
    fn a_verification_error_attached_as_a_context_is_recognised() {
        use anyhow::Context;
        let convert =
            |error| VerificationError::from_internal(error, ErrorCode::InternalError, Stage::Input);
        let typed = VerificationError::new(ErrorCode::InvalidSignature, Stage::Cms, "typed")
            .detail("signer", 1);
        // An untyped context with the typed error's text is not taken for it.
        let held = convert(
            anyhow::anyhow!("leaf")
                .context(typed.clone())
                .context("typed")
                .context("outer"),
        );
        let carried = convert(
            Err::<(), _>(std::fmt::Error)
                .context(typed.clone())
                .unwrap_err()
                .context("typed")
                .context("outer"),
        );
        for (error, leaf) in [
            (held, "leaf"),
            (carried, "an error occurred when formatting an argument"),
        ] {
            assert_eq!(error.code, ErrorCode::InvalidSignature);
            assert_eq!(error.stage, Stage::Cms);
            assert_eq!(error.message, "typed");
            assert_eq!(error.details, typed.details);
            assert_eq!(error.causes, vec!["outer", "typed", "typed", leaf]);
        }
        // Causes an earlier conversion gave it stand in for its message.
        let converted = convert(anyhow::anyhow!("root").context("inner"));
        let error = convert(
            anyhow::anyhow!("leaf")
                .context(converted.clone())
                .context("outer"),
        );
        assert_eq!(error.code, converted.code);
        assert_eq!(error.causes, vec!["outer", "inner", "root", "leaf"]);
        // The outermost typed layer decides, whatever its kind.
        let parser = Error::new(ErrorKind::InvalidCab, anyhow::anyhow!("cab leaf"));
        let error = convert(anyhow::Error::new(parser).context(typed.clone()));
        assert_eq!(error.code, ErrorCode::InvalidSignature);
        assert_eq!(error.causes, vec!["typed", "invalid CAB", "cab leaf"]);
        let cab = Error::new(ErrorKind::InvalidCab, anyhow::anyhow!("cab leaf"));
        let error = convert(anyhow::anyhow!("leaf").context(cab).context(typed.clone()));
        assert_eq!(error.code, ErrorCode::InvalidSignature);
        // A parser error held as a context there is its entry's text alone.
        assert_eq!(error.causes, vec!["typed", "invalid CAB", "leaf"]);
        // Other ways anyhow stores a context: an inline source that is not
        // zero-sized, `Option::context` and `Error::msg`.
        #[derive(Debug)]
        struct Leaf(alloc::string::String);
        impl core::fmt::Display for Leaf {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl std::error::Error for Leaf {}
        let inline = convert(
            Err::<(), _>(Leaf("sized leaf".into()))
                .context(typed.clone())
                .unwrap_err()
                .context("outer"),
        );
        assert_eq!(inline.causes, vec!["outer", "typed", "sized leaf"]);
        let optional = convert(
            None::<()>
                .context(typed.clone())
                .unwrap_err()
                .context("outer"),
        );
        let message = convert(anyhow::Error::msg(typed.clone()).context("outer"));
        for error in [inline, optional, message] {
            assert_eq!(error.code, ErrorCode::InvalidSignature);
            assert_eq!(error.stage, Stage::Cms);
            assert_eq!(error.details, typed.details);
        }
    }
}
