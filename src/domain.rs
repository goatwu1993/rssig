//! Serializable public results. Machine consumers match codes, never error prose.
use crate::crypto::Hash;
use ::der::{Decode, Encode, Tagged};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fmt};
use x509_cert::{Certificate, crl::CertificateList, name::Name};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidPe,
    InvalidMsi,
    InvalidCab,
    InvalidPowershell,
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
    UnsupportedAlgorithm,
    WeakAlgorithm,
    ImageDigestMismatch,
    PageHashMismatch,
    InvalidSignature,
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
    Powershell,
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
            Self::InvalidPowershell => "Invalid PowerShell script",
            Self::ScriptDigestMismatch => "Script digest mismatch",
            Self::InvalidCab => "Invalid CAB container",
            Self::CabDigestMismatch => "CAB digest mismatch",
            Self::InvalidMsi => "Invalid MSI container",
            Self::PackageDigestMismatch => "MSI package digest mismatch",
            Self::ExtendedDigestMismatch => "MSI extended digest mismatch",
            Self::InvalidPe => "Invalid PE image",
            Self::Unsigned => "Missing embedded signature",
            Self::InvalidCertificateTable => "Invalid certificate table",
            Self::MalformedCms => "Malformed CMS data",
            Self::UnsupportedAlgorithm => "Unsupported algorithm",
            Self::WeakAlgorithm => "Weak algorithm disallowed",
            Self::ImageDigestMismatch => "PE image digest mismatch",
            Self::PageHashMismatch => "Page hash mismatch",
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
impl std::error::Error for VerificationError {}

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
impl DistinguishedName {
    pub(crate) fn parse(name: &Name) -> Self {
        let mut result = Self {
            display: name.to_string(),
            common_names: vec![],
            organizations: vec![],
            organizational_units: vec![],
            countries: vec![],
            rdns: vec![],
        };
        for rdn in &name.0 {
            let mut attributes = Vec::new();
            for atv in rdn.0.iter() {
                let oid = atv.oid.to_string();
                let raw = atv.value.value();
                let tag = atv.value.tag();
                let value = match tag {
                    ::der::Tag::Utf8String
                    | ::der::Tag::PrintableString
                    | ::der::Tag::Ia5String
                    | ::der::Tag::VisibleString
                    | ::der::Tag::NumericString => std::str::from_utf8(raw).ok().map(str::to_owned),
                    ::der::Tag::BmpString if raw.len() % 2 == 0 => String::from_utf16(
                        &raw.as_chunks::<2>()
                            .0
                            .iter()
                            .map(|b| u16::from_be_bytes(*b))
                            .collect::<Vec<_>>(),
                    )
                    .ok(),
                    _ => None, // Preserve unfamiliar encodings instead of guessing or losing bytes.
                };
                if let Some(value) = &value {
                    match oid.as_str() {
                        "2.5.4.3" => result.common_names.push(value.clone()),
                        "2.5.4.10" => result.organizations.push(value.clone()),
                        "2.5.4.11" => result.organizational_units.push(value.clone()),
                        "2.5.4.6" => result.countries.push(value.clone()),
                        _ => {}
                    }
                }
                let short = match oid.as_str() {
                    "2.5.4.3" => Some("CN"),
                    "2.5.4.10" => Some("O"),
                    "2.5.4.11" => Some("OU"),
                    "2.5.4.6" => Some("C"),
                    "2.5.4.7" => Some("L"),
                    "2.5.4.8" => Some("ST"),
                    "1.2.840.113549.1.9.1" => Some("emailAddress"),
                    _ => None,
                };
                attributes.push(NameAttribute {
                    oid,
                    name: short.map(str::to_owned),
                    value,
                    asn1_tag: format!("{tag:?}"),
                    raw_value_hex: hex(raw),
                });
            }
            result.rdns.push(attributes);
        }
        result
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidReport {
    pub oid: String,
    pub name: Option<String>,
}
impl OidReport {
    pub(crate) fn new(oid: impl ToString) -> Self {
        let oid = oid.to_string();
        let name = match oid.as_str() {
            "1.3.6.1.5.5.7.3.1" => Some("server_auth"),
            "1.3.6.1.5.5.7.3.2" => Some("client_auth"),
            "1.3.6.1.5.5.7.3.3" => Some("code_signing"),
            "1.3.6.1.5.5.7.3.8" => Some("time_stamping"),
            "2.5.29.37.0" => Some("any_extended_key_usage"),
            "1.2.840.113549.1.1.1" => Some("rsa_encryption"),
            "1.2.840.113549.1.1.11" => Some("sha256_with_rsa"),
            "1.2.840.113549.1.1.12" => Some("sha384_with_rsa"),
            "1.2.840.113549.1.1.13" => Some("sha512_with_rsa"),
            "1.2.840.10045.2.1" => Some("ec_public_key"),
            "1.2.840.10045.4.3.2" => Some("ecdsa_sha256"),
            "1.2.840.10045.4.3.3" => Some("ecdsa_sha384"),
            _ => None,
        }
        .map(str::to_owned);
        Self { oid, name }
    }
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
impl CertificateReport {
    pub(crate) fn parse(cert: &Certificate) -> anyhow::Result<Self> {
        use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
        let tbs = &cert.tbs_certificate;
        let der = cert.to_der()?;
        let extended_key_usage = tbs
            .get::<ExtendedKeyUsage>()?
            .map(|(critical, eku)| EkuReport {
                critical,
                usages: eku.0.iter().map(OidReport::new).collect(),
            });
        let key_usage = tbs.get::<KeyUsage>()?.map(|(critical, ku)| {
            let values = [
                ("digital_signature", ku.digital_signature()),
                ("content_commitment", ku.non_repudiation()),
                ("key_encipherment", ku.key_encipherment()),
                ("data_encipherment", ku.data_encipherment()),
                ("key_agreement", ku.key_agreement()),
                ("key_cert_sign", ku.key_cert_sign()),
                ("crl_sign", ku.crl_sign()),
                ("encipher_only", ku.encipher_only()),
                ("decipher_only", ku.decipher_only()),
            ];
            KeyUsageReport {
                critical,
                usages: values
                    .into_iter()
                    .filter(|(_, enabled)| *enabled)
                    .map(|(name, _)| name.to_owned())
                    .collect(),
            }
        });
        let basic_constraints =
            tbs.get::<BasicConstraints>()?
                .map(|(critical, bc)| BasicConstraintsReport {
                    critical,
                    ca: bc.ca,
                    path_length: bc.path_len_constraint,
                });
        Ok(Self {
            sha256: hex(&Hash::Sha256.digest(&der)),
            der_hex: hex(&der),
            serial_number: hex(tbs.serial_number.as_bytes()),
            version: tbs.version as u8 + 1,
            subject: DistinguishedName::parse(&tbs.subject),
            issuer: DistinguishedName::parse(&tbs.issuer),
            not_before: tbs.validity.not_before.to_unix_duration().as_secs(),
            not_after: tbs.validity.not_after.to_unix_duration().as_secs(),
            public_key_algorithm: OidReport::new(tbs.subject_public_key_info.algorithm.oid),
            signature_algorithm: OidReport::new(cert.signature_algorithm.oid),
            extended_key_usage,
            key_usage,
            basic_constraints,
            extensions: extensions(tbs.extensions.as_deref().unwrap_or_default()),
        })
    }
}
fn extensions(ext: &[x509_cert::ext::Extension]) -> Vec<ExtensionReport> {
    ext.iter()
        .map(|e| ExtensionReport {
            oid: e.extn_id.to_string(),
            critical: e.critical,
            value_der_hex: hex(e.extn_value.as_bytes()),
        })
        .collect()
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
impl CrlReport {
    pub(crate) fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let crl = CertificateList::from_der(bytes)?;
        let tbs = crl.tbs_cert_list;
        Ok(Self {
            sha256: hex(&Hash::Sha256.digest(bytes)),
            der_hex: hex(bytes),
            issuer: DistinguishedName::parse(&tbs.issuer),
            this_update: tbs.this_update.to_unix_duration().as_secs(),
            next_update: tbs.next_update.map(|t| t.to_unix_duration().as_secs()),
            signature_algorithm: OidReport::new(crl.signature_algorithm.oid),
            role: "supplied".into(),
            revoked_certificates: tbs
                .revoked_certificates
                .unwrap_or_default()
                .iter()
                .map(|r| RevokedCertificateReport {
                    serial_number: hex(r.serial_number.as_bytes()),
                    revocation_time: r.revocation_date.to_unix_duration().as_secs(),
                    extensions: extensions(r.crl_entry_extensions.as_deref().unwrap_or_default()),
                })
                .collect(),
            extensions: extensions(tbs.crl_extensions.as_deref().unwrap_or_default()),
        })
    }
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
pub struct TimestampReport {
    pub kind: String,
    pub signing_time: u64,
    pub certificate: CertificateReport,
    pub trust: Option<TrustReport>,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppxIdentity {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub processor_architecture: Option<String>,
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
pub struct AppxReport {
    pub identity: AppxIdentity,
    pub block_map: AppxBlockMapReport,
    pub components: Vec<AppxComponentReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_integrity_catalog: Option<AppxCatalogReport>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationBundle {
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
impl std::ops::Deref for VerificationBundle {
    type Target = [SignatureReport];
    fn deref(&self) -> &Self::Target {
        &self.signatures
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileSuccess {
    pub file: std::path::PathBuf,
    pub ok: bool,
    #[serde(flatten)]
    pub verification: VerificationBundle,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileFailure {
    pub file: std::path::PathBuf,
    pub ok: bool,
    pub error: VerificationError,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FileResult {
    Success(FileSuccess),
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

pub(crate) fn webpki_error(error: webpki::Error) -> VerificationError {
    use webpki::Error as W;
    let (code, stage, details) = match &error {
        W::CertExpired { time, not_after } => (
            ErrorCode::CertificateExpired,
            Stage::CertificateChain,
            json!({"validation_time":time.as_secs(),"not_after":not_after.as_secs()}),
        ),
        W::CertNotValidYet { time, not_before } => (
            ErrorCode::CertificateNotYetValid,
            Stage::CertificateChain,
            json!({"validation_time":time.as_secs(),"not_before":not_before.as_secs()}),
        ),
        W::UnknownIssuer => (ErrorCode::UntrustedRoot, Stage::CertificateChain, json!({})),
        W::CertRevoked => (ErrorCode::CertificateRevoked, Stage::Revocation, json!({})),
        W::CrlExpired { time, next_update } => (
            ErrorCode::CrlExpired,
            Stage::Revocation,
            json!({"validation_time":time.as_secs(),"next_update":next_update.as_secs()}),
        ),
        W::InvalidCrlSignatureForPublicKey => {
            (ErrorCode::InvalidCrlSignature, Stage::Revocation, json!({}))
        }
        W::UnknownRevocationStatus => (ErrorCode::RevocationUnknown, Stage::Revocation, json!({})),
        W::RequiredEkuNotFoundContext(_) | W::EmptyEkuExtension => {
            (ErrorCode::InvalidEku, Stage::CertificateChain, json!({}))
        }
        W::IssuerNotCrlSigner => (ErrorCode::InvalidKeyUsage, Stage::Revocation, json!({})),
        _ => (
            ErrorCode::CertificateChainInvalid,
            Stage::CertificateChain,
            json!({}),
        ),
    };
    let mut result = VerificationError::new(
        code,
        stage,
        format!("certificate chain validation failed: {error:?}"),
    );
    if let Value::Object(map) = details {
        result.details.extend(map);
    }
    result
}
