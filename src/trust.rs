use alloc::{format, string::ToString, vec, vec::Vec};
mod error;
mod loading;
use crate::crypto::{ALGORITHMS, BudgetedAlgorithm};
use crate::domain::{
    CertificateReport, CrlReport, ErrorCode, OidReport, RevocationReport, RevocationStatus, Stage,
    TrustReport, VerificationError,
};
use crate::verify::budget::Budget;
use ::der::oid::AssociatedOid;
use ::der::{Decode, Encode};
#[cfg(feature = "cli")]
use anyhow::ensure;
use anyhow::{Context, Result};
use core::time::Duration;
use error::webpki_error;
pub use error::{TrustLoadError, TrustLoadErrorCode, TrustLoadErrorKind};
use rustls_pki_types::{CertificateDer, UnixTime};
use x509_cert::{
    Certificate,
    crl::CertificateList,
    ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier},
};

pub(crate) const CODE_SIGNING: &[u8] = &[43, 6, 1, 5, 5, 7, 3, 3];
pub(crate) const TIME_STAMPING: &[u8] = &[43, 6, 1, 5, 5, 7, 3, 8];
/// Microsoft lifetime signing, 1.3.6.1.4.1.311.10.3.13.
const LIFETIME_SIGNING: &[u8] = &[43, 6, 1, 4, 1, 130, 55, 10, 3, 13];

#[derive(Clone, Default)]
pub struct TrustStore {
    roots: Vec<CertificateDer<'static>>,
    crls: Vec<Vec<u8>>,
}

impl TrustStore {
    #[cfg(feature = "cli")]
    pub(crate) fn check_host_limits(&self) -> Result<()> {
        ensure!(
            self.roots.len() <= 4096 && self.crls.len() <= 64,
            "too many loaded roots or CRLs"
        );
        let mut remaining = 32 * 1024 * 1024usize;
        for bytes in self
            .roots
            .iter()
            .map(|v| v.as_ref())
            .chain(self.crls.iter().map(|v| v.as_slice()))
        {
            remaining = remaining
                .checked_sub(bytes.len())
                .context("loaded roots/CRLs exceed 32 MiB")?;
        }
        Ok(())
    }
    #[cfg(feature = "crl-fetch")]
    pub(crate) fn has_crl_for(&self, cert: &Certificate, budget: &Budget) -> Result<bool> {
        for bytes in &self.crls {
            for _ in 0..8 {
                budget.decoded_bytes.charge(bytes.len())?;
            }
            if CertificateList::from_der(bytes)
                .map_err(crate::compat_error)?
                .tbs_cert_list
                .issuer
                == cert.tbs_certificate.issuer
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    #[cfg(feature = "crl-fetch")]
    pub(crate) fn retrieval_crl_count(&self) -> usize {
        self.crls.len()
    }
    #[cfg(feature = "crl-fetch")]
    pub(crate) fn retrieval_bytes(&self) -> usize {
        self.roots.iter().map(|v| v.as_ref().len()).sum::<usize>()
            + self.crls.iter().map(Vec::len).sum::<usize>()
    }
    #[allow(clippy::too_many_arguments)] // Time, revocation and work policy are explicit.
    pub(crate) fn verify(
        &self,
        leaf: &Certificate,
        certificates: &[Certificate],
        eku: &'static [u8],
        signing_time: Option<u64>,
        now: u64,
        revocation: bool,
        budget: &Budget,
    ) -> Result<TrustReport> {
        // webpki exposes no caller-owned search budget. Reserve its entire
        // 200,000-call path-search allowance before starting each invocation.
        budget.path_work.charge(200_000)?;
        budget.certificate_bytes(certificates)?;
        budget
            .report_certificates
            .charge(certificates.len() + self.roots.len())?;
        if self.roots.is_empty() {
            return Err(VerificationError::new(
                ErrorCode::UntrustedRoot,
                Stage::CertificateChain,
                "no trust anchors configured",
            )
            .into());
        }
        // KeyUsage digitalSignature is not enforced by webpki's TLS-oriented
        // leaf processing, so enforce it explicitly for CMS signers.
        use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage};
        if let Some((_, ku)) = leaf
            .tbs_certificate
            .get::<KeyUsage>()
            .map_err(crate::compat_error)?
            && !ku.digital_signature()
        {
            return Err(VerificationError::new(
                ErrorCode::InvalidKeyUsage,
                Stage::Certificate,
                "signer KeyUsage lacks digitalSignature",
            )
            .detail("certificate", CertificateReport::parse(leaf)?)
            .into());
        }
        let lifetime_signing = if eku == TIME_STAMPING {
            let (critical, usage) = leaf
                .tbs_certificate
                .get::<ExtendedKeyUsage>()
                .map_err(crate::compat_error)?
                .ok_or_else(|| {
                    VerificationError::new(
                        ErrorCode::InvalidEku,
                        Stage::Timestamp,
                        "TSA certificate needs timeStamping EKU",
                    )
                })?;
            if !(critical && usage.0.len() == 1 && usage.0[0].as_bytes() == TIME_STAMPING) {
                return Err(VerificationError::new(
                    ErrorCode::InvalidEku,
                    Stage::Timestamp,
                    "TSA EKU must be critical and exclusively timeStamping",
                )
                .detail("certificate", CertificateReport::parse(leaf)?)
                .into());
            }
            false
        } else {
            let (_, usage) = leaf
                .tbs_certificate
                .get::<ExtendedKeyUsage>()
                .map_err(crate::compat_error)?
                .ok_or_else(|| {
                    VerificationError::new(
                        ErrorCode::InvalidEku,
                        Stage::Certificate,
                        "signer certificate lacks required EKU",
                    )
                })?;
            if !usage.0.iter().any(|id| id.as_bytes() == eku) {
                return Err(VerificationError::new(
                    ErrorCode::InvalidEku,
                    Stage::Certificate,
                    "signer certificate lacks required EKU",
                )
                .detail("certificate", CertificateReport::parse(leaf)?)
                .into());
            }
            usage.0.iter().any(|id| id.as_bytes() == LIFETIME_SIGNING)
        };
        // A lifetime-signing signer is not extended by its timestamp: the chain
        // must be valid at the validation time, as well as at the signing time.
        let validation_time = match signing_time {
            Some(at) if !lifetime_signing => at,
            _ => now,
        };
        let lifetime_signed_at = signing_time.filter(|_| lifetime_signing);
        let eku_oid =
            ::der::asn1::ObjectIdentifier::from_bytes(eku).map_err(crate::compat_error)?;
        let not_valid_at_signing = |cert: &Certificate, at: u64| {
            let error = VerificationError::new(
                ErrorCode::CertificateNotYetValid,
                Stage::CertificateChain,
                "lifetime-signing certificate was not valid at the signing time",
            )
            .detail("lifetime_signing", true)
            .detail("signing_time", at)
            .detail("validation_time", now)
            .detail("not_before", not_before(cert).as_secs())
            .detail("required_eku", eku_oid.to_string());
            // Keep the signing-time reason even if the report cannot be built.
            match CertificateReport::parse(cert) {
                Ok(report) => error.detail("certificate", report),
                Err(cause) => error.detail("certificate_report_error", format!("{cause:#}")),
            }
        };
        if let Some(at) = issued_after(leaf, lifetime_signed_at) {
            return Err(not_valid_at_signing(leaf, at).into());
        }
        let leaf_report = CertificateReport::parse(leaf)?;
        let leaf = CertificateDer::from(leaf.to_der().map_err(crate::compat_error)?);
        let leaf = webpki::EndEntityCert::try_from(&leaf)
            .map_err(|e| anyhow::anyhow!("invalid signer certificate: {e:?}"))?;
        for root in &self.roots {
            for _ in 0..8 {
                budget.hash_bytes.charge(root.as_ref().len())?;
                budget.decoded_bytes.charge(root.as_ref().len())?;
            }
        }
        for crl in &self.crls {
            for _ in 0..8 {
                budget.hash_bytes.charge(crl.len())?;
                budget.decoded_bytes.charge(crl.len())?;
            }
        }
        let roots: Vec<_> = self
            .roots
            .iter()
            .map(|c| {
                webpki::anchor_from_trusted_cert(c)
                    .map_err(|e| anyhow::anyhow!("unsupported configured trust anchor: {e:?}"))
            })
            .collect::<Result<_>>()?;
        let intermediates: Vec<_> = certificates
            .iter()
            .map(|c| c.to_der().map(CertificateDer::from))
            .collect::<core::result::Result<_, _>>()
            .map_err(crate::compat_error)?;
        let mut parsed_crls = Vec::new();
        if revocation {
            if self.crls.is_empty() {
                return Err(VerificationError::new(ErrorCode::RevocationUnknown, Stage::Revocation, "revocation requires --crl files covering the signer and intermediate certificates").into());
            }
            // A CRL cannot apply to this chain unless a root or candidate
            // certificate has its issuer name and, when the CRL names an
            // authority key, the same subject key. Such CRLs are excluded
            // rather than rejecting the request; a CRL from a chain issuer
            // must be usable or fail closed. A candidate without a subject key
            // identifier cannot disprove a match, and a differing key
            // identifier excludes a CRL only if the CRL's signature also fails
            // under every name-matching candidate key.
            let mut issuers = Vec::new();
            for root in &self.roots {
                let root = Certificate::from_der(root.as_ref()).map_err(crate::compat_error)?;
                issuers.push(issuer_identity(&root)?);
            }
            for certificate in certificates {
                issuers.push(issuer_identity(certificate)?);
            }
            for bytes in &self.crls {
                let crl = CertificateList::from_der(bytes).map_err(crate::compat_error)?;
                // Verify over the CRL's original TBS bytes, never a re-encoding.
                let signed = crate::der::one(bytes, 0x30)
                    .and_then(|outer| outer.children())
                    .map_err(crate::compat_error)?
                    .first()
                    .map(|tbs| tbs.full)
                    .context("CRL lacks tbsCertList")?;
                let tbs = crl.tbs_cert_list;
                let issuer = tbs.issuer.to_der().map_err(crate::compat_error)?;
                let named: Vec<_> = issuers.iter().filter(|i| i.name == issuer).collect();
                if named.is_empty() {
                    continue;
                }
                let authority_key = match tbs
                    .crl_extensions
                    .iter()
                    .flatten()
                    .find(|e| e.extn_id == AuthorityKeyIdentifier::OID)
                {
                    None => None,
                    Some(e) => {
                        AuthorityKeyIdentifier::from_der(e.extn_value.as_bytes())
                            .map_err(|_| {
                                VerificationError::new(
                                    ErrorCode::InvalidCrl,
                                    Stage::Revocation,
                                    "CRL authorityKeyIdentifier is malformed",
                                )
                                .detail("crl", CrlReport::parse(bytes).ok())
                            })?
                            .key_identifier
                    }
                };
                let applies = named.iter().any(|i| match (&authority_key, &i.key_id) {
                    (Some(wanted), Some(have)) => wanted.as_bytes() == have.as_slice(),
                    _ => true,
                }) || (authority_key.is_some()
                    && named.iter().any(|i| {
                        signed_by(
                            &i.spki,
                            &crl.signature_algorithm.oid,
                            signed,
                            &crl.signature,
                        )
                        .unwrap_or(true)
                    }));
                if !applies {
                    continue;
                }
                if tbs.this_update.to_unix_duration().as_secs() > now {
                    return Err(VerificationError::new(
                        ErrorCode::CrlNotYetValid,
                        Stage::Revocation,
                        "CRL thisUpdate is in the future",
                    )
                    .detail("crl", CrlReport::parse(bytes)?)
                    .detail("validation_time", now)
                    .into());
                }
                let Some(next_update) = tbs.next_update else {
                    return Err(VerificationError::new(
                        ErrorCode::InvalidCrl,
                        Stage::Revocation,
                        "CRL lacks nextUpdate",
                    )
                    .detail("crl", CrlReport::parse(bytes)?)
                    .into());
                };
                if next_update.to_unix_duration().as_secs() <= now {
                    return Err(VerificationError::new(
                        ErrorCode::CrlExpired,
                        Stage::Revocation,
                        "CRL has expired",
                    )
                    .detail("crl", CrlReport::parse(bytes)?)
                    .detail("validation_time", now)
                    .into());
                }
                parsed_crls.push(webpki::CertRevocationList::from(
                    webpki::BorrowedCertRevocationList::from_der(bytes)
                        .map_err(|e| anyhow::anyhow!("unsupported CRL: {e:?}"))?,
                ));
            }
        }
        if revocation && parsed_crls.is_empty() {
            return Err(VerificationError::new(
                ErrorCode::RevocationUnknown,
                Stage::Revocation,
                "no supplied CRL applies to the certificate chain",
            )
            .into());
        }
        let crl_refs: Vec<_> = parsed_crls.iter().collect();
        let revocation_enabled = revocation;
        let revocation = if revocation {
            Some(
                webpki::RevocationOptionsBuilder::new(&crl_refs)
                    .map_err(|e| anyhow::anyhow!("CRLs required: {e:?}"))?
                    .with_depth(webpki::RevocationCheckDepth::Chain)
                    .with_status_policy(webpki::UnknownStatusPolicy::Deny)
                    .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
                    .build(),
            )
        } else {
            None
        };
        // Rejecting a candidate path here is non-fatal: webpki tries other
        // issuers and reports the most specific rejection by its error rank.
        let invalid_ca_usage = core::cell::Cell::new(false);
        let issued_after_signing = core::cell::OnceCell::new();
        let check_path_policy = |path: &webpki::VerifiedPath<'_>| {
            let mut lacks_cert_sign = false;
            for intermediate in path.intermediate_certificates() {
                for _ in 0..8 {
                    budget
                        .decoded_bytes
                        .charge(intermediate.der().as_ref().len())
                        .map_err(|_| webpki::Error::BadDer)?;
                }
                let cert = Certificate::from_der(intermediate.der().as_ref())
                    .map_err(|_| webpki::Error::BadDer)?;
                if let Some(at) = issued_after(&cert, lifetime_signed_at) {
                    // Ranked like webpki's own validity errors. Keep the first
                    // rejection, which webpki also keeps among equal ranks.
                    let error = webpki::Error::CertNotValidYet {
                        time: UnixTime::since_unix_epoch(Duration::from_secs(at)),
                        not_before: UnixTime::since_unix_epoch(not_before(&cert)),
                    };
                    let _ = issued_after_signing.set(cert);
                    return Err(error);
                }
                if let Some((_, ku)) = cert
                    .tbs_certificate
                    .get::<KeyUsage>()
                    .map_err(|_| webpki::Error::BadDer)?
                    && !ku.key_cert_sign()
                {
                    // With a lifetime signing time, finish the signing-time
                    // checks first so they outrank a missing keyCertSign
                    // wherever each defect sits in the path.
                    if lifetime_signed_at.is_none() {
                        invalid_ca_usage.set(true);
                        return Err(webpki::Error::UnknownIssuer);
                    }
                    lacks_cert_sign = true;
                }
            }
            if lacks_cert_sign {
                invalid_ca_usage.set(true);
                return Err(webpki::Error::UnknownIssuer);
            }
            Ok(())
        };
        // An absent EKU in a CA is unrestricted. The leaf is required to have
        // the requested EKU above; any CA EKU that is present must permit it.
        let algorithms: Vec<_> = ALGORITHMS
            .iter()
            .map(|algorithm| BudgetedAlgorithm {
                algorithm: *algorithm,
                budget,
            })
            .collect();
        let algorithm_refs: Vec<&dyn rustls_pki_types::SignatureVerificationAlgorithm> = algorithms
            .iter()
            .map(|a| a as &dyn rustls_pki_types::SignatureVerificationAlgorithm)
            .collect();
        let path = leaf.verify_for_usage(
            &algorithm_refs,
            &roots,
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(validation_time)),
            webpki::KeyUsage::required_if_present(eku),
            revocation,
            Some(&check_path_policy),
        );
        budget.crypto.check()?;
        budget.hash_bytes.check()?;
        budget.decoded_bytes.check()?;
        let path = path.map_err(|e| {
            // Only the callback reports a validity error at the signing time;
            // webpki's own checks use the (later) validation time. Also require
            // the stored certificate to be the one behind the surviving error.
            if let (
                webpki::Error::CertNotValidYet {
                    time,
                    not_before: rejected,
                },
                Some(at),
                Some(cert),
            ) = (&e, lifetime_signed_at, issued_after_signing.get())
                && time.as_secs() == at
                && rejected.as_secs() == not_before(cert).as_secs()
            {
                // Every candidate path failed; report the issuer that postdates signing.
                return not_valid_at_signing(cert, at);
            }
            let mut error = if invalid_ca_usage.get() && e == webpki::Error::UnknownIssuer {
                VerificationError::new(
                    ErrorCode::InvalidKeyUsage,
                    Stage::CertificateChain,
                    "intermediate certificate KeyUsage lacks keyCertSign",
                )
            } else {
                webpki_error(e)
            };
            error = error
                .detail("certificate", &leaf_report)
                .detail("required_eku", eku_oid.to_string());
            if lifetime_signing {
                error = error.detail("lifetime_signing", true);
            }
            if let Some(at) = lifetime_signed_at {
                error = error.detail("signing_time", at);
            }
            error
        })?;
        let mut chain = vec![leaf_report];
        for intermediate in path.intermediate_certificates() {
            chain.push(CertificateReport::parse(
                &Certificate::from_der(intermediate.der().as_ref()).map_err(crate::compat_error)?,
            )?);
        }
        for root in &self.roots {
            if let Ok(anchor) = webpki::anchor_from_trusted_cert(root)
                && anchor.subject == path.anchor().subject
                && anchor.subject_public_key_info == path.anchor().subject_public_key_info
                // Equal subject/key pairs may carry different anchor constraints.
                // Report a certificate representing the anchor actually selected.
                && anchor.name_constraints == path.anchor().name_constraints
            {
                chain.push(CertificateReport::parse(
                    &Certificate::from_der(root.as_ref()).map_err(crate::compat_error)?,
                )?);
                break;
            }
        }
        Ok(TrustReport {
            validation_time,
            lifetime_signing,
            required_eku: OidReport::new(eku_oid),
            chain,
            revocation: RevocationReport {
                status: if revocation_enabled {
                    RevocationStatus::Good
                } else {
                    RevocationStatus::NotChecked
                },
                method: revocation_enabled.then(|| "crl".into()),
                crls: if revocation_enabled {
                    self.crls
                        .iter()
                        .map(|b| CrlReport::parse(b))
                        .collect::<Result<_>>()?
                } else {
                    vec![]
                },
            },
        })
    }
}

fn not_before(cert: &Certificate) -> Duration {
    cert.tbs_certificate.validity.not_before.to_unix_duration()
}

/// The lifetime signing time, when `cert` was issued after it.
fn issued_after(cert: &Certificate, signed_at: Option<u64>) -> Option<u64> {
    signed_at.filter(|at| not_before(cert).as_secs() > *at)
}

struct IssuerIdentity {
    name: Vec<u8>,
    key_id: Option<Vec<u8>>,
    spki: Vec<u8>,
}

/// Subject name DER, the subject key identifier bytes when present, and the SPKI DER.
fn issuer_identity(cert: &Certificate) -> Result<IssuerIdentity> {
    let name = cert
        .tbs_certificate
        .subject
        .to_der()
        .map_err(crate::compat_error)?;
    let key_id = cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == SubjectKeyIdentifier::OID)
        .and_then(|e| SubjectKeyIdentifier::from_der(e.extn_value.as_bytes()).ok())
        .map(|ski| ski.0.as_bytes().to_vec());
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(crate::compat_error)?;
    Ok(IssuerIdentity { name, key_id, spki })
}

/// Whether the CRL signature verifies under `spki`. `None` when the signature
/// algorithm is not one we can map to a digest: the caller must then treat
/// the CRL as applicable rather than exclude it.
fn signed_by(
    spki: &[u8],
    algorithm: &::der::asn1::ObjectIdentifier,
    message: &[u8],
    signature: &::der::asn1::BitString,
) -> Option<bool> {
    let oid = algorithm.as_bytes();
    let hash = match oid {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2]
        | [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 11] => crate::crypto::Hash::Sha256,
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3]
        | [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 12] => crate::crypto::Hash::Sha384,
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 4]
        | [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 13] => crate::crypto::Hash::Sha512,
        _ => return None,
    };
    Some(crate::crypto::verify_spki(spki, hash, oid, message, signature.as_bytes()?).is_ok())
}
