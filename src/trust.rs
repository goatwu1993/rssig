use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
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
        let signer = leaf;
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
        // Revocation is checked here, certificate by certificate on each
        // candidate path, as OpenSSL's check_cert_crl and Bouncy Castle's
        // X509RevocationChecker do: each certificate's CRLs are authenticated
        // under that path's real issuer key, and the best usable one decides.
        // webpki then confirms the accepted path with only the chosen CRLs.
        let crls = if revocation {
            // Without any applicable CRL, every certificate of this chain
            // lacks one: they are listed so that retrieval asks about these
            // and not about another chain's.
            let chain_without_crl = || -> Vec<CertificateReport> {
                core::iter::once(signer)
                    .chain(certificates)
                    .filter(|c| c.tbs_certificate.issuer != c.tbs_certificate.subject)
                    .filter_map(|c| CertificateReport::parse(c).ok())
                    .collect()
            };
            if self.crls.is_empty() {
                return Err(VerificationError::new(ErrorCode::RevocationUnknown, Stage::Revocation, "revocation requires --crl files covering the signer and intermediate certificates")
                    .detail("certificates_without_crl", chain_without_crl())
                    .into());
            }
            let mut issuer_names = Vec::new();
            for root in &self.roots {
                let root = Certificate::from_der(root.as_ref()).map_err(crate::compat_error)?;
                issuer_names.push(
                    root.tbs_certificate
                        .subject
                        .to_der()
                        .map_err(crate::compat_error)?,
                );
            }
            for certificate in certificates {
                issuer_names.push(
                    certificate
                        .tbs_certificate
                        .subject
                        .to_der()
                        .map_err(crate::compat_error)?,
                );
            }
            // Only a CRL whose issuer could be on the chain is decoded in
            // full; the issuer is read from the top-level fields first. One
            // whose issuer cannot be read that way is decoded and judged.
            let crls = self
                .crls
                .iter()
                .filter(|bytes| {
                    crate::der::tbs_issuer(bytes, 0x02, 1)
                        .is_none_or(|issuer| issuer_names.iter().any(|n| n == issuer))
                })
                .map(|bytes| LoadedCrl::load(bytes))
                .collect::<Result<Vec<_>>>()?;
            if !crls.iter().any(|crl| issuer_names.contains(&crl.issuer)) {
                return Err(VerificationError::new(
                    ErrorCode::RevocationUnknown,
                    Stage::Revocation,
                    "no supplied CRL applies to the certificate chain",
                )
                .detail("certificates_without_crl", chain_without_crl())
                .into());
            }
            crls
        } else {
            Vec::new()
        };
        let revocation_enabled = revocation;
        // The configured root behind each anchor, parsed once.
        let anchor_certificates: Vec<Option<Certificate>> = if revocation {
            self.roots
                .iter()
                .map(|root| Certificate::from_der(root.as_ref()).ok())
                .collect()
        } else {
            Vec::new()
        };
        // CRL signature results by (CRL, issuer key), shared by every
        // candidate path and charged to the work budget once each.
        let signatures: core::cell::RefCell<SignatureCache> = Default::default();
        // Per candidate path: the revocation outcomes it produced, and the
        // CRLs chosen for an accepted path.
        let outcomes: core::cell::RefCell<Vec<CertificateEvidence>> = Default::default();
        let chosen: core::cell::RefCell<Vec<usize>> = Default::default();
        // Rejecting a candidate path here is non-fatal: webpki tries other
        // issuers and reports the most specific rejection by its error rank.
        let invalid_ca_usage = core::cell::Cell::new(false);
        let issued_after_signing = core::cell::OnceCell::new();
        let check_path_policy = |path: &webpki::VerifiedPath<'_>| {
            let mut path_certificates = vec![signer.clone()];
            for intermediate in path.intermediate_certificates() {
                for _ in 0..8 {
                    budget
                        .decoded_bytes
                        .charge(intermediate.der().as_ref().len())
                        .map_err(|_| webpki::Error::BadDer)?;
                }
                path_certificates.push(
                    Certificate::from_der(intermediate.der().as_ref())
                        .map_err(|_| webpki::Error::BadDer)?,
                );
            }
            // Revocation first, as webpki checked it while verifying the
            // path's signatures, before any other path policy.
            if revocation_enabled {
                // Each certificate's issuer on this path: the next
                // certificate, or the configured root behind the anchor.
                let anchor = roots
                    .iter()
                    .position(|root| {
                        root.subject == path.anchor().subject
                            && root.subject_public_key_info == path.anchor().subject_public_key_info
                            && root.name_constraints == path.anchor().name_constraints
                    })
                    .and_then(|index| anchor_certificates[index].clone())
                    .ok_or(webpki::Error::UnknownIssuer)?;
                // Every certificate is evaluated, so that an unknown status
                // names every certificate without a usable CRL at once.
                let mut path_chosen = Vec::new();
                let mut rejected = None;
                for (depth, cert) in path_certificates.iter().enumerate() {
                    let issuer = match path_certificates.get(depth + 1) {
                        Some(next) => IssuerKey::of(next, false),
                        None => IssuerKey::of(&anchor, true),
                    }
                    .map_err(|_| webpki::Error::BadDer)?;
                    let evidence = evaluate_crls(
                        cert,
                        depth == 0,
                        &issuer,
                        &crls,
                        now,
                        &mut |index, crl: &LoadedCrl| {
                            *signatures
                                .borrow_mut()
                                .entry((index, issuer.spki.clone()))
                                .or_insert_with(|| {
                                    // Over budget: no verification, and the
                                    // exhausted counter ends the run below.
                                    budget.crypto.charge(1).map_err(|_| ())?;
                                    Ok(signed_by(
                                        &issuer.spki,
                                        &crl.algorithm,
                                        &crl.signed,
                                        &crl.signature,
                                    ))
                                })
                        },
                    );
                    match &evidence.outcome {
                        Outcome::Good(index) => path_chosen.push(*index),
                        Outcome::Revoked(_) => rejected = Some(webpki::Error::CertRevoked),
                        Outcome::Missing(_) => {
                            rejected.get_or_insert(webpki::Error::UnknownRevocationStatus);
                        }
                    }
                    outcomes.borrow_mut().push(evidence);
                }
                if let Some(error) = rejected {
                    return Err(error);
                }
                *chosen.borrow_mut() = path_chosen;
            }
            let mut lacks_cert_sign = false;
            for cert in &path_certificates[1..] {
                if let Some(at) = issued_after(cert, lifetime_signed_at) {
                    // Ranked like webpki's own validity errors. Keep the first
                    // rejection, which webpki also keeps among equal ranks.
                    let error = webpki::Error::CertNotValidYet {
                        time: UnixTime::since_unix_epoch(Duration::from_secs(at)),
                        not_before: UnixTime::since_unix_epoch(not_before(cert)),
                    };
                    let _ = issued_after_signing.set(cert.clone());
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
            None,
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
            let revocation_error = matches!(
                e,
                webpki::Error::CertRevoked | webpki::Error::UnknownRevocationStatus
            )
            .then(|| revocation_failure(&outcomes.borrow()))
            .flatten();
            let mut error = if let Some(error) = revocation_error {
                error
            } else if invalid_ca_usage.get() && e == webpki::Error::UnknownIssuer {
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
        // webpki confirms the accepted path's revocation status with only the
        // CRLs chosen for it, under its own rules and our crypto adapter. A
        // disagreement rejects; it never accepts what the check above did not.
        if revocation_enabled {
            let mut picked = chosen.borrow().clone();
            picked.sort_unstable();
            picked.dedup();
            let picked: Vec<webpki::CertRevocationList<'_>> = picked
                .iter()
                .filter_map(|&index| crls[index].webpki.clone().ok())
                .map(webpki::CertRevocationList::from)
                .collect();
            let picked_refs: Vec<_> = picked.iter().collect();
            let options = webpki::RevocationOptionsBuilder::new(&picked_refs)
                .map_err(|e| anyhow::anyhow!("CRLs required: {e:?}"))?
                .with_depth(webpki::RevocationCheckDepth::Chain)
                .with_status_policy(webpki::UnknownStatusPolicy::Deny)
                .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
                .build();
            // Only the accepted path is offered, so there is no search: the
            // path work is covered by the reservation above, and its signature
            // and CRL checks are charged through the budgeted algorithms.
            let path_intermediates: Vec<CertificateDer<'static>> = path
                .intermediate_certificates()
                .map(|c| c.der().clone().into_owned())
                .collect();
            let path_anchor = [path.anchor().clone()];
            let confirmed = leaf.verify_for_usage(
                &algorithm_refs,
                &path_anchor,
                &path_intermediates,
                UnixTime::since_unix_epoch(Duration::from_secs(validation_time)),
                webpki::KeyUsage::required_if_present(eku),
                Some(options),
                None,
            );
            budget.crypto.check()?;
            budget.hash_bytes.check()?;
            confirmed.map_err(|e| {
                webpki_error(e)
                    .detail("certificate", &leaf_report)
                    .detail("required_eku", eku_oid.to_string())
                    .detail("reason", "confirmation")
            })?;
        }
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

/// CRL signature results by (CRL index, issuer SPKI): `Ok(None)` when the
/// algorithm is unsupported, `Err` when the work budget is spent.
type SignatureCheck = core::result::Result<Option<bool>, ()>;
type SignatureCache = alloc::collections::BTreeMap<(usize, Vec<u8>), SignatureCheck>;

/// A supplied or retrieved CRL, decoded once per verification.
struct LoadedCrl {
    bytes: Vec<u8>,
    tbs: x509_cert::crl::TbsCertList,
    /// The original tbsCertList bytes, never a re-encoding.
    signed: Vec<u8>,
    algorithm: ::der::asn1::ObjectIdentifier,
    signature: ::der::asn1::BitString,
    issuer: Vec<u8>,
    /// The authorityKeyIdentifier keyIdentifier; `Err` when malformed.
    authority_key: core::result::Result<Option<Vec<u8>>, ()>,
    revoked: Vec<Vec<u8>>,
    /// webpki's own parse, which also rejects unsupported features.
    webpki: core::result::Result<webpki::OwnedCertRevocationList, webpki::Error>,
}

impl LoadedCrl {
    fn load(bytes: &[u8]) -> Result<Self> {
        let crl = CertificateList::from_der(bytes).map_err(crate::compat_error)?;
        let signed = crate::der::one(bytes, 0x30)
            .and_then(|outer| outer.children())
            .map_err(crate::compat_error)?
            .first()
            .map(|tbs| tbs.full.to_vec())
            .context("CRL lacks tbsCertList")?;
        let tbs = crl.tbs_cert_list;
        let issuer = tbs.issuer.to_der().map_err(crate::compat_error)?;
        let authority_key = match tbs
            .crl_extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id == AuthorityKeyIdentifier::OID)
        {
            None => Ok(None),
            Some(e) => AuthorityKeyIdentifier::from_der(e.extn_value.as_bytes())
                .map(|aki| aki.key_identifier.map(|k| k.as_bytes().to_vec()))
                .map_err(|_| ()),
        };
        let revoked = tbs
            .revoked_certificates
            .iter()
            .flatten()
            .map(|r| r.serial_number.as_bytes().to_vec())
            .collect();
        // Parse every entry now: webpki otherwise reads entries lazily, so an
        // unsupported entry could go unnoticed.
        let webpki =
            webpki::BorrowedCertRevocationList::from_der(bytes).and_then(|crl| crl.to_owned());
        Ok(Self {
            bytes: bytes.to_vec(),
            signed,
            algorithm: crl.signature_algorithm.oid,
            signature: crl.signature,
            issuer,
            authority_key,
            revoked,
            webpki,
            tbs,
        })
    }
}

/// The key, identifier and CRL-signing permission of a certificate's issuer
/// on one path.
struct IssuerKey {
    spki: Vec<u8>,
    key_id: Option<Vec<u8>>,
    /// Configured anchors are keys: their KeyUsage does not restrict CRL
    /// signing (webpki does not track anchor KeyUsage either).
    crl_sign: bool,
}

impl IssuerKey {
    fn of(cert: &Certificate, anchor: bool) -> Result<Self> {
        use x509_cert::ext::pkix::KeyUsage;
        let identity = issuer_identity(cert)?;
        let crl_sign = anchor
            || cert
                .tbs_certificate
                .get::<KeyUsage>()
                .map_err(crate::compat_error)?
                .is_none_or(|(_, ku)| ku.crl_sign());
        Ok(Self {
            spki: identity.spki,
            key_id: identity.key_id,
            crl_sign,
        })
    }
}

/// What one certificate's CRLs established on one candidate path.
struct CertificateEvidence {
    sha256: String,
    der: Vec<u8>,
    outcome: Outcome,
}

enum Outcome {
    /// The index of the usable, authoritative CRL chosen for it.
    Good(usize),
    Revoked(VerificationError),
    /// No usable authoritative CRL; the most specific reason, if a CRL of
    /// its issuer was found but could not be used.
    Missing(Option<(u8, VerificationError)>),
}

/// Choose the best CRL for `cert` among those of its issuer on this path, as
/// OpenSSL's CRL scoring and Bouncy Castle's validity filtering do: a CRL
/// that is forged for this key, from an issuer without cRLSign, unsupported,
/// out of scope, or not current is set aside when another is usable. Only
/// when none is usable does the most specific of their failures decide.
fn evaluate_crls(
    cert: &Certificate,
    end_entity: bool,
    issuer: &IssuerKey,
    crls: &[LoadedCrl],
    now: u64,
    verify_signature: &mut dyn FnMut(usize, &LoadedCrl) -> SignatureCheck,
) -> CertificateEvidence {
    let der = cert.to_der().unwrap_or_default();
    let sha256 = crate::domain::hex(&crate::crypto::Hash::Sha256.digest(&der));
    let Ok(issuer_name) = cert.tbs_certificate.issuer.to_der() else {
        return CertificateEvidence {
            sha256,
            der,
            outcome: Outcome::Missing(None),
        };
    };
    let serial = cert.tbs_certificate.serial_number.as_bytes();
    let lists_points = has_extension(cert, "2.5.29.31");
    let mut usable = None;
    let mut authenticated_listing = None;
    let mut failure: Option<(u8, VerificationError)> = None;
    // A failure's error is built only when it would be kept.
    let mut fail = |rank: u8, error: &dyn Fn() -> VerificationError| {
        if failure.as_ref().is_none_or(|(best, _)| rank > *best) {
            failure = Some((rank, error()));
        }
    };
    for (index, crl) in crls.iter().enumerate() {
        if crl.issuer != issuer_name {
            continue;
        }
        let with_crl =
            |error: VerificationError| error.detail("crl", CrlReport::parse(&crl.bytes).ok());
        // Authenticate under this path's issuer key first: what an
        // authenticated CRL lists counts whatever else is wrong with it.
        // A CRL that names another key and is not signed by this one is not
        // this issuer's: it is set aside without a failure.
        let named_key = crl.authority_key.as_ref().ok().and_then(Option::as_ref);
        match verify_signature(index, crl) {
            Ok(Some(true)) => {}
            Ok(Some(false))
                if named_key.is_some_and(|named| issuer.key_id.as_ref() != Some(named)) =>
            {
                continue;
            }
            Ok(Some(false)) => {
                fail(5, &|| {
                    with_crl(webpki_revocation_error(
                        &sha256,
                        webpki::Error::InvalidCrlSignatureForPublicKey,
                    ))
                });
                continue;
            }
            // An algorithm the engine cannot verify: unsupported, not forged.
            Ok(None) => {
                fail(3, &|| {
                    with_crl(
                        revocation_error(
                            &sha256,
                            ErrorCode::InvalidCrl,
                            "CRL signature algorithm is unsupported",
                        )
                        .detail("reason", "unsupported_signature_algorithm"),
                    )
                });
                continue;
            }
            // The work budget is spent: the run ends with that error.
            Err(()) => continue,
        }
        if crl.revoked.iter().any(|s| s.as_slice() == serial) {
            authenticated_listing.get_or_insert(index);
        }
        if crl.authority_key.is_err() {
            fail(3, &|| {
                with_crl(
                    revocation_error(
                        &sha256,
                        ErrorCode::InvalidCrl,
                        "CRL authorityKeyIdentifier is malformed",
                    )
                    .detail("reason", "malformed_authority_key_identifier"),
                )
            });
            continue;
        }
        if !issuer.crl_sign {
            fail(4, &|| {
                with_crl(webpki_revocation_error(
                    &sha256,
                    webpki::Error::IssuerNotCrlSigner,
                ))
            });
            continue;
        }
        // webpki would treat a CRL scoped to a named distribution point as
        // authoritative for a certificate that lists none, so such a
        // partition could clear a certificate it does not cover.
        if !lists_points && names_distribution_point(&crl.tbs) {
            fail(3, &|| {
                with_crl(
                    revocation_error(
                        &sha256,
                        ErrorCode::InvalidCrl,
                        "CRL is scoped to a distribution point that the certificate does not list",
                    )
                    .detail("reason", "distribution_point_scope"),
                )
            });
            continue;
        }
        // A CRL that webpki can use and whose scope is known not to cover
        // this certificate (another point or role) is set aside, whatever its
        // age. One that webpki cannot use is reported below: its scope is not
        // trusted enough to set it aside silently.
        let authority = authority_for(&crl.tbs, cert, end_entity);
        if crl.webpki.is_ok() && authority == Some(false) {
            continue;
        }
        let Some(next_update) = crl.tbs.next_update else {
            fail(3, &|| {
                with_crl(
                    revocation_error(&sha256, ErrorCode::InvalidCrl, "CRL lacks nextUpdate")
                        .detail("reason", "missing_next_update"),
                )
            });
            continue;
        };
        // Feature support is reported before freshness, which a refreshed
        // CRL could not fix.
        if let Err(e) = &crl.webpki {
            fail(3, &|| {
                with_crl(
                    revocation_error(
                        &sha256,
                        ErrorCode::InvalidCrl,
                        format!("unsupported or malformed CRL: {e:?}"),
                    )
                    .detail("reason", crl_rejection_reason(e)),
                )
            });
            continue;
        }
        if crl.tbs.this_update.to_unix_duration().as_secs() > now {
            fail(2, &|| {
                with_crl(revocation_error(
                    &sha256,
                    ErrorCode::CrlNotYetValid,
                    "CRL thisUpdate is in the future",
                ))
                .detail("validation_time", now)
            });
            continue;
        }
        if next_update.to_unix_duration().as_secs() <= now {
            fail(1, &|| {
                with_crl(revocation_error(
                    &sha256,
                    ErrorCode::CrlExpired,
                    "CRL has expired",
                ))
                .detail("validation_time", now)
            });
            continue;
        }
        if authority == Some(true) {
            usable.get_or_insert(index);
        }
    }
    let outcome = match (usable, authenticated_listing) {
        // A current authoritative CRL makes the status known; a listing in
        // any CRL authenticated by this issuer key then revokes, even a stale
        // or partition CRL: revocations do not expire.
        (Some(_), Some(listing)) => Outcome::Revoked(
            webpki_revocation_error(&sha256, webpki::Error::CertRevoked)
                .detail("crl", CrlReport::parse(&crls[listing].bytes).ok()),
        ),
        (Some(index), None) => Outcome::Good(index),
        // Without one, the status is unknown, even if a CRL lists it.
        (None, _) => Outcome::Missing(failure),
    };
    CertificateEvidence {
        sha256,
        der,
        outcome,
    }
}

/// The error for a revocation rejection, from what the candidate paths
/// established: a revocation first, then the most specific reason a CRL could
/// not be used, else unknown status naming every certificate that lacked a
/// usable CRL.
fn revocation_failure(outcomes: &[CertificateEvidence]) -> Option<VerificationError> {
    if outcomes.is_empty() {
        return None;
    }
    if let Some(error) = outcomes.iter().find_map(|o| match &o.outcome {
        Outcome::Revoked(error) => Some(error.clone()),
        _ => None,
    }) {
        return Some(error);
    }
    // Each certificate in full, so that a CRL source can be asked about it
    // whichever candidate path it was on.
    let mut seen: Vec<&str> = Vec::new();
    let mut missing: Vec<CertificateReport> = Vec::new();
    for outcome in outcomes {
        if matches!(outcome.outcome, Outcome::Missing(None))
            && !seen.contains(&outcome.sha256.as_str())
        {
            seen.push(&outcome.sha256);
            if let Some(report) = Certificate::from_der(&outcome.der)
                .ok()
                .and_then(|c| CertificateReport::parse(&c).ok())
            {
                missing.push(report);
            }
        }
    }
    let mut best: Option<&(u8, VerificationError)> = None;
    for outcome in outcomes {
        if let Outcome::Missing(Some(failure)) = &outcome.outcome
            && best.is_none_or(|b| failure.0 > b.0)
        {
            best = Some(failure);
        }
    }
    // A certificate with no CRL at all makes the result unknown, so that it
    // can be retrieved; the most specific unusable CRL is still reported
    // with it. Only when no certificate simply lacks one does that failure
    // decide.
    match best {
        Some((_, error)) if missing.is_empty() => Some(error.clone()),
        best => {
            let error = VerificationError::new(
                ErrorCode::RevocationUnknown,
                Stage::Revocation,
                "no usable authoritative CRL for a certificate on the path",
            )
            .detail("certificates_without_crl", missing);
            Some(match best {
                Some((_, unusable)) => error.detail("unusable_crl", unusable),
                None => error,
            })
        }
    }
}

/// A revocation error naming the affected certificate.
fn revocation_error(
    certificate: &str,
    code: ErrorCode,
    message: impl Into<String>,
) -> VerificationError {
    VerificationError::new(code, Stage::Revocation, message)
        .detail("affected_certificate", certificate)
}

/// The error webpki's own check reports, naming the affected certificate.
fn webpki_revocation_error(certificate: &str, error: webpki::Error) -> VerificationError {
    webpki_error(error).detail("affected_certificate", certificate)
}

/// Whether a CRL is authoritative for `cert`: no issuingDistributionPoint,
/// or one whose role flags admit the certificate and that names a fullName
/// URI the certificate lists (or the certificate lists none). This is webpki
/// 0.103's rule; webpki re-checks it when confirming the path. `None` when
/// the scope cannot be read (an undecodable issuingDistributionPoint, or one
/// without a fullName), which webpki rejects as unsupported.
fn authority_for(
    tbs: &x509_cert::crl::TbsCertList,
    cert: &Certificate,
    end_entity: bool,
) -> Option<bool> {
    use x509_cert::ext::pkix::{
        CrlDistributionPoints,
        crl::dp::IssuingDistributionPoint,
        name::{DistributionPointName, GeneralName},
    };
    // By OID string: x509-cert 0.2 associates the wrong OID with this type.
    let Some(idp) = tbs
        .crl_extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == "2.5.29.28")
    else {
        return Some(true);
    };
    let idp = IssuingDistributionPoint::from_der(idp.extn_value.as_bytes()).ok()?;
    if idp.only_contains_ca_certs && end_entity || idp.only_contains_user_certs && !end_entity {
        return Some(false);
    }
    let points = match cert.tbs_certificate.get::<CrlDistributionPoints>() {
        Ok(None) => return Some(true),
        Ok(Some((_, points))) => points.0,
        Err(_) => return Some(false),
    };
    let uris = |name: &Option<DistributionPointName>| -> Option<Vec<Vec<u8>>> {
        match name {
            Some(DistributionPointName::FullName(names)) => Some(
                names
                    .iter()
                    .filter_map(|n| match n {
                        GeneralName::UniformResourceIdentifier(uri) => {
                            Some(uri.as_bytes().to_vec())
                        }
                        _ => None,
                    })
                    .collect(),
            ),
            _ => None,
        }
    };
    let scope = uris(&idp.distribution_point)?;
    Some(
        points
            .iter()
            .filter(|p| p.reasons.is_none() && p.crl_issuer.is_none())
            .flat_map(|p| uris(&p.distribution_point).unwrap_or_default())
            .any(|uri| scope.contains(&uri)),
    )
}

fn not_before(cert: &Certificate) -> Duration {
    cert.tbs_certificate.validity.not_before.to_unix_duration()
}

/// The lifetime signing time, when `cert` was issued after it.
fn issued_after(cert: &Certificate, signed_at: Option<u64>) -> Option<u64> {
    signed_at.filter(|at| not_before(cert).as_secs() > *at)
}

struct IssuerIdentity {
    key_id: Option<Vec<u8>>,
    spki: Vec<u8>,
}

/// The subject key identifier bytes when present, and the SPKI DER.
fn issuer_identity(cert: &Certificate) -> Result<IssuerIdentity> {
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
    Ok(IssuerIdentity { key_id, spki })
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

/// Stable machine-readable reason for a CRL that webpki cannot use.
fn crl_rejection_reason(error: &webpki::Error) -> &'static str {
    use webpki::Error as W;
    match error {
        W::UnsupportedCriticalExtension => "unknown_critical_extension",
        W::UnsupportedDeltaCrl => "delta_crl",
        W::UnsupportedIndirectCrl => "indirect_crl",
        W::UnsupportedCrlIssuingDistributionPoint => "issuing_distribution_point",
        W::UnsupportedCrlVersion => "crl_version",
        W::MalformedExtensions => "malformed_extensions",
        W::UnsupportedRevocationReasonsPartitioning => "revocation_reasons_partitioning",
        W::UnsupportedRevocationReason => "revocation_reason",
        W::InvalidCrlNumber => "invalid_crl_number",
        _ => "unsupported_or_malformed",
    }
}

fn has_extension(cert: &Certificate, oid: &str) -> bool {
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .any(|e| e.extn_id.to_string() == oid)
}

/// Whether the CRL's issuingDistributionPoint carries a [0] distributionPoint.
fn names_distribution_point(tbs: &x509_cert::crl::TbsCertList) -> bool {
    tbs.crl_extensions
        .iter()
        .flatten()
        .filter(|e| e.extn_id.to_string() == "2.5.29.28")
        .any(|e| {
            crate::der::one(e.extn_value.as_bytes(), 0x30)
                .and_then(|idp| idp.children())
                .map_or(true, |fields| fields.iter().any(|f| f.tag == 0xa0))
        })
}

#[cfg(test)]
mod revocation_reporting {
    use super::*;

    fn evidence(sha: &str, outcome: Outcome) -> CertificateEvidence {
        let der = include_bytes!("../tests/fixtures/sec06-issuer.der").to_vec();
        CertificateEvidence {
            sha256: sha.into(),
            der,
            outcome,
        }
    }
    fn failed(rank: u8, code: ErrorCode) -> Outcome {
        Outcome::Missing(Some((rank, revocation_error("x", code, "test"))))
    }

    #[test]
    fn a_revocation_then_a_missing_crl_then_the_most_specific_failure_decides() {
        // A certificate without any CRL outranks one whose CRL is unusable, so
        // that it can still be retrieved.
        let error = revocation_failure(&[
            evidence("a", failed(5, ErrorCode::InvalidCrlSignature)),
            evidence("b", Outcome::Missing(None)),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::RevocationUnknown);
        assert_eq!(
            error.details["certificates_without_crl"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // The unusable CRL is not hidden: it is reported beside the gap.
        assert_eq!(
            error.details["unusable_crl"]["code"],
            "invalid_crl_signature"
        );
        // Without one, the highest-ranked failure decides.
        let error = revocation_failure(&[
            evidence("a", failed(1, ErrorCode::CrlExpired)),
            evidence("b", failed(3, ErrorCode::InvalidCrl)),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::InvalidCrl);
        // A revocation outranks everything.
        let revoked = webpki_revocation_error("c", webpki::Error::CertRevoked);
        let error = revocation_failure(&[
            evidence("a", Outcome::Missing(None)),
            evidence("c", Outcome::Revoked(revoked)),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert_eq!(error.details["affected_certificate"], "c");
    }
}
