use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
#[cfg(all(feature = "revocation-crosscheck", debug_assertions))]
mod crosscheck;
mod error;
mod loading;
mod names;
use crate::crypto::{ALGORITHMS, BudgetedAlgorithm};
use crate::domain::{
    CertificateReport, CrlReport, ErrorCode, OidReport, RevocationReport, RevocationStatus, Stage,
    TrustReport, VerificationError,
};
use crate::verify::budget::Budget;
use ::der::oid::AssociatedOid;
use ::der::{Decode, Encode};
use anyhow::{Context, Result};
use core::time::Duration;
use error::webpki_error;
pub use error::{TrustLoadError, TrustLoadErrorCode, TrustLoadErrorKind};
#[cfg(feature = "retrieval")]
pub(crate) use loading::crl_issuers;
use names::ComparableName;
use rustls_pki_types::{CertificateDer, UnixTime};
use x509_cert::{
    Certificate,
    crl::CertificateList,
    ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier, name::GeneralName},
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
    /// Whether this exact CRL (DER) is already loaded.
    #[cfg(feature = "retrieval")]
    pub(crate) fn has_crl(&self, der: &[u8]) -> bool {
        self.crls.iter().any(|crl| crl == der)
    }
    /// Where this exact CRL (DER) is among the loaded ones.
    #[cfg(feature = "retrieval")]
    pub(crate) fn crl_index(&self, der: &[u8]) -> Option<usize> {
        self.crls.iter().position(|crl| crl == der)
    }
    /// The number of configured trust anchors.
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }
    /// The number of loaded CRLs.
    pub fn crl_count(&self) -> usize {
        self.crls.len()
    }
    /// The DER bytes held: every root and every CRL. An application bounds
    /// what it loads with this; the engine bounds CRL retrieval with it.
    pub fn encoded_len(&self) -> usize {
        self.roots.iter().map(|v| v.as_ref().len()).sum::<usize>()
            + self.crls.iter().map(Vec::len).sum::<usize>()
    }
    /// Build and validate the signer's chain to a configured root, checking
    /// revocation per certificate on each candidate path when requested.
    pub(crate) fn verify(&self, request: ChainRequest<'_>, budget: &Budget) -> Result<TrustReport> {
        let ChainRequest {
            leaf,
            certificates,
            eku,
            signing_time,
            now,
            revocation,
        } = request;
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
        let requirements = SignerRequirements::check(leaf, eku, signing_time, now)?;
        if let Some(at) = issued_after(leaf, requirements.lifetime_signed_at) {
            return Err(requirements.not_valid_at_signing(leaf, at).into());
        }
        let leaf_report = CertificateReport::parse(leaf)?;
        let leaf_der = CertificateDer::from(leaf.to_der().map_err(crate::compat_error)?);
        let end_entity = webpki::EndEntityCert::try_from(&leaf_der)
            .map_err(|e| anyhow::anyhow!("invalid signer certificate: {e:?}"))?;
        self.charge_loaded(budget)?;
        let anchors: Vec<_> = self
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
        // This is the only revocation check; webpki builds paths without one.
        // With no applicable CRL at all, the path is still built: an
        // untrusted chain fails as such, and a trusted one reports every
        // certificate on it as without a CRL.
        // Each configured root is decoded once, for the CRL prefilter and the
        // anchor certificates both.
        let roots = if revocation {
            self.decoded_roots()?
        } else {
            Vec::new()
        };
        let crls = if revocation {
            self.applicable_crls(&roots, certificates)?
        } else {
            Vec::new()
        };
        let evaluator = PathEvaluator {
            signer: leaf,
            anchors: &anchors,
            anchor_certificates: roots,
            crls: &crls,
            now,
            revocation,
            lifetime_signed_at: requirements.lifetime_signed_at,
            budget,
            state: Default::default(),
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
        let path = {
            let check_path = |path: &webpki::VerifiedPath<'_>| evaluator.check(path);
            end_entity.verify_for_usage(
                &algorithm_refs,
                &anchors,
                &intermediates,
                UnixTime::since_unix_epoch(Duration::from_secs(requirements.validation_time)),
                webpki::KeyUsage::required_if_present(eku),
                None,
                Some(&check_path),
            )
        };
        budget.crypto.check()?;
        budget.hash_bytes.check()?;
        budget.decoded_bytes.check()?;
        let state = evaluator.state.into_inner();
        let path = path.map_err(|e| path_error(e, &state, &crls, &requirements, &leaf_report))?;
        // rssig's per-certificate check above is the only revocation
        // decision. Issuers of one name with different keys on the accepted
        // path are rejected here when their CRLs cannot be told apart by key,
        // as OpenSSL and BoringSSL do (see `ambiguous_issuer_keys`).
        if revocation {
            let rejects = ambiguous_issuer_keys(&state.chosen);
            // Test builds only: webpki's own revocation check must agree.
            #[cfg(all(feature = "revocation-crosscheck", debug_assertions))]
            crosscheck::confirm(
                &end_entity,
                &path,
                requirements.validation_time,
                eku,
                &state.chosen,
                &crls,
                rejects,
            );
            if rejects {
                return Err(VerificationError::new(
                    ErrorCode::CertificateChainInvalid,
                    Stage::CertificateChain,
                    "CRLs of two issuers with one name and different keys cannot be told \
                     apart: each must name its issuer's key in an authorityKeyIdentifier",
                )
                .detail("certificate", &leaf_report)
                .detail("required_eku", requirements.eku_oid.to_string())
                .detail("reason", "ambiguous_issuer_keys")
                .into());
            }
            state.warn_ignored_listings(budget);
        }
        Ok(TrustReport {
            validation_time: requirements.validation_time,
            lifetime_signing: requirements.lifetime_signing,
            chain: self.chain_report(leaf_report, &anchors, &path)?,
            required_eku: OidReport::new(requirements.eku_oid),
            revocation: self.revocation_report(revocation)?,
        })
    }

    /// Charge the loaded roots and CRLs to the hash and decode budgets.
    fn charge_loaded(&self, budget: &Budget) -> Result<()> {
        let loaded = self
            .roots
            .iter()
            .map(|root| root.as_ref().len())
            .chain(self.crls.iter().map(Vec::len));
        for len in loaded {
            for _ in 0..8 {
                budget.hash_bytes.charge(len)?;
                budget.decoded_bytes.charge(len)?;
            }
        }
        Ok(())
    }

    /// The loaded CRLs whose issuer could be on a chain through `certificates`.
    ///
    /// Only a CRL whose issuer could be on the chain is decoded in full; the
    /// issuer is read from the top-level fields first and compared
    /// re-encoded, as the chain's names are (der sorts a SET OF while
    /// decoding, so raw and re-encoded bytes can differ). One whose issuer
    /// cannot be read that way is decoded and judged.
    ///
    /// Within the prefilter each name is prepared at most once; a CRL that
    /// passes it has its issuer prepared again when it is loaded (CRL-T033).
    fn applicable_crls(
        &self,
        roots: &[Certificate],
        certificates: &[Certificate],
    ) -> Result<Vec<LoadedCrl>> {
        let mut issuer_names = Vec::new();
        for root in roots {
            issuer_names.push(ComparableName::new(
                root.tbs_certificate
                    .subject
                    .to_der()
                    .map_err(crate::compat_error)?,
            ));
        }
        for certificate in certificates {
            issuer_names.push(ComparableName::new(
                certificate
                    .tbs_certificate
                    .subject
                    .to_der()
                    .map_err(crate::compat_error)?,
            ));
        }
        self.crls
            .iter()
            .filter(|bytes| crl_may_apply(bytes, &issuer_names))
            .map(|bytes| LoadedCrl::load(bytes))
            .collect()
    }

    /// Every configured root, decoded once per verification. Loading has
    /// already decoded each one (`validate` in `loading.rs`), so this fails
    /// only if that check and this decoding disagree.
    fn decoded_roots(&self) -> Result<Vec<Certificate>> {
        self.roots
            .iter()
            .map(|root| Certificate::from_der(root.as_ref()).map_err(crate::compat_error))
            .collect()
    }

    /// The accepted chain: the signer, the path's intermediates, and a
    /// configured root representing the anchor actually selected.
    fn chain_report(
        &self,
        leaf_report: CertificateReport,
        anchors: &[rustls_pki_types::TrustAnchor<'_>],
        path: &webpki::VerifiedPath<'_>,
    ) -> Result<Vec<CertificateReport>> {
        let mut chain = vec![leaf_report];
        for intermediate in path.intermediate_certificates() {
            chain.push(CertificateReport::parse(
                &Certificate::from_der(intermediate.der().as_ref()).map_err(crate::compat_error)?,
            )?);
        }
        // Equal subject/key pairs may carry different anchor constraints.
        if let Some((root, _)) = self
            .roots
            .iter()
            .zip(anchors)
            .find(|(_, anchor)| same_anchor(anchor, path.anchor()))
        {
            chain.push(CertificateReport::parse(
                &Certificate::from_der(root.as_ref()).map_err(crate::compat_error)?,
            )?);
        }
        Ok(chain)
    }

    fn revocation_report(&self, revocation: bool) -> Result<RevocationReport> {
        Ok(if revocation {
            RevocationReport {
                status: RevocationStatus::Good,
                method: Some("crl".into()),
                crls: self
                    .crls
                    .iter()
                    .map(|b| CrlReport::parse(b))
                    .collect::<Result<_>>()?,
            }
        } else {
            RevocationReport {
                status: RevocationStatus::NotChecked,
                method: None,
                crls: vec![],
            }
        })
    }
}

/// One chain-validation request for [`TrustStore::verify`].
pub(crate) struct ChainRequest<'a> {
    /// The signer certificate.
    pub(crate) leaf: &'a Certificate,
    /// Untrusted embedded certificates, used as chain candidates only.
    pub(crate) certificates: &'a [Certificate],
    /// The extended key usage the signer must have.
    pub(crate) eku: &'static [u8],
    /// A verified timestamp's signing time, if any.
    pub(crate) signing_time: Option<u64>,
    /// The validation time.
    pub(crate) now: u64,
    /// Whether to check revocation against CRLs.
    pub(crate) revocation: bool,
}

/// Whether two anchors are the same one to webpki: one key, name and
/// name constraints.
fn same_anchor(
    a: &rustls_pki_types::TrustAnchor<'_>,
    b: &rustls_pki_types::TrustAnchor<'_>,
) -> bool {
    a.subject == b.subject
        && a.subject_public_key_info == b.subject_public_key_info
        && a.name_constraints == b.name_constraints
}

/// The signer's own key usage and EKU, and the times its chain is judged at.
struct SignerRequirements {
    eku_oid: ::der::asn1::ObjectIdentifier,
    /// Whether the signer has the Microsoft lifetime-signing EKU.
    lifetime_signing: bool,
    /// The time webpki validates the path at.
    validation_time: u64,
    /// The signing time, only for a lifetime-signing signer.
    lifetime_signed_at: Option<u64>,
    now: u64,
}

impl SignerRequirements {
    fn check(
        leaf: &Certificate,
        eku: &'static [u8],
        signing_time: Option<u64>,
        now: u64,
    ) -> Result<Self> {
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
        Ok(Self {
            eku_oid: ::der::asn1::ObjectIdentifier::from_bytes(eku).map_err(crate::compat_error)?,
            lifetime_signing,
            validation_time,
            lifetime_signed_at: signing_time.filter(|_| lifetime_signing),
            now,
        })
    }

    /// `cert` was issued after the lifetime signing time `at`.
    fn not_valid_at_signing(&self, cert: &Certificate, at: u64) -> VerificationError {
        let error = VerificationError::new(
            ErrorCode::CertificateNotYetValid,
            Stage::CertificateChain,
            "lifetime-signing certificate was not valid at the signing time",
        )
        .detail("lifetime_signing", true)
        .detail("signing_time", at)
        .detail("validation_time", self.now)
        .detail("not_before", not_before(cert).as_secs())
        .detail("required_eku", self.eku_oid.to_string());
        // Keep the signing-time reason even if the report cannot be built.
        match CertificateReport::parse(cert) {
            Ok(report) => error.detail("certificate", report),
            Err(cause) => error.detail("certificate_report_error", format!("{cause:#}")),
        }
    }
}

/// What the path callback recorded across every candidate path webpki tried.
#[derive(Default)]
struct PathState {
    /// CRL signature results by (CRL, issuer key), shared by every candidate
    /// path and charged to the work budget once each.
    signatures: SignatureCache,
    /// Per candidate path: the revocation outcomes it produced.
    outcomes: Vec<CertificateEvidence>,
    /// The CRLs chosen for the last path whose revocation passed.
    chosen: Vec<ChosenCrl>,
    paths_evaluated: usize,
    /// The last path whose revocation passed: the accepted one on success.
    accepted_path: Option<usize>,
    /// A path was rejected for a CA without keyCertSign.
    invalid_ca_usage: bool,
    /// The first CA found issued after the lifetime signing time.
    issued_after_signing: Option<Certificate>,
}

impl PathState {
    /// Once, for the accepted path only: a listing that was set aside is
    /// never dropped silently.
    fn warn_ignored_listings(&self, budget: &Budget) {
        for evidence in self
            .outcomes
            .iter()
            .filter(|o| Some(o.path) == self.accepted_path && o.ignored_listings > 0)
        {
            budget.log.warn(
                Stage::Revocation,
                format_args!(
                    "certificate {} is listed by {} authenticated CRL(s) that do not \
                     decide (not current, superseded or out of scope); not counted",
                    evidence.sha256, evidence.ignored_listings
                ),
            );
        }
    }
}

/// The path checks webpki calls back into for each candidate path.
///
/// Rejecting a candidate path is non-fatal: webpki tries other issuers and
/// reports the most specific rejection by its error rank. What each path
/// established is kept in `state` for the final report or error.
struct PathEvaluator<'a, 'b> {
    signer: &'a Certificate,
    anchors: &'a [rustls_pki_types::TrustAnchor<'a>],
    /// The configured root behind each anchor; empty without revocation.
    anchor_certificates: Vec<Certificate>,
    crls: &'a [LoadedCrl],
    now: u64,
    revocation: bool,
    lifetime_signed_at: Option<u64>,
    budget: &'a Budget<'b>,
    state: core::cell::RefCell<PathState>,
}

impl PathEvaluator<'_, '_> {
    fn check(&self, path: &webpki::VerifiedPath<'_>) -> core::result::Result<(), webpki::Error> {
        let path_certificates = self.path_certificates(path)?;
        // The other path checks are judged first but applied after
        // revocation, as webpki checked revocation while verifying the
        // path's signatures: only a path that would pass it can still be
        // completed by a fetched CRL.
        let other_failure = path_check_failure(&path_certificates, self.lifetime_signed_at)?;
        if self.revocation {
            self.check_revocation(path, &path_certificates, other_failure.is_none())?;
        }
        match other_failure {
            None => Ok(()),
            Some(PathCheckFailure::IssuedAfterSigning(cert, at)) => {
                // Ranked like webpki's own validity errors. Keep the first
                // rejection, which webpki also keeps among equal ranks.
                let error = webpki::Error::CertNotValidYet {
                    time: UnixTime::since_unix_epoch(Duration::from_secs(at)),
                    not_before: UnixTime::since_unix_epoch(not_before(cert)),
                };
                self.state
                    .borrow_mut()
                    .issued_after_signing
                    .get_or_insert_with(|| cert.clone());
                Err(error)
            }
            Some(PathCheckFailure::LacksCertSign) => {
                self.state.borrow_mut().invalid_ca_usage = true;
                Err(webpki::Error::UnknownIssuer)
            }
        }
    }

    /// The signer and the path's intermediates, decoded under the budget.
    fn path_certificates(
        &self,
        path: &webpki::VerifiedPath<'_>,
    ) -> core::result::Result<Vec<Certificate>, webpki::Error> {
        let mut path_certificates = vec![self.signer.clone()];
        for intermediate in path.intermediate_certificates() {
            for _ in 0..8 {
                self.budget
                    .decoded_bytes
                    .charge(intermediate.der().as_ref().len())
                    .map_err(|_| webpki::Error::BadDer)?;
            }
            path_certificates.push(
                Certificate::from_der(intermediate.der().as_ref())
                    .map_err(|_| webpki::Error::BadDer)?,
            );
        }
        Ok(path_certificates)
    }

    /// The anchor's key. Configured roots that are this anchor to webpki
    /// (one key, name and constraints) may carry different key identifiers:
    /// a CRL naming any of them is this anchor's.
    fn anchor_key(
        &self,
        anchor: &rustls_pki_types::TrustAnchor<'_>,
    ) -> core::result::Result<IssuerKey, webpki::Error> {
        let mut anchors = self
            .anchors
            .iter()
            .enumerate()
            .filter(|(_, root)| same_anchor(root, anchor))
            .filter_map(|(index, _)| self.anchor_certificates.get(index));
        let first = anchors.next().ok_or(webpki::Error::UnknownIssuer)?;
        let mut anchor_key = IssuerKey::of(first, true).map_err(|_| webpki::Error::BadDer)?;
        for same_key in anchors {
            let identity = issuer_identity(same_key).map_err(|_| webpki::Error::BadDer)?;
            anchor_key
                .certificates
                .push(CertificateName::of(same_key).map_err(|_| webpki::Error::BadDer)?);
            match identity.key_id {
                Some(id) => anchor_key.other_key_ids.push(id),
                // One that names no key cannot disprove a match.
                None => anchor_key.undisprovable = true,
            }
        }
        Ok(anchor_key)
    }

    /// Check every certificate on the path against its issuer's CRLs, so
    /// that an unknown status names every certificate without a usable CRL
    /// at once.
    fn check_revocation(
        &self,
        path: &webpki::VerifiedPath<'_>,
        path_certificates: &[Certificate],
        path_viable: bool,
    ) -> core::result::Result<(), webpki::Error> {
        // Each certificate's issuer on this path: the next certificate, or
        // the configured root behind the anchor.
        let anchor_key = self.anchor_key(path.anchor())?;
        let path_index = {
            let mut state = self.state.borrow_mut();
            state.paths_evaluated += 1;
            state.paths_evaluated - 1
        };
        let mut path_chosen = Vec::new();
        let mut rejected = None;
        for (depth, cert) in path_certificates.iter().enumerate() {
            let issuer = match path_certificates.get(depth + 1) {
                Some(next) => IssuerKey::of(next, false).map_err(|_| webpki::Error::BadDer)?,
                None => anchor_key.clone(),
            };
            let mut evidence = evaluate_crls(
                cert,
                depth == 0,
                &issuer,
                self.crls,
                self.now,
                &mut |index, crl: &LoadedCrl| self.crl_signature(index, crl, &issuer),
            )
            .ok_or(webpki::Error::BadDer)?;
            evidence.path = path_index;
            evidence.path_viable = path_viable;
            match &evidence.outcome {
                Outcome::Good(index) => {
                    let named = self.crls[*index].authority_key.as_ref();
                    // A positive match only: an issuer with no key identifier
                    // never names itself, while `names_another_key` (a CRL set
                    // aside as another key's) needs a negative one it cannot
                    // make without an identifier.
                    let names_issuer = matches!(named, Ok(Some(named)) if issuer.names(named));
                    path_chosen.push(ChosenCrl {
                        index: *index,
                        names_issuer,
                        issuer_spki: issuer.spki.clone(),
                        issuer_name: cert
                            .tbs_certificate
                            .issuer
                            .to_der()
                            .map_err(|_| webpki::Error::BadDer)?,
                    });
                }
                Outcome::Revoked(_) => rejected = Some(webpki::Error::CertRevoked),
                Outcome::Missing(_) => {
                    rejected.get_or_insert(webpki::Error::UnknownRevocationStatus);
                }
            }
            self.state.borrow_mut().outcomes.push(evidence);
        }
        if let Some(error) = rejected {
            return Err(error);
        }
        let mut state = self.state.borrow_mut();
        state.chosen = path_chosen;
        state.accepted_path = Some(path_index);
        Ok(())
    }

    /// Whether `crl` is signed by `issuer`, cached by (CRL, issuer key).
    fn crl_signature(&self, index: usize, crl: &LoadedCrl, issuer: &IssuerKey) -> SignatureCheck {
        let mut state = self.state.borrow_mut();
        let checks = state.signatures.entry(index).or_default();
        if let Some(check) = checks.get(issuer.spki.as_slice()) {
            return *check;
        }
        let check = (|| {
            // Over budget: no verification, and the exhausted counter ends
            // the run after path building.
            self.budget.crypto.charge(1).map_err(|_| ())?;
            // An identifier the adapter rejects is unsupported, whatever its
            // OID.
            if !crl.algorithm_accepted {
                return Ok(None);
            }
            Ok(signed_by(
                &issuer.spki,
                &crl.algorithm,
                &crl.signed,
                &crl.signature,
            ))
        })();
        checks.insert(issuer.spki.clone(), check);
        check
    }
}

/// Map webpki's final path-building error, with what the path callback
/// recorded, to the reported verification error.
fn path_error(
    e: webpki::Error,
    state: &PathState,
    crls: &[LoadedCrl],
    requirements: &SignerRequirements,
    leaf_report: &CertificateReport,
) -> VerificationError {
    // webpki ranks another path's validity error above unknown revocation
    // status, but a path that passes every path check and only lacks CRLs
    // is the one a CRL could complete: it outranks every other path's error,
    // including a CA issued after the lifetime signing time. A definite
    // revocation does not: a higher-ranked error on another path still
    // decides, as pinned by `time-011-lifetime-rollover-revoked-issuer` (TIME-T002).
    let revocation_rejected = matches!(
        e,
        webpki::Error::CertRevoked | webpki::Error::UnknownRevocationStatus
    );
    // webpki's own search limits are never replaced: the search did not
    // finish, so no other path's status is final.
    let viable = if revocation_rejected || search_limit(&e) {
        None
    } else {
        completable_path(&state.outcomes)
    };
    // Only the callback reports a validity error at the signing time;
    // webpki's own checks use the (later) validation time. Also require the
    // stored certificate to be the one behind the surviving error.
    if let (
        webpki::Error::CertNotValidYet {
            time,
            not_before: rejected,
        },
        Some(at),
        Some(cert),
    ) = (
        &e,
        requirements.lifetime_signed_at,
        state.issued_after_signing.as_ref(),
    ) && viable.is_none()
        && time.as_secs() == at
        && rejected.as_secs() == not_before(cert).as_secs()
    {
        // Every candidate path failed; report the issuer that postdates signing.
        return requirements.not_valid_at_signing(cert, at);
    }
    let revocation_error = if revocation_rejected {
        revocation_failure(&state.outcomes)
    } else {
        viable
    };
    let mut error = if let Some(mut error) = revocation_error {
        report_crls(&mut error, crls);
        error
    } else if state.invalid_ca_usage && e == webpki::Error::UnknownIssuer {
        VerificationError::new(
            ErrorCode::InvalidKeyUsage,
            Stage::CertificateChain,
            "intermediate certificate KeyUsage lacks keyCertSign",
        )
    } else {
        webpki_error(e)
    };
    error = error
        .detail("certificate", leaf_report)
        .detail("required_eku", requirements.eku_oid.to_string());
    if requirements.lifetime_signing {
        error = error.detail("lifetime_signing", true);
    }
    if let Some(at) = requirements.lifetime_signed_at {
        error = error.detail("signing_time", at);
    }
    error
}

/// CRL signature results by (CRL index, issuer SPKI): `Ok(None)` when the
/// algorithm is unsupported, `Err` when the work budget is spent.
type SignatureCheck = core::result::Result<Option<bool>, ()>;
/// Keyed by CRL index, then issuer SPKI, so a hit borrows the SPKI and copies
/// nothing.
type SignatureCache =
    alloc::collections::BTreeMap<usize, alloc::collections::BTreeMap<Vec<u8>, SignatureCheck>>;

/// A supplied or retrieved CRL, decoded once per verification.
struct LoadedCrl {
    bytes: Vec<u8>,
    tbs: x509_cert::crl::TbsCertList,
    /// The original tbsCertList bytes, never a re-encoding.
    signed: Vec<u8>,
    algorithm: ::der::asn1::ObjectIdentifier,
    /// Whether the complete signature AlgorithmIdentifier is one the webpki
    /// algorithm adapter accepts.
    algorithm_accepted: bool,
    signature: ::der::asn1::BitString,
    /// The issuer, prepared once for RFC 5280 comparison (CRL-041).
    issuer: ComparableName,
    /// The authorityKeyIdentifier keyIdentifier; `Err` when malformed.
    authority_key: core::result::Result<Option<Vec<u8>>, ()>,
    /// The authorityKeyIdentifier's authorityCertIssuer (its directoryNames)
    /// and authorityCertSerialNumber, when well formed.
    authority_cert: Option<AuthorityCert>,
    revoked: Vec<Vec<u8>>,
    /// webpki's own parse. It is not used to check revocation; its errors
    /// name the CRL features rssig does not support (delta, indirect,
    /// unknown critical extensions), reported as `invalid_crl`.
    webpki: core::result::Result<webpki::OwnedCertRevocationList, webpki::Error>,
    /// For a CRL without nextUpdate, which webpki cannot parse: webpki's
    /// verdict on a copy with a stand-in nextUpdate. `None` for a CRL with
    /// nextUpdate, and for one that could not be judged that way.
    stand_in: Option<core::result::Result<(), webpki::Error>>,
}

/// Why a CRL is rejected apart from a missing nextUpdate.
enum Rejection<'a> {
    /// webpki's own rejection.
    Webpki(&'a webpki::Error),
    /// A CRL without nextUpdate whose encoding is not canonical, so webpki
    /// was not asked.
    NotJudged,
}

impl LoadedCrl {
    /// Whether webpki accepts the CRL, or would if only its missing
    /// nextUpdate were present: such a CRL counts under webpki's rules.
    fn webpki_admits(&self) -> bool {
        self.webpki.is_ok() || matches!(self.stand_in, Some(Ok(())))
    }

    /// What webpki rejects the CRL for, other than a missing nextUpdate.
    fn rejection(&self) -> Option<Rejection<'_>> {
        match (&self.stand_in, &self.webpki) {
            (Some(verdict), _) => verdict.as_ref().err().map(Rejection::Webpki),
            (None, Err(e)) if self.tbs.next_update.is_some() => Some(Rejection::Webpki(e)),
            // A CRL without nextUpdate that could not be judged (it does not
            // re-encode to its own bytes): treated as malformed, as webpki
            // would on a normalized copy it must not see; replaceable.
            (None, _) if self.tbs.next_update.is_none() => Some(Rejection::NotJudged),
            _ => None,
        }
    }

    fn load(bytes: &[u8]) -> Result<Self> {
        let crl = CertificateList::from_der(bytes).map_err(crate::compat_error)?;
        let stand_in = stand_in_verdict(&crl, bytes);
        let signed = crate::der::one(bytes, 0x30)
            .and_then(|outer| outer.children())
            .map_err(crate::compat_error)?
            .first()
            .map(|tbs| tbs.full.to_vec())
            .context("CRL lacks tbsCertList")?;
        let tbs = crl.tbs_cert_list;
        let issuer = ComparableName::new(tbs.issuer.to_der().map_err(crate::compat_error)?);
        let aki = tbs
            .crl_extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id == AuthorityKeyIdentifier::OID)
            .map(|e| AuthorityKeyIdentifier::from_der(e.extn_value.as_bytes()));
        let authority_key = match &aki {
            None => Ok(None),
            Some(Ok(aki)) => Ok(aki.key_identifier.as_ref().map(|k| k.as_bytes().to_vec())),
            Some(Err(_)) => Err(()),
        };
        let authority_cert = match aki {
            Some(Ok(aki)) => Some(AuthorityCert {
                issuers: aki
                    .authority_cert_issuer
                    .iter()
                    .flatten()
                    .filter_map(|name| match name {
                        GeneralName::DirectoryName(name) => {
                            name.to_der().ok().map(ComparableName::new)
                        }
                        _ => None,
                    })
                    .collect(),
                serial: aki
                    .authority_cert_serial_number
                    .map(|serial| serial.as_bytes().to_vec()),
            }),
            _ => None,
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
        // The whole AlgorithmIdentifier, parameters included, must be one the
        // webpki adapter accepts for certificates: a CRL signed with an
        // identifier it rejects is unsupported and is never chosen ahead of a
        // usable one.
        let algorithm_accepted = crl
            .signature_algorithm
            .to_der()
            .ok()
            .and_then(|der| {
                crate::der::one(&der, 0x30)
                    .ok()
                    .map(|sequence| sequence.body.to_vec())
            })
            .is_some_and(|identifier| {
                ALGORITHMS
                    .iter()
                    .any(|a| a.signature_alg_id().as_ref() == identifier.as_slice())
            });
        Ok(Self {
            bytes: bytes.to_vec(),
            stand_in,
            signed,
            algorithm_accepted,
            algorithm: crl.signature_algorithm.oid,
            signature: crl.signature,
            issuer,
            authority_key,
            authority_cert,
            revoked,
            webpki,
            tbs,
        })
    }
}

/// The certificate an authorityKeyIdentifier names: the directoryNames of its
/// issuer (any may be the one) and its serial, each when present.
struct AuthorityCert {
    issuers: Vec<ComparableName>,
    serial: Option<Vec<u8>>,
}

/// A certificate of an issuer: its issuer name and serial number.
#[derive(Clone)]
struct CertificateName {
    issuer: ComparableName,
    serial: Vec<u8>,
}

impl CertificateName {
    fn of(cert: &Certificate) -> Result<Self> {
        Ok(Self {
            issuer: ComparableName::new(
                cert.tbs_certificate
                    .issuer
                    .to_der()
                    .map_err(crate::compat_error)?,
            ),
            serial: cert.tbs_certificate.serial_number.as_bytes().to_vec(),
        })
    }
}

/// The key, identifier and CRL-signing permission of a certificate's issuer
/// on one path.
#[derive(Clone)]
struct IssuerKey {
    spki: Vec<u8>,
    key_id: Option<Vec<u8>>,
    /// The issuer's certificate, and any configured root that is this same
    /// anchor: the certificates an authorityKeyIdentifier may name by issuer
    /// and serial.
    certificates: Vec<CertificateName>,
    /// Identifiers of other configured roots that are this same anchor.
    other_key_ids: Vec<Vec<u8>>,
    /// Another configured root that is this same anchor names no key, so a
    /// CRL naming a different one cannot be disproved.
    undisprovable: bool,
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
            certificates: vec![CertificateName::of(cert)?],
            other_key_ids: Vec::new(),
            undisprovable: false,
            crl_sign,
        })
    }
    /// Whether `identifier` names this key.
    fn names(&self, identifier: &[u8]) -> bool {
        self.key_id.as_deref() == Some(identifier)
            || self.other_key_ids.iter().any(|id| id == identifier)
    }
}

/// Whether a supplied CRL's issuer could be on the chain, read from its
/// top-level fields without decoding it in full, and compared re-encoded as
/// the chain's names are. One whose issuer cannot be read is kept, to be
/// decoded and judged.
fn crl_may_apply(bytes: &[u8], issuer_names: &[ComparableName]) -> bool {
    crate::der::tbs_issuer(bytes, 0x02, 1)
        .and_then(|raw| x509_cert::name::Name::from_der(raw).ok())
        .and_then(|name| name.to_der().ok())
        .map(ComparableName::new)
        .is_none_or(|issuer| issuer_names.iter().any(|name| name.matches(&issuer)))
}

/// A path-check failure other than revocation, judged without side effects.
enum PathCheckFailure<'c> {
    /// A CA certificate issued after the lifetime signing time.
    IssuedAfterSigning(&'c Certificate, u64),
    /// A CA certificate whose KeyUsage lacks keyCertSign.
    LacksCertSign,
}

/// The first path-check failure on a path, in the order it is reported:
/// without a lifetime signing time a missing keyCertSign is reported where it
/// is found; with one, every signing-time check comes first, so it outranks a
/// missing keyCertSign wherever each defect sits in the path.
fn path_check_failure(
    path_certificates: &[Certificate],
    lifetime_signed_at: Option<u64>,
) -> core::result::Result<Option<PathCheckFailure<'_>>, webpki::Error> {
    let mut lacks_cert_sign = false;
    for cert in &path_certificates[1..] {
        if let Some(at) = issued_after(cert, lifetime_signed_at) {
            return Ok(Some(PathCheckFailure::IssuedAfterSigning(cert, at)));
        }
        if let Some((_, ku)) = cert
            .tbs_certificate
            .get::<x509_cert::ext::pkix::KeyUsage>()
            .map_err(|_| webpki::Error::BadDer)?
            && !ku.key_cert_sign()
        {
            if lifetime_signed_at.is_none() {
                return Ok(Some(PathCheckFailure::LacksCertSign));
            }
            lacks_cert_sign = true;
        }
    }
    Ok(lacks_cert_sign.then_some(PathCheckFailure::LacksCertSign))
}

/// The CRL that decided one certificate's status on the accepted path.
struct ChosenCrl {
    index: usize,
    /// Whether its authorityKeyIdentifier names the key of the issuer it was
    /// authenticated under.
    names_issuer: bool,
    /// That issuer's subjectPublicKeyInfo.
    issuer_spki: Vec<u8>,
    /// The certificate's issuer name, as webpki matched it to that issuer.
    issuer_name: Vec<u8>,
}

/// Whether the accepted path has two issuers of one name with different
/// keys whose CRLs cannot be told apart: at least one of the two CRLs chosen
/// for them does not name its issuer's key in an authorityKeyIdentifier.
/// `chosen` is in path order, the signer's first.
///
/// Matching a CRL to a certificate by issuer name alone gives both
/// certificates the same CRL, which then fails its signature check under
/// one of the two keys. OpenSSL (`get_crl_sk`, `check_crl`) and BoringSSL
/// reject such a path; Bouncy Castle (`checkCRL`) tries the next CRL and
/// accepts. rssig rejects, as pinned by
/// `crl-008-self-issued-rollover-with-both-crls-is-rejected`. When each CRL
/// names its issuer's key, all three give each certificate its own key's CRL
/// and accept (`crl-007-self-issued-rollover-with-key-identified-crls-verifies`).
fn ambiguous_issuer_keys(chosen: &[ChosenCrl]) -> bool {
    same_name_different_keys(chosen)
        .any(|(first, second)| !(first.names_issuer && second.names_issuer))
}

/// Pairs of CRLs chosen for a path whose issuers have one name and different
/// keys, in path order.
fn same_name_different_keys(
    chosen: &[ChosenCrl],
) -> impl Iterator<Item = (&ChosenCrl, &ChosenCrl)> {
    chosen
        .iter()
        .enumerate()
        .flat_map(move |(position, first)| {
            chosen[position + 1..]
                .iter()
                .filter(move |second| {
                    // One CRL cannot verify under two keys; skipped as the
                    // former rule did.
                    first.index != second.index
                        // The issuers' names on the path, compared as webpki
                        // built it (exact bytes), not the CRLs' issuer fields,
                        // which CRL-041 lets differ in encoding: a CRL cannot
                        // escape this rule by spelling its issuer differently.
                        && first.issuer_name == second.issuer_name
                        && first.issuer_spki != second.issuer_spki
                })
                .map(move |second| (first, second))
        })
}

/// What one certificate's CRLs established on one candidate path.
struct CertificateEvidence {
    /// The candidate path it was evaluated on, in the order webpki tried them.
    path: usize,
    /// Whether that path passes every path check but revocation, so that a
    /// CRL for it could still make it verify.
    path_viable: bool,
    /// Authenticated CRLs that list the certificate but did not count: not
    /// current, older than the deciding CRL, or not covering it.
    ignored_listings: usize,
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
) -> Option<CertificateEvidence> {
    // A certificate decoded from DER re-encodes; one that does not is no
    // evidence of anything and rejects the path.
    let der = cert.to_der().ok()?;
    let sha256 = crate::domain::hex(&crate::crypto::Hash::Sha256.digest(&der));
    // Prepared at most once per certificate per candidate path, when a CRL's
    // issuer differs in bytes (CRL-T033).
    let issuer_name = ComparableName::new(cert.tbs_certificate.issuer.to_der().ok()?);
    let serial = cert.tbs_certificate.serial_number.as_bytes();
    let lists_points = has_extension(cert, "2.5.29.31");
    let points_unreadable = cert
        .tbs_certificate
        .get::<x509_cert::ext::pkix::CrlDistributionPoints>()
        .is_err();
    let mut usable = None;
    // Each with its thisUpdate: the newest usable CRL decides, and a listing
    // counts only from a CRL at least as new.
    let mut authenticated_listing: Option<(usize, u64)> = None;
    // Authenticated CRLs that list the serial, whether or not they count:
    // one that does not is logged, never dropped silently.
    let mut listings: Vec<usize> = Vec::new();
    // The newest listing in a CRL whose only defect is a missing nextUpdate:
    // OpenSSL, BoringSSL and Bouncy Castle use such a CRL, so its listing
    // revokes even when no CRL is usable as evidence of good status.
    let mut revoking_without_next_update: Option<(usize, u64)> = None;
    // The newest authenticated, current, complete CRL definitely in scope
    // for the certificate, listing it or not: as OpenSSL reads only the
    // newest best-scored CRL, a listing older than that does not revoke
    // (it may be a released hold, or released by removeFromCRL there).
    let mut newest_complete: Option<u64> = None;
    let mut failure: Option<(u8, VerificationError)> = None;
    // A failure's error is built only when it would be kept.
    let mut fail = |rank: u8, error: &dyn Fn() -> VerificationError| {
        if failure.as_ref().is_none_or(|(best, _)| rank > *best) {
            failure = Some((rank, error()));
        }
    };
    for (index, crl) in crls.iter().enumerate() {
        if !crl.issuer.matches(&issuer_name) {
            continue;
        }
        // Only the CRL's index is kept per candidate path: its full report
        // (DER and every entry) is built once, for the error returned.
        let with_crl = |error: VerificationError| error.detail(CRL_INDEX, index);
        // Authenticate under this path's issuer key first: what an
        // authenticated CRL lists counts whatever else is wrong with it.
        // A CRL that names another key and is not signed by this one is not
        // this issuer's: it is set aside without a failure.
        let named_key = crl.authority_key.as_ref().ok().and_then(Option::as_ref);
        // A CRL whose issuer equals the certificate's only under CRL-041
        // (another case, spacing or string type), and whose
        // authorityKeyIdentifier does not claim this issuer, is another CA's
        // unless its signature proves otherwise: set aside, so it neither
        // forges a result nor stops retrieval (CRL-018). One that claims this
        // issuer's key or certificate is judged like an exactly named CRL.
        let loose = crl.issuer.der() != issuer_name.der()
            && !claims_issuer(named_key, crl.authority_cert.as_ref(), issuer);
        match verify_signature(index, crl) {
            Ok(Some(true)) => {}
            Ok(Some(false))
                if loose
                    || names_another_key(named_key, issuer)
                    || names_another_certificate(
                        named_key,
                        crl.authority_cert.as_ref(),
                        issuer,
                    ) =>
            {
                continue;
            }
            // Nor is a loosely named CRL that cannot be verified this
            // issuer's unsupported CRL.
            Ok(None) if loose => continue,
            Ok(Some(false)) => {
                fail(FORGED, &|| {
                    with_crl(webpki_revocation_error(
                        &sha256,
                        webpki::Error::InvalidCrlSignatureForPublicKey,
                    ))
                });
                continue;
            }
            // An algorithm the engine cannot verify: unsupported, not forged.
            Ok(None) => {
                fail(UNUSABLE, &|| {
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
        // A listing counts only from a CRL that is current at the validation
        // time, as in OpenSSL (only the best-scored, current CRL is read) and
        // Bouncy Castle (CRLs past nextUpdate are dropped before any entry is
        // read): a stale CRL's entry may be a hold that was since released.
        // One without nextUpdate claims no expiry and is current, as in
        // OpenSSL (`ossl_x509_check_crl_time`), Bouncy Castle (`PKIXCRLUtil`)
        // and BoringSSL, so its listing revokes beside another usable CRL,
        // and alone (below). It is still not evidence of good status (RFC
        // 5280 requires nextUpdate): without a listing it is `invalid_crl`.
        // The newest listing is kept, to be compared with the deciding CRL.
        let this_update = crl.tbs.this_update.to_unix_duration().as_secs();
        let current = this_update <= now
            && crl
                .tbs
                .next_update
                .is_none_or(|next| next.to_unix_duration().as_secs() > now);
        // Nor does one in a CRL that does not cover this certificate (a
        // partition for another point or role): OpenSSL gives it no scope
        // score and Bouncy Castle's processCRLB2 rejects it, so neither reads
        // its entries.
        let authority = authority_for(&crl.tbs, cert, end_entity);
        let covers = listing_in_scope(&crl.tbs, cert, end_entity);
        let lists = crl.revoked.iter().any(|s| s.as_slice() == serial);
        if lists {
            listings.push(index);
        }
        // A CRL that is complete for this certificate: usable but for a
        // possibly missing nextUpdate. It is current, positively in scope
        // (`covers` also admits a CRL whose match cannot be ruled out, which
        // is right for counting a listing beside a usable CRL but not here;
        // `authority` alone admits a point-scoped CRL for a certificate that
        // lists none), has a well-formed authorityKeyIdentifier, comes from an
        // issuer with cRLSign, and webpki accepts it apart from a missing
        // nextUpdate.
        let complete = authority == Some(true)
            && covers
            && current
            && crl.webpki_admits()
            && crl.authority_key.is_ok()
            && issuer.crl_sign;
        // The newest complete CRL decides, as OpenSSL and BoringSSL keep
        // only the newest of equally scored CRLs.
        if complete && newest_complete.is_none_or(|n| this_update > n) {
            newest_complete = Some(this_update);
        }
        // A complete CRL from an issuer with cRLSign is usable (below)
        // unless it lacks nextUpdate, so one recorded here and used when no
        // CRL is usable has that as its sole defect. Its listing then
        // revokes alone, unless the entry is removeFromCRL.
        if complete
            && crl.tbs.next_update.is_none()
            && lists_revoking(&crl.tbs, serial)
            && revoking_without_next_update.is_none_or(|(_, newest)| this_update > newest)
        {
            revoking_without_next_update = Some((index, this_update));
        }
        // Beside a usable CRL, any authenticated, current, covering listing
        // counts, whatever else is wrong with its CRL: rejecting is the safe
        // side (decided in PR #60). Alone, a CRL without nextUpdate revokes
        // only under webpki's other rules (above), since the alternative is
        // a CRL failure that also rejects.
        if current
            && covers
            && lists
            && authenticated_listing.is_none_or(|(_, newest)| this_update > newest)
        {
            authenticated_listing = Some((index, this_update));
        }
        // An issuer without cRLSign signs no usable CRL, whatever else is
        // wrong with this one: recorded first, so that the certificate is
        // not offered to a source.
        if !issuer.crl_sign {
            fail(NO_CRL_SIGN, &|| {
                with_crl(webpki_revocation_error(
                    &sha256,
                    webpki::Error::IssuerNotCrlSigner,
                ))
            });
            continue;
        }
        if crl.authority_key.is_err() {
            fail(REPLACEABLE, &|| {
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
        // webpki would treat a CRL scoped to a named distribution point as
        // authoritative for a certificate that lists none, so such a
        // partition could clear a certificate it does not cover.
        // Replaceable: a certificate that lists no point is still asked
        // about by certificate and issuer, and a full CRL from the source
        // decides, as OpenSSL's store lookup would after a scope miss.
        if !lists_points && names_distribution_point(&crl.tbs) {
            fail(REPLACEABLE, &|| {
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
        // A CRL that webpki can use (apart from a missing nextUpdate) and
        // whose scope is known not to cover this certificate (another point
        // or role) is set aside, whatever its age. One that webpki cannot use
        // is reported below: its scope is not trusted enough to set it aside
        // silently.
        if crl.webpki_admits() && authority == Some(false) {
            continue;
        }
        // Feature support is reported before freshness. Whatever webpki
        // rejects, unsupported or malformed, a source's CRL can replace.
        if let Some(rejection) = crl.rejection() {
            fail(REPLACEABLE, &|| {
                let (message, reason) = match &rejection {
                    Rejection::Webpki(e) => (
                        format!("unsupported or malformed CRL: {e:?}"),
                        crl_rejection_reason(e),
                    ),
                    Rejection::NotJudged => (
                        String::from(
                            "CRL without nextUpdate does not re-encode to its own bytes, so \
                             it cannot be judged",
                        ),
                        "unsupported_or_malformed",
                    ),
                };
                with_crl(
                    revocation_error(&sha256, ErrorCode::InvalidCrl, message)
                        .detail("reason", reason),
                )
            });
            continue;
        }
        if crl.tbs.this_update.to_unix_duration().as_secs() > now {
            fail(NOT_YET_VALID, &|| {
                with_crl(revocation_error(
                    &sha256,
                    ErrorCode::CrlNotYetValid,
                    "CRL thisUpdate is in the future",
                ))
                .detail("validation_time", now)
            });
            continue;
        }
        // A missing nextUpdate is checked last, after the scope defects below:
        // to OpenSSL, BoringSSL and Bouncy Castle it is no defect, so the
        // CRL's other defects decide as they would with nextUpdate present,
        // and are replaceable. Only as the sole defect is it rssig's stricter
        // `invalid_crl`, for which no source is asked: the references would
        // use this CRL and not look again.
        let next_update = crl.tbs.next_update;
        if next_update.is_some_and(|next| next.to_unix_duration().as_secs() <= now) {
            fail(EXPIRED, &|| {
                with_crl(revocation_error(
                    &sha256,
                    ErrorCode::CrlExpired,
                    "CRL has expired",
                ))
                .detail("validation_time", now)
            });
            continue;
        }
        match authority {
            // The newest usable CRL decides, as OpenSSL prefers the latest
            // lastUpdate among equally good CRLs.
            Some(true) if next_update.is_some() => {
                if usable.is_none_or(|(_, newest): (usize, u64)| this_update > newest) {
                    usable = Some((index, this_update));
                }
            }
            // Usable but for the missing nextUpdate (see above).
            Some(true) => fail(UNUSABLE, &|| {
                with_crl(
                    revocation_error(&sha256, ErrorCode::InvalidCrl, "CRL lacks nextUpdate")
                        .detail("reason", "missing_next_update"),
                )
            }),
            Some(false) => {}
            // webpki can use it, but its scope cannot be read here: reported,
            // never silently dropped.
            // The certificate is at fault, not the CRL: its own points
            // cannot be read, so the CRL's scope cannot be matched.
            None if points_unreadable => fail(UNUSABLE, &|| {
                with_crl(
                    revocation_error(
                        &sha256,
                        ErrorCode::InvalidCrl,
                        "certificate cRLDistributionPoints cannot be read, so the CRL's \
                         distribution point cannot be matched",
                    )
                    .detail("reason", "certificate_distribution_points"),
                )
            }),
            None => fail(REPLACEABLE, &|| {
                with_crl(
                    revocation_error(
                        &sha256,
                        ErrorCode::InvalidCrl,
                        "CRL issuingDistributionPoint cannot be read",
                    )
                    .detail("reason", "issuing_distribution_point"),
                )
            }),
        }
    }
    let outcome = match (usable, authenticated_listing) {
        // A current authoritative CRL makes the status known; a listing in
        // a current CRL authenticated by this issuer key that covers the
        // certificate then revokes, unless the deciding CRL is newer: a
        // superseded CRL's entry may be a hold that was since released.
        (Some((_, decided)), Some((listing, listed))) if listed >= decided => Outcome::Revoked(
            webpki_revocation_error(&sha256, webpki::Error::CertRevoked).detail(CRL_INDEX, listing),
        ),
        (Some((index, _)), _) => Outcome::Good(index),
        // Without one, a listing revokes only from a CRL whose sole defect
        // is a missing nextUpdate; otherwise the status is unknown, even if
        // a CRL lists it.
        (None, _) => match revoking_without_next_update {
            // The newest complete CRL decides: an older listing does not
            // count (a newest CRL that revokes is itself this listing).
            Some((listing, listed)) if newest_complete.is_none_or(|newest| listed >= newest) => {
                Outcome::Revoked(
                    webpki_revocation_error(&sha256, webpki::Error::CertRevoked)
                        .detail(CRL_INDEX, listing),
                )
            }
            _ => Outcome::Missing(failure),
        },
    };
    // With a good status, every listing was set aside.
    let ignored_listings = match outcome {
        Outcome::Good(_) => listings.len(),
        _ => 0,
    };
    Some(CertificateEvidence {
        path: 0,
        path_viable: true,
        ignored_listings,
        sha256,
        der,
        outcome,
    })
}

/// A CRL that fails under this issuer's key and whose authorityKeyIdentifier
/// names no key identifier but another certificate, by issuer and serial, is
/// that certificate's CRL, and set aside likewise (CRL-043). The serial and
/// the issuer name must both match one certificate of the issuer, the name as
/// CRL-041 compares names; with several directoryNames, any one may match.
/// RFC 5280 requires the two fields together, so an extension with only one
/// names no certificate and is not judged, nor is one whose issuer holds no
/// directoryName: no other GeneralName form can be compared with a
/// certificate's issuer, so such a CRL stays forged. An
/// extension that does name a key identifier is judged by that alone.
fn names_another_certificate(
    crl_key: Option<&Vec<u8>>,
    named: Option<&AuthorityCert>,
    issuer: &IssuerKey,
) -> bool {
    crl_key.is_none()
        && named.and_then(|named| names_issuer_certificate(named, issuer)) == Some(false)
}

/// Whether an authorityKeyIdentifier claims this issuer: it names a key
/// identifier the issuer cannot disprove (one of its own, or any when it has
/// none, as CRL-042 holds), or one of its certificates by issuer and serial.
fn claims_issuer(
    crl_key: Option<&Vec<u8>>,
    named: Option<&AuthorityCert>,
    issuer: &IssuerKey,
) -> bool {
    match crl_key {
        Some(key) => !names_another_key(Some(key), issuer),
        None => named.and_then(|named| names_issuer_certificate(named, issuer)) == Some(true),
    }
}

/// Whether an authorityKeyIdentifier's issuer and serial name one of this
/// issuer's certificates; `None` when it does not carry both, which RFC 5280
/// requires together, or holds no directoryName to compare.
fn names_issuer_certificate(named: &AuthorityCert, issuer: &IssuerKey) -> Option<bool> {
    let serial = named
        .serial
        .as_ref()
        .filter(|_| !named.issuers.is_empty())?;
    Some(issuer.certificates.iter().any(|certificate| {
        *serial == certificate.serial
            && named
                .issuers
                .iter()
                .any(|name| name.matches(&certificate.issuer))
    }))
}

/// A CRL that fails under this issuer's key is set aside as another key's
/// only when both identifiers are present and differ: an issuer without a
/// subjectKeyIdentifier cannot disprove a match, so the CRL counts as forged.
fn names_another_key(crl_key: Option<&Vec<u8>>, issuer: &IssuerKey) -> bool {
    matches!(
        crl_key,
        Some(named) if !issuer.undisprovable && issuer.key_id.is_some() && !issuer.names(named)
    )
}

/// The error for a revocation rejection, from what the candidate paths
/// established: a revocation first, then the most specific reason a CRL could
/// not be used, else unknown status naming every certificate that lacked a
/// usable CRL. Only paths that pass every other path check decide, unless
/// none does.
fn revocation_failure(outcomes: &[CertificateEvidence]) -> Option<VerificationError> {
    if outcomes.is_empty() {
        return None;
    }
    let viable: Vec<&CertificateEvidence> = outcomes.iter().filter(|o| o.path_viable).collect();
    if viable.is_empty() {
        // No path passes the other path checks. Revocation is still reported
        // first, as webpki checked it first, but the list of certificates
        // without a CRL is empty: no CRL could make such a path verify, so
        // retrieval asks nothing and reports the same result.
        let all: Vec<&CertificateEvidence> = outcomes.iter().collect();
        if let Some(revoked) = first_revocation(&all) {
            return Some(revoked);
        }
        return unknown_status(&all).map(|error| {
            // Nothing is named: no CRL could make such a path verify.
            let mut error = error;
            error.details.remove("certificates_with_expired_crl");
            error.details.remove(WITH_REPLACEABLE_CRL);
            if error.code == ErrorCode::RevocationUnknown {
                error.detail("certificates_without_crl", Vec::<CertificateReport>::new())
            } else {
                error
            }
        });
    }
    let revoked_paths: Vec<usize> = viable
        .iter()
        .filter(|o| matches!(o.outcome, Outcome::Revoked(_)))
        .map(|o| o.path)
        .collect();
    if let Some(revoked) = first_revocation(&viable) {
        // A revocation decides. Another path that passes every other path
        // checks and has certificates with no CRL at all, or whose only CRLs
        // have expired or are otherwise replaceable (not yet valid, malformed,
        // an unsupported feature), could still verify with a current one:
        // they are
        // named, so that a CRL source can be asked about them, as Bouncy
        // Castle tries every path and fetches past an expired CRL. Only a
        // path a source could complete is named: one with a CRL that cannot
        // be replaced (forged, no cRLSign, no nextUpdate) cannot verify whatever
        // is fetched, so nothing on it is asked about.
        let stuck = stuck_paths(&viable);
        let open: Vec<&CertificateEvidence> = viable
            .iter()
            .copied()
            .filter(|o| !revoked_paths.contains(&o.path) && !stuck.contains(&o.path))
            .collect();
        let (_, missing) = without_crl(&open);
        let expired = with_expired_crl(&open);
        let mut revoked = revoked;
        if !missing.is_empty() {
            revoked = revoked.detail("certificates_without_crl", missing);
        }
        if !expired.is_empty() {
            revoked = revoked.detail("certificates_with_expired_crl", expired);
        }
        let unusable = with_replaceable_crl(&open);
        if !unusable.is_empty() {
            revoked = revoked.detail(WITH_REPLACEABLE_CRL, unusable);
        }
        return Some(revoked);
    }
    // A path a source could complete is reported over a stuck path's more
    // specific failure, so that its certificates are named.
    unknown_status(&completable_first(&viable))
}

/// The paths with a CRL that no source can replace (forged, no cRLSign,
/// no nextUpdate, unreadable certificate points): no source could complete
/// them.
fn stuck_paths(outcomes: &[&CertificateEvidence]) -> Vec<usize> {
    outcomes
        .iter()
        .filter(|o| matches!(&o.outcome, Outcome::Missing(Some((rank, _))) if *rank > REPLACEABLE))
        .map(|o| o.path)
        .collect()
}

/// The outcomes of the paths a source could complete, if any has a gap;
/// otherwise all of them, so the most specific failure still decides.
fn completable_first<'a>(outcomes: &[&'a CertificateEvidence]) -> Vec<&'a CertificateEvidence> {
    let stuck = stuck_paths(outcomes);
    let completable: Vec<&CertificateEvidence> = outcomes
        .iter()
        .copied()
        .filter(|o| !stuck.contains(&o.path))
        .collect();
    if completable
        .iter()
        .any(|o| matches!(o.outcome, Outcome::Missing(_)))
    {
        completable
    } else {
        outcomes.to_vec()
    }
}

fn first_revocation(outcomes: &[&CertificateEvidence]) -> Option<VerificationError> {
    outcomes.iter().find_map(|o| match &o.outcome {
        Outcome::Revoked(error) => Some(error.clone()),
        _ => None,
    })
}

/// Whether webpki stopped the path search at one of its own limits.
fn search_limit(e: &webpki::Error) -> bool {
    matches!(
        e,
        webpki::Error::MaximumPathBuildCallsExceeded
            | webpki::Error::MaximumSignatureChecksExceeded
            | webpki::Error::MaximumPathDepthExceeded
            | webpki::Error::MaximumNameConstraintComparisonsExceeded
    )
}

/// The status of a path that passes every path check, has no revocation
/// and only lacks CRLs or has only ones a source's CRL could replace
/// (expired, not yet valid, or another replaceable failure), if any path is
/// like that.
fn completable_path(outcomes: &[CertificateEvidence]) -> Option<VerificationError> {
    let revoked_paths: Vec<usize> = outcomes
        .iter()
        .filter(|o| matches!(o.outcome, Outcome::Revoked(_)))
        .map(|o| o.path)
        .collect();
    let open: Vec<&CertificateEvidence> = outcomes
        .iter()
        .filter(|o| o.path_viable && !revoked_paths.contains(&o.path))
        .collect();
    let stuck = stuck_paths(&open);
    let open: Vec<&CertificateEvidence> = open
        .into_iter()
        .filter(|o| !stuck.contains(&o.path))
        .collect();
    // What a CRL source could still supply: a CRL for a certificate that
    // has none, or one replacing CRLs that are expired or otherwise
    // replaceable. Any other
    // failure is not completable, and the other path's error stands.
    if !open
        .iter()
        .any(|o| matches!(o.outcome, Outcome::Missing(_)))
    {
        return None;
    }
    unknown_status(&open).filter(|error| {
        error.code == ErrorCode::RevocationUnknown
            || error.details.contains_key("certificates_with_expired_crl")
            || error.details.contains_key(WITH_REPLACEABLE_CRL)
    })
}

/// The certificates with no CRL at all, once each, and whether there were
/// any. A certificate whose report cannot be built still counts; it is only
/// not offered for retrieval by name.
fn without_crl(outcomes: &[&CertificateEvidence]) -> (bool, Vec<CertificateReport>) {
    reports(outcomes, |o| matches!(o, Outcome::Missing(None)))
}

/// The certificates whose only CRLs have expired, once each: a source can
/// refresh them, as Bouncy Castle drops expired CRLs and then fetches from
/// the certificate's points.
fn with_expired_crl(outcomes: &[&CertificateEvidence]) -> Vec<CertificateReport> {
    reports(outcomes, |o| {
        matches!(o, Outcome::Missing(Some((EXPIRED, _))))
    })
    .1
}

/// The certificates whose only CRLs are unusable for another reason a
/// source's CRL could replace (not yet valid, an issuingDistributionPoint that
/// cannot be used, an unsupported feature), once each. A CRL known to cover
/// another scope is set aside without a failure, and its certificate is
/// named as one without a CRL.
fn with_replaceable_crl(outcomes: &[&CertificateEvidence]) -> Vec<CertificateReport> {
    reports(outcomes, |o| {
        matches!(o, Outcome::Missing(Some((rank, _))) if *rank > EXPIRED && *rank <= REPLACEABLE)
    })
    .1
}

fn reports(
    outcomes: &[&CertificateEvidence],
    wanted: impl Fn(&Outcome) -> bool,
) -> (bool, Vec<CertificateReport>) {
    let mut seen: Vec<&str> = Vec::new();
    let mut listed: Vec<CertificateReport> = Vec::new();
    for outcome in outcomes {
        if wanted(&outcome.outcome) && !seen.contains(&outcome.sha256.as_str()) {
            seen.push(&outcome.sha256);
            if let Some(report) = Certificate::from_der(&outcome.der)
                .ok()
                .and_then(|c| CertificateReport::parse(&c).ok())
            {
                listed.push(report);
            }
        }
    }
    (!seen.is_empty(), listed)
}

/// The detail under which a rejected path's evidence names a CRL by its
/// index among the loaded CRLs, until the returned error is built.
const CRL_INDEX: &str = "crl_index";

/// Replace each CRL index in the error to be returned, and in the unusable
/// CRL it reports, with that CRL's full report.
fn report_crls(error: &mut VerificationError, crls: &[LoadedCrl]) {
    let report = |index: &serde_json::Value| {
        let crl = index.as_u64().and_then(|i| crls.get(i as usize));
        serde_json::to_value(crl.and_then(|crl| CrlReport::parse(&crl.bytes).ok()))
            .unwrap_or(serde_json::Value::Null)
    };
    if let Some(index) = error.details.remove(CRL_INDEX) {
        error.details.insert("crl".into(), report(&index));
    }
    if let Some(details) = error
        .details
        .get_mut("unusable_crl")
        .and_then(|unusable| unusable.get_mut("details"))
        .and_then(|details| details.as_object_mut())
        && let Some(index) = details.remove(CRL_INDEX)
    {
        details.insert("crl".into(), report(&index));
    }
}

// The ranks of unusable-CRL failures; the highest among a certificate's
// CRLs is reported. Up to `REPLACEABLE`, a CRL from a source can replace
// the unusable one: it has expired, is not yet valid, has an
// issuingDistributionPoint that cannot be used, uses a feature that is not
// supported, or is malformed. OpenSSL and BoringSSL score such a CRL below a
// valid one, or drop it when decoding, and then look the issuer's CRLs up
// in the store (`get_crl_delta`, `get_crl`), and Bouncy Castle fetches after
// any CRL failure. Above it, a source is not asked, by decision: a fetched
// usable CRL would still decide if supplied, but OpenSSL and BoringSSL do
// not score the signature and report its failure (or an unsupported
// signature algorithm) without another lookup (BoringSSL decides the tie
// with Bouncy Castle); an issuer without cRLSign signs no usable CRL; a CRL
// whose only defect is a missing nextUpdate is usable to all three
// references, so none of them would look again (with another defect, that
// defect is reported and decides); and a certificate whose own points
// cannot be read is itself at fault. A CRL
// scoped to a point, for a certificate that lists none, is replaceable: the
// certificate is asked about by certificate and issuer.

/// An expired CRL: replaceable (a source's CRL can decide).
const EXPIRED: u8 = 1;
/// Not yet valid: replaceable.
const NOT_YET_VALID: u8 = 2;
/// The highest replaceable rank (an unusable issuingDistributionPoint, an
/// unsupported feature, a malformed CRL, a point scope for a certificate
/// that lists none): offered to a source.
const REPLACEABLE: u8 = 3;
/// Stuck, a source is not asked: a CRL signed with an algorithm the engine
/// cannot verify, a CRL with no other defect that lacks nextUpdate, or one
/// whose certificate points cannot be read.
const UNUSABLE: u8 = 4;
/// An issuer without cRLSign: stuck.
const NO_CRL_SIGN: u8 = 5;
/// A bad signature: stuck. (An unsupported signature algorithm is
/// `UNUSABLE`: it is not proof of forgery.)
const FORGED: u8 = 6;
// `stuck_paths`, `with_replaceable_crl` and `unknown_status` compare these
// with `<=` and `>`: inserting a rank must keep the order, and the groups
// (replaceable up to `REPLACEABLE`, stuck above it) must be revisited.
const _: () = assert!(
    EXPIRED < NOT_YET_VALID
        && NOT_YET_VALID < REPLACEABLE
        && REPLACEABLE < UNUSABLE
        && UNUSABLE < NO_CRL_SIGN
        && NO_CRL_SIGN < FORGED
);

/// The detail naming certificates whose only CRLs are unusable for a reason
/// other than expiry that a CRL from a source could replace.
pub(crate) const WITH_REPLACEABLE_CRL: &str = "certificates_with_replaceable_crl";

/// The failure for paths without a revocation: unknown status naming every
/// certificate without any CRL, else the most specific unusable CRL.
fn unknown_status(outcomes: &[&CertificateEvidence]) -> Option<VerificationError> {
    // Each certificate in full, so that a CRL source can be asked about it
    // whichever candidate path it was on.
    let (any_without, missing) = without_crl(outcomes);
    let expired = with_expired_crl(outcomes);
    let unusable = with_replaceable_crl(outcomes);
    let named = |mut error: VerificationError| {
        if !expired.is_empty() {
            error = error.detail("certificates_with_expired_crl", expired.clone());
        }
        if !unusable.is_empty() {
            error = error.detail(WITH_REPLACEABLE_CRL, unusable.clone());
        }
        error
    };
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
        // Every failure is one a source's CRL could replace: the error
        // stands, and names the certificates to ask about.
        Some((rank, error)) if !any_without && *rank <= REPLACEABLE => Some(named(error.clone())),
        Some((_, error)) if !any_without => Some(error.clone()),
        best => {
            let error = VerificationError::new(
                ErrorCode::RevocationUnknown,
                Stage::Revocation,
                "no usable authoritative CRL for a certificate on the path",
            )
            .detail("certificates_without_crl", missing);
            let error = named(error);
            Some(match best {
                Some((_, failure)) => error.detail("unusable_crl", failure),
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

/// Whether a revocation listed in this CRL applies to `cert`, as OpenSSL
/// (`crl_crldp_check`) and Bouncy Castle (processCRLB2) decide which CRLs to
/// read entries from:
/// - no issuingDistributionPoint: yes;
/// - one that does not decode, or whose role flags exclude the certificate:
///   no (OpenSSL `IDP_INVALID`; Bouncy Castle skips the CRL);
/// - one that admits the role and names no point: yes
///   (`crl->idp->distpoint == NULL` is in scope);
/// - one that names a point: only on a positive match with a fullName URI
///   the certificate lists. A certificate that lists none does not match. A
///   name form that cannot be compared (relative, non-URI) is no match.
///
/// A certificate whose own points cannot be read fails closed: the listing
/// counts, since a match cannot be ruled out.
fn listing_in_scope(
    tbs: &x509_cert::crl::TbsCertList,
    cert: &Certificate,
    end_entity: bool,
) -> bool {
    use x509_cert::ext::pkix::{
        CrlDistributionPoints,
        crl::dp::IssuingDistributionPoint,
        name::{DistributionPointName, GeneralName},
    };
    let Some(idp) = tbs
        .crl_extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == "2.5.29.28")
    else {
        return true;
    };
    let Ok(idp) = IssuingDistributionPoint::from_der(idp.extn_value.as_bytes()) else {
        return false;
    };
    if idp.only_contains_ca_certs && end_entity || idp.only_contains_user_certs && !end_entity {
        return false;
    }
    let Some(name) = &idp.distribution_point else {
        return true;
    };
    let points = match cert.tbs_certificate.get::<CrlDistributionPoints>() {
        Ok(None) => return false,
        Ok(Some((_, points))) => points.0,
        Err(_) => return true,
    };
    let uris = |name: &DistributionPointName| -> Vec<Vec<u8>> {
        match name {
            DistributionPointName::FullName(names) => names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_bytes().to_vec()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    };
    let scope = uris(name);
    points
        .iter()
        .filter(|p| p.reasons.is_none() && p.crl_issuer.is_none())
        .filter_map(|p| p.distribution_point.as_ref())
        .flat_map(uris)
        .any(|uri| scope.contains(&uri))
}

/// Whether a CRL is authoritative for `cert`: no issuingDistributionPoint,
/// or one whose role flags admit the certificate and that names a fullName
/// URI the certificate lists (or the certificate lists none). This follows
/// webpki 0.103's rule, kept from when webpki also checked revocation. `None` when
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
        // The certificate's points cannot be read (one unsupported name
        // fails the whole extension), so whether a point matches is not
        // known: never a silent mismatch.
        Err(_) => return None,
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
/// algorithm is not one we can map to a digest: the CRL is then unsupported,
/// not forged. A signature that is not whole octets does not verify.
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
    Some(signature.as_bytes().is_some_and(|signature| {
        crate::crypto::verify_spki(spki, hash, oid, message, signature).is_ok()
    }))
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

/// webpki's verdict on a CRL that lacks nextUpdate, as if it had one: the
/// CRL is re-encoded with a stand-in nextUpdate (its thisUpdate) and parsed
/// by webpki, so every other webpki rule applies (version, extensions,
/// cRLNumber, issuingDistributionPoint, every entry, and the signature
/// AlgorithmIdentifier match). The signature is not checked here; it was
/// authenticated over the original bytes.
///
/// `None` for a CRL with nextUpdate, and for one that does not re-encode to
/// exactly its original bytes: webpki must never judge a normalized copy of
/// an encoding it would reject, so such a CRL is not judged and neither
/// revokes alone, clears a listing nor is set aside.
fn stand_in_verdict(
    crl: &CertificateList,
    original: &[u8],
) -> Option<core::result::Result<(), webpki::Error>> {
    if crl.tbs_cert_list.next_update.is_some() {
        return None;
    }
    if crl.to_der().ok().as_deref() != Some(original) {
        return None;
    }
    let mut synthetic = crl.clone();
    synthetic.tbs_cert_list.next_update = Some(synthetic.tbs_cert_list.this_update);
    let der = synthetic.to_der().ok()?;
    Some(
        webpki::BorrowedCertRevocationList::from_der(&der)
            .and_then(|parsed| parsed.to_owned())
            .map(|_| ()),
    )
}

/// Whether the CRL lists `serial` with an entry that revokes: as OpenSSL
/// (`cert_crl`) and Bouncy Castle (step k), which agree, an entry with
/// reasonCode removeFromCRL (8) releases the certificate; webpki and
/// BoringSSL revoke on any entry.
fn lists_revoking(tbs: &x509_cert::crl::TbsCertList, serial: &[u8]) -> bool {
    // Any entry for the serial that revokes counts, as the listing does.
    tbs.revoked_certificates
        .iter()
        .flatten()
        .filter(|r| r.serial_number.as_bytes() == serial)
        .any(|entry| {
            // reasonCode (2.5.29.21): compared as an OID, without allocating.
            const REASON_CODE: ::der::asn1::ObjectIdentifier =
                ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.21");
            !entry
                .crl_entry_extensions
                .iter()
                .flatten()
                .any(|e| e.extn_id == REASON_CODE && e.extn_value.as_bytes() == [0x0a, 1, 8])
        })
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
        on_path(0, sha, outcome)
    }
    fn on_path(path: usize, sha: &str, outcome: Outcome) -> CertificateEvidence {
        let der = include_bytes!("../../tests/fixtures/path-issuer.der").to_vec();
        CertificateEvidence {
            path,
            path_viable: true,
            ignored_listings: 0,
            sha256: sha.into(),
            der,
            outcome,
        }
    }
    fn failed(rank: u8, code: ErrorCode) -> Outcome {
        Outcome::Missing(Some((rank, revocation_error("x", code, "test"))))
    }

    /// A CRL lacking only nextUpdate revokes under webpki's other rules: not
    /// when it is a delta, indirect or reason-partitioned CRL, carries
    /// another critical extension, or its entry is critical or removeFromCRL.
    #[test]
    fn a_crl_without_next_update_revokes_only_under_webpki_rules() {
        use ::der::Decode;
        let crl = x509_cert::crl::CertificateList::from_der(include_bytes!(
            "../../tests/fixtures/crl-root-no-next-update-revoked.crl"
        ))
        .unwrap();
        let outer = crl.clone();
        let base = crl.tbs_cert_list;
        // Whether the test signer, listed by the CRL, is revoked by it alone:
        // `evaluate_crls` decides, with every condition it applies.
        let signer_cert = signer(include_bytes!("../../tests/fixtures/good-pe64.exe"));
        let load = |tbs: &x509_cert::crl::TbsCertList| {
            let mut list = outer.clone();
            list.tbs_cert_list = tbs.clone();
            LoadedCrl::load(&list.to_der().unwrap()).unwrap()
        };
        let revokes_without_next_update = |tbs: &x509_cert::crl::TbsCertList| {
            matches!(
                evaluated(&signer_cert, true, &[load(tbs)]),
                Outcome::Revoked(_)
            )
        };
        // Whether webpki would accept the CRL apart from the missing
        // nextUpdate. A scoped CRL is judged this way: the signer lists no
        // point, so it would be a scope miss before it could revoke.
        let admitted = |tbs: &x509_cert::crl::TbsCertList| load(tbs).webpki_admits();
        assert!(revokes_without_next_update(&base));
        let extension = |oid: &str, critical: bool, value: &[u8]| x509_cert::ext::Extension {
            extn_id: ::der::asn1::ObjectIdentifier::new_unwrap(oid),
            critical,
            extn_value: ::der::asn1::OctetString::new(value).unwrap(),
        };
        let with_crl_extension = |e: x509_cert::ext::Extension| {
            let mut tbs = base.clone();
            tbs.crl_extensions.get_or_insert_with(Vec::new).push(e);
            tbs
        };
        // Delta, indirect, reasons partition, another critical extension.
        for (oid, critical, value) in [
            ("2.5.29.27", true, &[2u8, 1, 1][..]),
            ("2.5.29.28", true, &[0x30, 3, 0x84, 1, 0xff][..]),
            ("2.5.29.28", true, &[0x30, 4, 0x83, 2, 0x07, 0x80][..]),
            ("1.2.3.4", true, &[5, 0][..]),
        ] {
            let tbs = with_crl_extension(extension(oid, critical, value));
            assert!(!revokes_without_next_update(&tbs), "{oid} {value:?}");
        }
        // webpki rejects a v1 CRL.
        let mut v1 = base.clone();
        v1.version = x509_cert::Version::V1;
        assert!(!revokes_without_next_update(&v1));
        // Each issuingDistributionPoint condition on its own, with a fullName
        // point: plain is accepted; indirect, reasons, attribute-only are not.
        let point = [
            0xa0, 0x0c, 0xa0, 0x0a, 0x86, 0x08, b'h', b't', b't', b'p', b':', b'/', b'/', b'a',
        ];
        let idp = |extra: &[u8]| {
            let mut body = point.to_vec();
            body.extend_from_slice(extra);
            let mut der = vec![0x30, body.len() as u8];
            der.extend(body);
            der
        };
        let plain = with_crl_extension(extension("2.5.29.28", true, &idp(&[])));
        assert!(admitted(&plain));
        for extra in [
            &[0x84u8, 1, 0xff][..],
            &[0x83, 2, 0x07, 0x80][..],
            &[0x85, 1, 0xff][..],
        ] {
            let tbs = with_crl_extension(extension("2.5.29.28", true, &idp(extra)));
            assert!(!admitted(&tbs), "{extra:?}");
        }
        // A malformed cRLNumber.
        let mut number = base.clone();
        for e in number.crl_extensions.iter_mut().flatten() {
            if e.extn_id.to_string() == "2.5.29.20" {
                e.extn_value = ::der::asn1::OctetString::new([0x02, 1, 0xff]).unwrap();
            }
        }
        assert!(!revokes_without_next_update(&number));
        // Another entry webpki rejects makes the whole CRL unusable.
        let mut other = base.clone();
        let mut indirect_entry = other.revoked_certificates.as_ref().unwrap()[0].clone();
        indirect_entry.serial_number = x509_cert::serial_number::SerialNumber::from(4242u32);
        indirect_entry.crl_entry_extensions = Some(vec![extension("2.5.29.29", false, &[0x30, 0])]);
        other
            .revoked_certificates
            .as_mut()
            .unwrap()
            .push(indirect_entry);
        assert!(!revokes_without_next_update(&other));
        // No crlExtensions at all, which webpki requires.
        let mut bare = base.clone();
        bare.crl_extensions = None;
        assert!(!revokes_without_next_update(&bare));
        // A tbsCertList signature algorithm that differs from the outer one.
        let mut mismatched = base.clone();
        mismatched.signature.oid = ::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        assert!(!revokes_without_next_update(&mismatched));
        // A duplicate issuingDistributionPoint.
        let mut twice = with_crl_extension(extension("2.5.29.28", true, &idp(&[])));
        twice
            .crl_extensions
            .as_mut()
            .unwrap()
            .push(extension("2.5.29.28", true, &idp(&[])));
        assert!(!revokes_without_next_update(&twice));
        // A role-only issuingDistributionPoint, which webpki 0.103 rejects.
        let role_only = with_crl_extension(extension("2.5.29.28", true, &[0x30, 3, 0x81, 1, 0xff]));
        assert!(!admitted(&role_only));
        // A non-critical unknown extension is ignorable.
        let tbs = with_crl_extension(extension("1.2.3.4", false, &[5, 0]));
        assert!(revokes_without_next_update(&tbs));
        let with_entry_extension = |e: x509_cert::ext::Extension| {
            let mut tbs = base.clone();
            tbs.revoked_certificates.as_mut().unwrap()[0]
                .crl_entry_extensions
                .get_or_insert_with(Vec::new)
                .push(e);
            tbs
        };
        let removed = with_entry_extension(extension("2.5.29.21", false, &[0x0a, 1, 8]));
        assert!(!revokes_without_next_update(&removed));
        let held = with_entry_extension(extension("2.5.29.21", false, &[0x0a, 1, 6]));
        assert!(revokes_without_next_update(&held));
        let critical = with_entry_extension(extension("1.2.3.4", true, &[5, 0]));
        assert!(!revokes_without_next_update(&critical));
        // webpki understands a critical reasonCode and invalidityDate.
        let compromised = with_entry_extension(extension("2.5.29.21", true, &[0x0a, 1, 1]));
        assert!(revokes_without_next_update(&compromised));
        let invalidity = with_entry_extension(extension(
            "2.5.29.24",
            true,
            &[
                0x18, 15, b'2', b'0', b'2', b'7', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0',
                b'0', b'0', b'Z',
            ],
        ));
        assert!(revokes_without_next_update(&invalidity));
        // An undefined reason, and a certificateIssuer (indirect), do not.
        let unused = with_entry_extension(extension("2.5.29.21", false, &[0x0a, 1, 7]));
        assert!(!revokes_without_next_update(&unused));
        let indirect = with_entry_extension(extension("2.5.29.29", false, &[0x30, 0]));
        assert!(!revokes_without_next_update(&indirect));
    }

    /// A revocation beside a path with a replaceable CRL names that path's
    /// certificate, and not one beside a path whose CRL cannot be replaced.
    #[test]
    fn a_revocation_names_a_path_with_a_replaceable_crl() {
        let revoked = || {
            Outcome::Revoked(revocation_error(
                "r",
                ErrorCode::CertificateRevoked,
                "revoked",
            ))
        };
        let error = revocation_failure(&[
            on_path(0, "r", revoked()),
            on_path(1, "u", failed(NOT_YET_VALID, ErrorCode::CrlNotYetValid)),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert!(error.details.contains_key(WITH_REPLACEABLE_CRL));
        let error = revocation_failure(&[
            on_path(0, "r", revoked()),
            on_path(1, "f", failed(FORGED, ErrorCode::InvalidCrlSignature)),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert!(!error.details.contains_key(WITH_REPLACEABLE_CRL));
    }

    #[test]
    fn only_a_replaceable_crl_failure_names_its_certificate() {
        for (rank, code) in [
            (NOT_YET_VALID, ErrorCode::CrlNotYetValid),
            (REPLACEABLE, ErrorCode::InvalidCrl),
        ] {
            let error = revocation_failure(&[evidence("a", failed(rank, code))]).unwrap();
            assert_eq!(error.code, code);
            assert!(error.details.contains_key(WITH_REPLACEABLE_CRL));
            assert!(!error.details.contains_key("certificates_with_expired_crl"));
            assert!(completable_path(&[evidence("a", failed(rank, code))]).is_some());
        }
        for (rank, code) in [
            (UNUSABLE, ErrorCode::InvalidCrl),
            (NO_CRL_SIGN, ErrorCode::InvalidCrl),
            (FORGED, ErrorCode::InvalidCrlSignature),
        ] {
            let error = revocation_failure(&[evidence("a", failed(rank, code))]).unwrap();
            assert_eq!(error.code, code);
            assert!(!error.details.contains_key(WITH_REPLACEABLE_CRL));
            assert!(completable_path(&[evidence("a", failed(rank, code))]).is_none());
        }
        // A certificate without a CRL beside one with a replaceable CRL:
        // unknown status naming both.
        let error = revocation_failure(&[
            evidence("a", Outcome::Missing(None)),
            evidence("b", failed(REPLACEABLE, ErrorCode::InvalidCrl)),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::RevocationUnknown);
        assert!(error.details.contains_key("certificates_without_crl"));
        assert!(error.details.contains_key(WITH_REPLACEABLE_CRL));
    }

    #[test]
    fn a_path_a_source_could_complete_is_reported_over_a_stuck_paths_failure() {
        let expired = || failed(EXPIRED, ErrorCode::CrlExpired);
        let forged = || failed(FORGED, ErrorCode::InvalidCrlSignature);
        // Path 0's CRL is forged (no refresh fixes it); path 1 only has an
        // expired CRL: path 1 is reported, so a source can refresh it.
        let outcomes = [on_path(0, "f", forged()), on_path(1, "e", expired())];
        let error = revocation_failure(&outcomes).unwrap();
        assert_eq!(error.code, ErrorCode::CrlExpired);
        assert!(error.details.contains_key("certificates_with_expired_crl"));
        let error = completable_path(&outcomes).unwrap();
        assert_eq!(error.code, ErrorCode::CrlExpired);
        // A stuck path's certificate without a CRL is not named.
        let outcomes = [
            on_path(0, "f", forged()),
            on_path(0, "m", Outcome::Missing(None)),
            on_path(1, "e", expired()),
        ];
        let error = revocation_failure(&outcomes).unwrap();
        assert_eq!(error.code, ErrorCode::CrlExpired);
        // Every path stuck: the most specific failure decides, as before.
        let error = revocation_failure(&[on_path(0, "f", forged())]).unwrap();
        assert_eq!(error.code, ErrorCode::InvalidCrlSignature);
        assert!(completable_path(&[on_path(0, "f", forged())]).is_none());
    }

    #[test]
    fn a_revocation_names_only_paths_a_source_could_complete() {
        let revoked =
            || Outcome::Revoked(revocation_error("r", ErrorCode::CertificateRevoked, "x"));
        let expired = || failed(EXPIRED, ErrorCode::CrlExpired);
        // Path 1 only lacks or has expired CRLs: both named.
        let error = revocation_failure(&[
            on_path(0, "r", revoked()),
            on_path(1, "m", Outcome::Missing(None)),
            on_path(1, "e", expired()),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert!(error.details.contains_key("certificates_without_crl"));
        assert!(error.details.contains_key("certificates_with_expired_crl"));
        // Path 1 also has a forged CRL that no refresh fixes: nothing on it
        // is named, so no source is asked.
        let error = revocation_failure(&[
            on_path(0, "r", revoked()),
            on_path(1, "m", Outcome::Missing(None)),
            on_path(1, "e", expired()),
            on_path(1, "f", failed(FORGED, ErrorCode::InvalidCrlSignature)),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert!(!error.details.contains_key("certificates_without_crl"));
        assert!(!error.details.contains_key("certificates_with_expired_crl"));
    }

    #[test]
    fn a_revocation_then_a_missing_crl_then_the_most_specific_failure_decides() {
        // A certificate without any CRL outranks one whose CRL is unusable, so
        // that it can still be retrieved.
        let error = revocation_failure(&[
            evidence("a", failed(FORGED, ErrorCode::InvalidCrlSignature)),
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
            evidence("a", failed(EXPIRED, ErrorCode::CrlExpired)),
            evidence("b", failed(UNUSABLE, ErrorCode::InvalidCrl)),
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

    #[test]
    fn a_revocation_decides_and_names_what_another_path_still_lacks() {
        let revoked = || Outcome::Revoked(webpki_revocation_error("r", webpki::Error::CertRevoked));
        let without = |error: &VerificationError| {
            error
                .details
                .get("certificates_without_crl")
                .map(|v| v.as_array().unwrap().len())
        };
        // One path revoked, another only lacking a CRL: the revocation
        // decides, and the other path's gap is named for a CRL source.
        let error = revocation_failure(&[
            on_path(0, "leaf", Outcome::Good(0)),
            on_path(0, "r", revoked()),
            on_path(1, "leaf", Outcome::Good(0)),
            on_path(1, "m", Outcome::Missing(None)),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert_eq!(without(&error), Some(1));
        // Every path revoked: nothing is named.
        let error = revocation_failure(&[
            on_path(0, "r", revoked()),
            on_path(1, "m", Outcome::Missing(None)),
            on_path(1, "r", revoked()),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert_eq!(without(&error), None);
        // A path that only lacks a CRL but fails other path checks (here,
        // keyCertSign) could not be completed: nothing is named.
        let mut blocked = on_path(1, "m", Outcome::Missing(None));
        blocked.path_viable = false;
        let error = revocation_failure(&[on_path(0, "r", revoked()), blocked]).unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert_eq!(without(&error), None);
        // A path with no revocation problem (rejected for another reason)
        // names nothing either.
        let error = revocation_failure(&[
            on_path(0, "r", revoked()),
            on_path(1, "leaf", Outcome::Good(0)),
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert_eq!(without(&error), None);
    }

    #[test]
    fn only_paths_that_pass_other_checks_decide_an_unknown_status() {
        let revoked = || Outcome::Revoked(webpki_revocation_error("r", webpki::Error::CertRevoked));
        // Path 0 could verify but its CRL is unusable; path 1 fails other
        // path checks and lacks a CRL. The usable path's failure decides,
        // and path 1's certificate is not offered for retrieval.
        let mut blocked = on_path(1, "m", Outcome::Missing(None));
        blocked.path_viable = false;
        let error = revocation_failure(&[
            on_path(0, "a", failed(EXPIRED, ErrorCode::CrlExpired)),
            blocked,
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CrlExpired);
        // When no path passes other checks, every tried path decides.
        let mut first = on_path(0, "a", failed(EXPIRED, ErrorCode::CrlExpired));
        first.path_viable = false;
        let mut second = on_path(1, "m", Outcome::Missing(None));
        second.path_viable = false;
        let error = revocation_failure(&[first, second]).unwrap();
        assert_eq!(error.code, ErrorCode::RevocationUnknown);
        // ... but names nothing for retrieval: no CRL could make it verify.
        assert_eq!(
            error.details["certificates_without_crl"],
            serde_json::json!([])
        );
        // A specific CRL failure on such paths carries no such list.
        let mut first = on_path(0, "a", failed(EXPIRED, ErrorCode::CrlExpired));
        first.path_viable = false;
        let error = revocation_failure(&[first]).unwrap();
        assert_eq!(error.code, ErrorCode::CrlExpired);
        assert!(!error.details.contains_key("certificates_without_crl"));
        // A revocation on a path failing other checks does not hide the
        // usable path's own failure.
        let mut blocked = on_path(1, "r", revoked());
        blocked.path_viable = false;
        let error = revocation_failure(&[
            on_path(0, "a", failed(EXPIRED, ErrorCode::CrlExpired)),
            blocked,
        ])
        .unwrap();
        assert_eq!(error.code, ErrorCode::CrlExpired);
    }

    #[test]
    fn a_crl_issuer_written_out_of_der_order_still_matches_the_chain() {
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag, body.len() as u8];
            out.extend_from_slice(body);
            out
        }
        let atv = |oid_last: u8, value: &[u8]| {
            tlv(
                0x30,
                &[tlv(0x06, &[0x55, 0x04, oid_last]), tlv(0x0c, value)].concat(),
            )
        };
        // One RDN with O before CN: valid BER, not DER order.
        let (cn, o) = (atv(0x03, b"b"), atv(0x0a, b"a"));
        let raw = tlv(0x30, &tlv(0x31, &[o.clone(), cn.clone()].concat()));
        let sorted = tlv(0x30, &tlv(0x31, &[cn, o].concat()));
        // tbsCertList: version, signature algorithm, issuer.
        let algorithm = tlv(
            0x30,
            &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        );
        let tbs = tlv(0x30, &[tlv(0x02, &[1]), algorithm, raw.clone()].concat());
        let crl = tlv(0x30, &tbs);
        // The chain's names are re-encoded, so sorted.
        let reencoded = x509_cert::name::Name::from_der(&raw)
            .unwrap()
            .to_der()
            .unwrap();
        assert_eq!(reencoded, sorted);
        assert!(crl_may_apply(&crl, &[ComparableName::new(sorted)]));
        assert!(!crl_may_apply(
            &crl,
            &[ComparableName::new(b"other".to_vec())]
        ));
    }

    #[test]
    fn a_search_limit_is_never_replaced_by_a_completable_path() {
        assert!(search_limit(&webpki::Error::MaximumPathBuildCallsExceeded));
        assert!(search_limit(&webpki::Error::MaximumSignatureChecksExceeded));
        assert!(!search_limit(&webpki::Error::CertExpired {
            time: UnixTime::since_unix_epoch(Duration::from_secs(2)),
            not_after: UnixTime::since_unix_epoch(Duration::from_secs(1)),
        }));
        assert!(!search_limit(&webpki::Error::UnknownIssuer));
    }

    /// The signer of a committed PE fixture.
    fn signer(pe: &[u8]) -> Certificate {
        let pe = crate::parse::Pe::parse(pe).unwrap();
        let cms = pe.signatures().unwrap();
        let sd = crate::parse::SignedData::parse(cms[0]).unwrap();
        sd.certificate_choices()[0].x509().unwrap().clone()
    }
    fn tbs(crl: &[u8]) -> x509_cert::crl::TbsCertList {
        CertificateList::from_der(crl).unwrap().tbs_cert_list
    }

    /// The validation time of the direct `evaluate_crls` tests below.
    const AT: u64 = 1_800_000_000;
    const REVOKING: &[u8] =
        include_bytes!("../../tests/fixtures/crl-root-no-next-update-revoked.crl");

    fn at(seconds: u64) -> x509_cert::time::Time {
        x509_cert::time::Time::UtcTime(
            ::der::asn1::UtcTime::from_unix_duration(core::time::Duration::from_secs(seconds))
                .unwrap(),
        )
    }
    fn crl_extension(oid: &str, critical: bool, value: &[u8]) -> x509_cert::ext::Extension {
        x509_cert::ext::Extension {
            extn_id: ::der::asn1::ObjectIdentifier::new_unwrap(oid),
            critical,
            extn_value: ::der::asn1::OctetString::new(value).unwrap(),
        }
    }
    /// A committed CRL after `edit`, loaded as production loads it. Its
    /// signature no longer verifies; these tests stand in for that check.
    fn edited(base: &[u8], edit: impl FnOnce(&mut CertificateList)) -> LoadedCrl {
        let mut crl = CertificateList::from_der(base).unwrap();
        edit(&mut crl);
        LoadedCrl::load(&crl.to_der().unwrap()).unwrap()
    }
    /// The outcome for `cert` as an end entity, every CRL counting as
    /// authenticated under its issuer's key.
    fn evaluated(cert: &Certificate, crl_sign: bool, crls: &[LoadedCrl]) -> Outcome {
        let issuer = IssuerKey {
            spki: Vec::new(),
            key_id: None,
            certificates: Vec::new(),
            other_key_ids: Vec::new(),
            undisprovable: false,
            crl_sign,
        };
        evaluate_crls(cert, true, &issuer, crls, AT, &mut |_, _| Ok(Some(true)))
            .unwrap()
            .outcome
    }
    /// The rank and `details.reason` (or the code) of an unusable-CRL outcome.
    fn unusable(outcome: &Outcome) -> (u8, String) {
        match outcome {
            Outcome::Missing(Some((rank, error))) => (
                *rank,
                error
                    .details
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .map_or_else(
                        || {
                            String::from(
                                serde_json::to_value(error.code).unwrap().as_str().unwrap(),
                            )
                        },
                        String::from,
                    ),
            ),
            Outcome::Missing(None) => panic!("no CRL failure was recorded"),
            Outcome::Good(_) => panic!("good"),
            Outcome::Revoked(_) => panic!("revoked"),
        }
    }
    /// An issuingDistributionPoint whose fullName is one URI.
    fn named_point(uri: &str) -> Vec<u8> {
        let der = |tag: u8, body: &[u8]| {
            let mut out = vec![tag, body.len() as u8];
            out.extend_from_slice(body);
            out
        };
        der(0x30, &der(0xa0, &der(0xa0, &der(0x86, uri.as_bytes()))))
    }

    /// A CRL whose issuer equals the certificate's only under CRL-041 and
    /// whose signature algorithm cannot be verified is set aside, not this
    /// issuer's unsupported CRL; an exactly named one is reported unusable.
    #[test]
    fn a_loosely_named_crl_that_cannot_be_verified_is_set_aside() {
        let cert = signer(include_bytes!("../../tests/fixtures/good-pe64.exe"));
        let issuer = IssuerKey {
            spki: Vec::new(),
            key_id: None,
            certificates: Vec::new(),
            other_key_ids: Vec::new(),
            undisprovable: false,
            crl_sign: true,
        };
        let outcome = |bytes: &[u8]| {
            let crls = [LoadedCrl::load(bytes).unwrap()];
            evaluate_crls(&cert, true, &issuer, &crls, AT, &mut |_, _| Ok(None))
                .unwrap()
                .outcome
        };
        let loose = outcome(include_bytes!(
            "../../tests/fixtures/crl-root-issuer-case-space.crl"
        ));
        assert!(matches!(loose, Outcome::Missing(None)));
        let exact = outcome(include_bytes!("../../tests/fixtures/good.crl"));
        assert_eq!(unusable(&exact).0, UNUSABLE);
    }

    /// A CRL without nextUpdate that lists the certificate revokes alone
    /// only when every condition holds; with another defect, that defect is
    /// reported as it would be with nextUpdate present, and is replaceable.
    #[test]
    fn a_crl_without_next_update_is_judged_by_its_other_defects() {
        let cert = signer(include_bytes!("../../tests/fixtures/good-pe64.exe"));
        let alone = |edit: &dyn Fn(&mut CertificateList)| {
            evaluated(&cert, true, &[edited(REVOKING, |crl| edit(crl))])
        };
        assert!(matches!(alone(&|_| {}), Outcome::Revoked(_)));
        // From an issuer without cRLSign nothing revokes.
        let unsigned = evaluated(&cert, false, &[edited(REVOKING, |_| {})]);
        assert_eq!(unusable(&unsigned).0, NO_CRL_SIGN);
        // A delta CRL: webpki would reject it with nextUpdate too.
        let delta = alone(&|crl| {
            let extensions = crl
                .tbs_cert_list
                .crl_extensions
                .get_or_insert_with(Vec::new);
            extensions.push(crl_extension("2.5.29.27", true, &[2, 1, 1]));
        });
        assert_eq!(unusable(&delta), (REPLACEABLE, "delta_crl".into()));
        // The entry is removeFromCRL: no other defect, so the missing
        // nextUpdate is what is reported, and no source is asked.
        let released = alone(&|crl| {
            crl.tbs_cert_list.revoked_certificates.as_mut().unwrap()[0].crl_entry_extensions =
                Some(vec![crl_extension("2.5.29.21", false, &[0x0a, 1, 8])]);
        });
        assert_eq!(
            unusable(&released),
            (UNUSABLE, "missing_next_update".into())
        );
        // Not yet valid.
        let early = alone(&|crl| crl.tbs_cert_list.this_update = at(AT + 100));
        assert_eq!(
            unusable(&early),
            (NOT_YET_VALID, "crl_not_yet_valid".into())
        );
        // Scoped to a point, for a certificate that lists none.
        let scoped = alone(&|crl| {
            let extensions = crl
                .tbs_cert_list
                .crl_extensions
                .get_or_insert_with(Vec::new);
            extensions.push(crl_extension(
                "2.5.29.28",
                true,
                &named_point("http://crl.invalid/root.crl"),
            ));
        });
        assert_eq!(
            unusable(&scoped),
            (REPLACEABLE, "distribution_point_scope".into())
        );
        // A malformed authorityKeyIdentifier is another defect: reported and
        // replaceable, as for the same CRL with nextUpdate, which alone does
        // not revoke either.
        let malformed = |crl: &mut CertificateList| {
            let extensions = crl
                .tbs_cert_list
                .crl_extensions
                .get_or_insert_with(Vec::new);
            extensions.push(crl_extension("2.5.29.35", false, &[0x04, 0x00]));
        };
        assert_eq!(
            unusable(&alone(&malformed)),
            (REPLACEABLE, "malformed_authority_key_identifier".into())
        );
        let with_next_update = alone(&|crl| {
            crl.tbs_cert_list.next_update = Some(at(AT + 1000));
            malformed(crl);
        });
        assert_eq!(
            unusable(&with_next_update),
            (REPLACEABLE, "malformed_authority_key_identifier".into())
        );
    }

    /// A newer CRL clears an older listing in a CRL without nextUpdate only
    /// if it is current, covers the certificate, and is otherwise usable.
    #[test]
    fn only_a_usable_covering_crl_clears_a_listing_without_next_update() {
        let cert = signer(include_bytes!("../../tests/fixtures/good-pe64.exe"));
        let beside = |edit: &dyn Fn(&mut CertificateList)| {
            let newer = edited(REVOKING, |crl| {
                crl.tbs_cert_list.revoked_certificates = None;
                crl.tbs_cert_list.this_update = at(AT - 10);
                edit(crl);
            });
            evaluated(&cert, true, &[edited(REVOKING, |_| {}), newer])
        };
        let cleared = beside(&|_| {});
        assert_eq!(unusable(&cleared), (UNUSABLE, "missing_next_update".into()));
        // Not current.
        let early = beside(&|crl| crl.tbs_cert_list.this_update = at(AT + 100));
        assert!(matches!(early, Outcome::Revoked(_)));
        // One webpki would reject apart from nextUpdate.
        let delta = beside(&|crl| {
            let extensions = crl
                .tbs_cert_list
                .crl_extensions
                .get_or_insert_with(Vec::new);
            extensions.push(crl_extension("2.5.29.27", true, &[2, 1, 1]));
        });
        assert!(matches!(delta, Outcome::Revoked(_)));
        // A malformed authorityKeyIdentifier.
        let malformed = beside(&|crl| {
            let extensions = crl
                .tbs_cert_list
                .crl_extensions
                .get_or_insert_with(Vec::new);
            extensions.push(crl_extension("2.5.29.35", false, &[0x04, 0x00]));
        });
        assert!(matches!(malformed, Outcome::Revoked(_)));
        // A partition for a point, when the certificate lists none.
        let scoped = beside(&|crl| {
            let extensions = crl
                .tbs_cert_list
                .crl_extensions
                .get_or_insert_with(Vec::new);
            extensions.push(crl_extension(
                "2.5.29.28",
                true,
                &named_point("http://crl.invalid/root.crl"),
            ));
        });
        assert!(matches!(scoped, Outcome::Revoked(_)));

        // A partition whose match cannot be read (the certificate's own
        // points do not decode) cannot clear a listing in a full CRL.
        let mut leaf = signer(include_bytes!("../../tests/fixtures/crl-leaf-crl-dp.exe"));
        let serial = leaf.tbs_certificate.serial_number.clone();
        let listing = |crl: &mut CertificateList| {
            crl.tbs_cert_list.next_update = None;
            crl.tbs_cert_list.this_update = at(AT - 50);
            crl.tbs_cert_list.revoked_certificates = Some(vec![x509_cert::crl::RevokedCert {
                serial_number: serial.clone(),
                revocation_date: at(AT - 60),
                crl_entry_extensions: None,
            }]);
        };
        let full = include_bytes!("../../tests/fixtures/path-issuer.crl");
        let partition = include_bytes!("../../tests/fixtures/crl-issuer-idp-other.crl");
        let newer_partition = |crl: &mut CertificateList| {
            crl.tbs_cert_list.next_update = None;
            crl.tbs_cert_list.this_update = at(AT - 10);
        };
        // Readable points: the partition is for another point and is set
        // aside, so the listing revokes.
        let readable = evaluated(
            &leaf,
            true,
            &[edited(full, listing), edited(partition, newer_partition)],
        );
        assert!(matches!(readable, Outcome::Revoked(_)));
        leaf.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.31")
            .unwrap()
            .extn_value = ::der::asn1::OctetString::new(vec![0x04, 0x00]).unwrap();
        let unreadable = evaluated(
            &leaf,
            true,
            &[edited(full, listing), edited(partition, newer_partition)],
        );
        assert!(matches!(unreadable, Outcome::Revoked(_)));
    }

    /// A CRL without nextUpdate known to cover another point is set aside
    /// like one with nextUpdate, but only if webpki would otherwise admit it.
    #[test]
    fn a_crl_without_next_update_for_another_point_is_set_aside_if_admitted() {
        let leaf = signer(include_bytes!("../../tests/fixtures/crl-leaf-crl-dp.exe"));
        let partition = include_bytes!("../../tests/fixtures/crl-issuer-idp-other.crl");
        let set_aside = evaluated(
            &leaf,
            true,
            &[edited(partition, |crl| {
                crl.tbs_cert_list.next_update = None
            })],
        );
        assert!(matches!(set_aside, Outcome::Missing(None)));
        let delta = evaluated(
            &leaf,
            true,
            &[edited(partition, |crl| {
                crl.tbs_cert_list.next_update = None;
                let extensions = crl
                    .tbs_cert_list
                    .crl_extensions
                    .get_or_insert_with(Vec::new);
                extensions.push(crl_extension("2.5.29.27", true, &[2, 1, 1]));
            })],
        );
        assert_eq!(unusable(&delta), (REPLACEABLE, "delta_crl".into()));
    }

    /// webpki judges a CRL without nextUpdate on a re-encoded copy, so one
    /// that does not re-encode to its own bytes is not judged: here a
    /// cRLNumber extension with an explicitly encoded `critical FALSE`,
    /// which x509-cert accepts and drops when encoding.
    #[test]
    fn a_crl_that_does_not_reencode_to_its_bytes_is_not_judged() {
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            match body.len() {
                n if n < 0x80 => out.push(n as u8),
                n if n < 0x100 => out.extend([0x81, n as u8]),
                n => out.extend([0x82, (n >> 8) as u8, n as u8]),
            }
            out.extend_from_slice(body);
            out
        }
        let outer = crate::der::one(REVOKING, 0x30).unwrap().children().unwrap();
        let fields = crate::der::one(outer[0].full, 0x30)
            .unwrap()
            .children()
            .unwrap();
        let (wrapper, before) = fields.split_last().unwrap();
        assert_eq!(wrapper.tag, 0xa0);
        let extensions = crate::der::one(wrapper.body, 0x30)
            .unwrap()
            .children()
            .unwrap();
        let mut rebuilt = Vec::new();
        for extension in &extensions {
            let parts = extension.children().unwrap();
            // extnID, then an explicit BOOLEAN FALSE, then extnValue.
            let mut body = parts[0].full.to_vec();
            body.extend([0x01, 0x01, 0x00]);
            body.extend(parts[1..].iter().flat_map(|p| p.full.to_vec()));
            rebuilt.extend(tlv(0x30, &body));
        }
        let mut tbs: Vec<u8> = before.iter().flat_map(|f| f.full.to_vec()).collect();
        tbs.extend(tlv(0xa0, &tlv(0x30, &rebuilt)));
        let mut whole = tlv(0x30, &tbs);
        whole.extend(outer[1..].iter().flat_map(|p| p.full.to_vec()));
        let bytes = tlv(0x30, &whole);
        assert_ne!(bytes, REVOKING);

        let crl = LoadedCrl::load(&bytes).unwrap();
        assert!(crl.stand_in.is_none());
        assert!(!crl.webpki_admits());
        // The canonical CRL is judged and revokes; this one does neither, and
        // is reported as malformed (replaceable), as it would be with
        // nextUpdate.
        assert_eq!(LoadedCrl::load(REVOKING).unwrap().stand_in, Some(Ok(())));
        let cert = signer(include_bytes!("../../tests/fixtures/good-pe64.exe"));
        let outcome = evaluated(&cert, true, &[crl]);
        assert_eq!(
            unusable(&outcome),
            (REPLACEABLE, "unsupported_or_malformed".into())
        );
    }

    #[test]
    fn a_listing_counts_only_on_a_positive_scope_match() {
        // The signer lists http://crl.invalid/sec10-a.crl.
        let listed = signer(include_bytes!("../../tests/fixtures/crl-leaf-crl-dp.exe"));
        let plain = signer(include_bytes!("../../tests/fixtures/good-path-basic.exe"));
        let matching = tbs(include_bytes!(
            "../../tests/fixtures/crl-issuer-idp-match-revoked.crl"
        ));
        let other = tbs(include_bytes!(
            "../../tests/fixtures/crl-issuer-idp-other-revoked.crl"
        ));
        let relative = tbs(include_bytes!(
            "../../tests/fixtures/crl-issuer-idp-relative.crl"
        ));
        let role_only = tbs(include_bytes!(
            "../../tests/fixtures/crl-root-idp-user-certs-revoked.crl"
        ));
        let full = tbs(include_bytes!("../../tests/fixtures/path-issuer.crl"));
        assert!(listing_in_scope(&full, &listed, true));
        assert!(listing_in_scope(&matching, &listed, true));
        assert!(!listing_in_scope(&other, &listed, true));
        // A named partition whose name cannot be compared is no match.
        assert!(!listing_in_scope(&relative, &listed, true));
        // A certificate that lists no point is not in a named partition.
        assert!(!listing_in_scope(&matching, &plain, true));
        // A role-only partition admits its role and nothing else.
        assert!(listing_in_scope(&role_only, &plain, true));
        assert!(!listing_in_scope(&role_only, &plain, false));
    }

    #[test]
    fn unreadable_certificate_points_never_discard_a_partition() {
        // One name x509-cert cannot decode fails the whole extension: the
        // match is unknown, so the partition is neither set aside as out of
        // scope nor are its listings dropped.
        let mut cert = signer(include_bytes!("../../tests/fixtures/crl-leaf-crl-dp.exe"));
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.31")
            .unwrap()
            .extn_value = ::der::asn1::OctetString::new(vec![0x04, 0x00]).unwrap();
        let matching = tbs(include_bytes!(
            "../../tests/fixtures/crl-issuer-idp-match-revoked.crl"
        ));
        assert_eq!(authority_for(&matching, &cert, true), None);
        assert!(listing_in_scope(&matching, &cert, true));
    }

    #[test]
    fn a_crl_algorithm_identifier_the_adapter_rejects_is_unsupported() {
        let good = include_bytes!("../../tests/fixtures/good.crl");
        assert!(LoadedCrl::load(good).unwrap().algorithm_accepted);
        // The same ECDSA OID with NULL parameters, inner and outer: webpki's
        // adapter matches the whole identifier and rejects it, so it must
        // not be ranked as a verifiable CRL.
        let mut crl = CertificateList::from_der(good).unwrap();
        let null = ::der::Any::from_der(&[0x05, 0x00]).unwrap();
        crl.signature_algorithm.parameters = Some(null.clone());
        crl.tbs_cert_list.signature.parameters = Some(null);
        let loaded = LoadedCrl::load(&crl.to_der().unwrap()).unwrap();
        assert!(!loaded.algorithm_accepted);
    }

    #[test]
    fn a_crl_signature_that_is_not_whole_octets_is_invalid_not_unsupported() {
        let crl = LoadedCrl::load(include_bytes!("../../tests/fixtures/good.crl")).unwrap();
        let spki = Certificate::from_der(include_bytes!("../../tests/fixtures/root.der"))
            .unwrap()
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        assert_eq!(
            signed_by(&spki, &crl.algorithm, &crl.signed, &crl.signature),
            Some(true)
        );
        let bits = ::der::asn1::BitString::new(3, crl.signature.raw_bytes()).unwrap();
        assert_eq!(
            signed_by(&spki, &crl.algorithm, &crl.signed, &bits),
            Some(false)
        );
    }

    #[test]
    fn crl_indices_become_reports_only_in_the_returned_error() {
        let crls = [LoadedCrl::load(include_bytes!("../../tests/fixtures/good.crl")).unwrap()];
        let inner = revocation_error("a", ErrorCode::CrlExpired, "x").detail(CRL_INDEX, 0);
        let mut error = revocation_error("a", ErrorCode::RevocationUnknown, "y")
            .detail(CRL_INDEX, 0)
            .detail("unusable_crl", inner);
        report_crls(&mut error, &crls);
        assert!(!error.details.contains_key(CRL_INDEX));
        assert!(error.details["crl"]["der_hex"].is_string());
        let nested = &error.details["unusable_crl"]["details"];
        assert!(nested.get(CRL_INDEX).is_none());
        assert!(nested["crl"]["der_hex"].is_string());
    }

    #[test]
    fn a_path_needing_only_a_fresh_crl_is_completable() {
        // An expired CRL on the path that otherwise verifies: retrieval can
        // refresh it, so it is reported ahead of another path's error.
        let error =
            completable_path(&[on_path(0, "a", failed(EXPIRED, ErrorCode::CrlExpired))]).unwrap();
        assert_eq!(error.code, ErrorCode::CrlExpired);
        assert!(error.details.contains_key("certificates_with_expired_crl"));
        // A CRL that cannot be replaced is not something a source fixes.
        assert!(
            completable_path(&[on_path(0, "a", failed(UNUSABLE, ErrorCode::InvalidCrl))]).is_none()
        );
        // Nor is a path that fails other path checks.
        let mut blocked = on_path(0, "a", failed(EXPIRED, ErrorCode::CrlExpired));
        blocked.path_viable = false;
        assert!(completable_path(&[blocked]).is_none());
    }

    #[test]
    fn only_a_differing_key_identifier_sets_a_failed_crl_aside() {
        let named = vec![1u8, 2];
        let issuer = |key_id: Option<Vec<u8>>, others: Vec<Vec<u8>>| IssuerKey {
            spki: Vec::new(),
            key_id,
            certificates: Vec::new(),
            other_key_ids: others,
            undisprovable: false,
            crl_sign: true,
        };
        assert!(names_another_key(
            Some(&named),
            &issuer(Some(vec![3]), vec![])
        ));
        assert!(!names_another_key(
            Some(&named),
            &issuer(Some(vec![1, 2]), vec![])
        ));
        // An issuer without a subjectKeyIdentifier cannot disprove the match.
        assert!(!names_another_key(Some(&named), &issuer(None, vec![])));
        assert!(!names_another_key(None, &issuer(Some(vec![3]), vec![])));
        assert!(!names_another_key(None, &issuer(None, vec![])));
        // Another configured root with the same key may carry the identifier
        // the CRL names.
        let same_key = issuer(Some(vec![3]), vec![vec![1, 2]]);
        assert!(!names_another_key(Some(&named), &same_key));
        assert!(same_key.names(&[3]) && same_key.names(&[1, 2]) && !same_key.names(&[9]));
        // One same-key root with no identifier: a different one cannot be
        // disproved, but the identifiers that are known still match.
        let mut partial = issuer(Some(vec![3]), vec![vec![1, 2]]);
        partial.undisprovable = true;
        assert!(!names_another_key(Some(&vec![9]), &partial));
        assert!(partial.names(&[1, 2]));
        // The first root has no identifier but a later one does.
        let mut first_bare = issuer(None, vec![vec![1, 2]]);
        first_bare.undisprovable = true;
        assert!(first_bare.names(&[1, 2]));
        // Either order of a bare root and one with an identifier gives the
        // same answer: a CRL naming a different key is not disproved.
        assert!(!names_another_key(Some(&vec![9]), &first_bare));
        let mut bare_later = issuer(Some(vec![1, 2]), vec![]);
        bare_later.undisprovable = true;
        assert!(!names_another_key(Some(&vec![9]), &bare_later));
        assert!(bare_later.names(&[1, 2]));
    }

    #[test]
    fn a_failed_crl_naming_another_certificate_by_issuer_and_serial_is_set_aside() {
        use core::str::FromStr;
        use x509_cert::name::Name;
        let name =
            |text: &str| ComparableName::new(Name::from_str(text).unwrap().to_der().unwrap());
        let issuer = IssuerKey {
            spki: Vec::new(),
            key_id: Some(vec![1]),
            certificates: vec![CertificateName {
                issuer: name("CN=Root"),
                serial: vec![1],
            }],
            other_key_ids: Vec::new(),
            undisprovable: false,
            crl_sign: true,
        };
        let names = |issuer: Option<ComparableName>, serial: Option<Vec<u8>>| AuthorityCert {
            issuers: issuer.into_iter().collect(),
            serial,
        };
        let another = |named: &AuthorityCert, key: Option<&Vec<u8>>| {
            names_another_certificate(key, Some(named), &issuer)
        };
        // The certificate itself, the name compared as in CRL-041: not another's.
        assert!(!another(&names(Some(name("CN=Root")), Some(vec![1])), None));
        assert!(!another(&names(Some(name("CN=root")), Some(vec![1])), None));
        // Another serial or another issuer name is.
        assert!(another(&names(Some(name("CN=Root")), Some(vec![2])), None));
        assert!(another(&names(Some(name("CN=Other")), Some(vec![1])), None));
        // With several issuer names, any one may be the issuer's.
        let several = AuthorityCert {
            issuers: vec![name("CN=Other"), name("CN=Root")],
            serial: Some(vec![1]),
        };
        assert!(!another(&several, None));
        // Only one of the two fields, which RFC 5280 forbids, names nothing.
        assert!(!another(&names(None, Some(vec![2])), None));
        assert!(!another(&names(Some(name("CN=Other")), None), None));
        // Nothing named, or a key identifier named, is judged elsewhere.
        assert!(!another(&names(None, None), None));
        assert!(!another(&names(None, Some(vec![2])), Some(&vec![9])));
        assert!(!names_another_certificate(None, None, &issuer));
        // A configured root that is the same anchor may be the one named.
        let mut same_anchor = issuer.clone();
        same_anchor.certificates.push(CertificateName {
            issuer: name("CN=Root"),
            serial: vec![2],
        });
        assert!(!names_another_certificate(
            None,
            Some(&names(Some(name("CN=Root")), Some(vec![2]))),
            &same_anchor
        ));
        assert!(names_another_certificate(
            None,
            Some(&names(Some(name("CN=Root")), Some(vec![3]))),
            &same_anchor
        ));
    }
}
