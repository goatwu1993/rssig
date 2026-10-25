use crate::crypto::ALGORITHMS;
use crate::domain::{
    CertificateReport, CrlReport, ErrorCode, OidReport, RevocationReport, RevocationStatus, Stage,
    TrustReport, VerificationError, webpki_error,
};
use ::der::{Decode, Encode};
use anyhow::{Context, Result, ensure};
use rustls_pki_types::{CertificateDer, UnixTime};
use std::time::Duration;
use x509_cert::{Certificate, crl::CertificateList};

pub(crate) const CODE_SIGNING: &[u8] = &[43, 6, 1, 5, 5, 7, 3, 3];
pub(crate) const TIME_STAMPING: &[u8] = &[43, 6, 1, 5, 5, 7, 3, 8];

#[derive(Default)]
pub struct TrustStore {
    roots: Vec<CertificateDer<'static>>,
    crls: Vec<Vec<u8>>,
}

impl TrustStore {
    /// Load the platform root store only. No native signature or chain APIs are called.
    pub fn from_system() -> Result<Self> {
        let native = rustls_native_certs::load_native_certs();
        ensure!(
            !native.certs.is_empty(),
            "no system roots loaded: {:?}",
            native.errors
        );
        Ok(Self {
            roots: native.certs,
            crls: Vec::new(),
        })
    }
    /// Add explicit DER or PEM roots. They are trust anchors, not intermediates.
    pub fn add_roots(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.starts_with(b"-----BEGIN") {
            for cert in Certificate::load_pem_chain(bytes)? {
                self.roots.push(CertificateDer::from(cert.to_der()?));
            }
        } else {
            Certificate::from_der(bytes)?;
            self.roots.push(CertificateDer::from(bytes.to_vec()));
        }
        Ok(())
    }
    pub fn add_crl(&mut self, bytes: &[u8]) -> Result<()> {
        let crl = if bytes.starts_with(b"-----BEGIN") {
            let (label, decoded) = ::der::pem::decode_vec(bytes)
                .map_err(|e| anyhow::anyhow!("invalid CRL PEM: {e}"))?;
            ensure!(label == "X509 CRL", "expected X509 CRL PEM label");
            CertificateList::from_der(&decoded)?
        } else {
            CertificateList::from_der(bytes)?
        };
        self.crls.push(crl.to_der()?);
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        leaf: &Certificate,
        certificates: &[Certificate],
        eku: &'static [u8],
        at: u64,
        now: u64,
        revocation: bool,
    ) -> Result<TrustReport> {
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
        if let Some((_, ku)) = leaf.tbs_certificate.get::<KeyUsage>()?
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
        if eku == TIME_STAMPING {
            let (critical, usage) =
                leaf.tbs_certificate
                    .get::<ExtendedKeyUsage>()?
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
        } else {
            let (_, usage) = leaf
                .tbs_certificate
                .get::<ExtendedKeyUsage>()?
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
        }
        let leaf_report = CertificateReport::parse(leaf)?;
        let leaf = CertificateDer::from(leaf.to_der()?);
        let leaf = webpki::EndEntityCert::try_from(&leaf)
            .map_err(|e| anyhow::anyhow!("invalid signer certificate: {e:?}"))?;
        let roots: Vec<_> = self
            .roots
            .iter()
            .filter_map(|c| webpki::anchor_from_trusted_cert(c).ok())
            .collect();
        ensure!(!roots.is_empty(), "no supported trust anchors");
        let intermediates: Vec<_> = certificates
            .iter()
            .map(|c| c.to_der().map(CertificateDer::from))
            .collect::<std::result::Result<_, _>>()?;
        let mut parsed_crls = Vec::new();
        if revocation {
            if self.crls.is_empty() {
                return Err(VerificationError::new(ErrorCode::RevocationUnknown, Stage::Revocation, "revocation requires --crl files covering the signer and intermediate certificates").into());
            }
            for bytes in &self.crls {
                let crl = CertificateList::from_der(bytes)?;
                let tbs = crl.tbs_cert_list;
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
                if tbs
                    .next_update
                    .context("CRL lacks nextUpdate")?
                    .to_unix_duration()
                    .as_secs()
                    <= now
                {
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
        let invalid_ca_usage = std::cell::Cell::new(false);
        let check_ca_usage = |path: &webpki::VerifiedPath<'_>| {
            for intermediate in path.intermediate_certificates() {
                let cert = Certificate::from_der(intermediate.der().as_ref())
                    .map_err(|_| webpki::Error::BadDer)?;
                if let Some((_, ku)) = cert
                    .tbs_certificate
                    .get::<KeyUsage>()
                    .map_err(|_| webpki::Error::BadDer)?
                    && !ku.key_cert_sign()
                {
                    invalid_ca_usage.set(true);
                    return Err(webpki::Error::UnknownIssuer);
                }
            }
            Ok(())
        };
        // An absent EKU in a CA is unrestricted. The leaf is required to have
        // the requested EKU above; any CA EKU that is present must permit it.
        let path = leaf
            .verify_for_usage(
                ALGORITHMS,
                &roots,
                &intermediates,
                UnixTime::since_unix_epoch(Duration::from_secs(at)),
                webpki::KeyUsage::required_if_present(eku),
                revocation,
                Some(&check_ca_usage),
            )
            .map_err(|e| {
                let mut error = if invalid_ca_usage.get() && e == webpki::Error::UnknownIssuer {
                    VerificationError::new(
                        ErrorCode::InvalidKeyUsage,
                        Stage::CertificateChain,
                        "intermediate certificate KeyUsage lacks keyCertSign",
                    )
                } else {
                    webpki_error(e)
                };
                error = error.detail("certificate", &leaf_report).detail(
                    "required_eku",
                    ::der::asn1::ObjectIdentifier::from_bytes(eku)
                        .map(|o| o.to_string())
                        .unwrap_or_default(),
                );
                error
            })?;
        let mut chain = vec![leaf_report];
        for intermediate in path.intermediate_certificates() {
            chain.push(CertificateReport::parse(&Certificate::from_der(
                intermediate.der().as_ref(),
            )?)?);
        }
        for root in &self.roots {
            if let Ok(anchor) = webpki::anchor_from_trusted_cert(root)
                && anchor.subject == path.anchor().subject
                && anchor.subject_public_key_info == path.anchor().subject_public_key_info
            {
                chain.push(CertificateReport::parse(&Certificate::from_der(
                    root.as_ref(),
                )?)?);
                break;
            }
        }
        Ok(TrustReport {
            validation_time: at,
            required_eku: OidReport::new(::der::asn1::ObjectIdentifier::from_bytes(eku)?),
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
