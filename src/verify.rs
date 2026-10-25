use crate::domain::*;
use crate::{
    cms::{self, SignedData},
    crypto::Hash,
    der::{self, Node},
    pe::Pe,
    trust::{self, TrustStore},
};
use ::der::Decode;
use anyhow::{Context, Result, ensure};

pub struct VerifyOptions<'a> {
    pub trust: Option<&'a TrustStore>,
    pub check_revocation: bool,
    pub allow_sha1: bool,
    pub now: u64,
}

pub fn verify_pe(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

fn tagged<T>(result: Result<T>, code: ErrorCode, stage: Stage) -> Result<T> {
    result.map_err(|e| VerificationError::from_internal(e, code, stage).into())
}

fn verify_inner(bytes: &[u8], options: &VerifyOptions<'_>) -> Result<VerificationBundle> {
    let pe = tagged(Pe::parse(bytes), ErrorCode::InvalidPe, Stage::Pe)?;
    let mut reports = Vec::new();
    for certificate in tagged(
        pe.certificates(),
        ErrorCode::InvalidCertificateTable,
        Stage::CertificateTable,
    )? {
        // Some signers count zero padding inside dwLength. Only permit zeroes
        // after one complete DER object, never arbitrary unsigned payloads.
        let mut rest = certificate;
        let node = tagged(der::take(&mut rest), ErrorCode::MalformedCms, Stage::Cms)?;
        if !rest.iter().all(|b| *b == 0) {
            return Err(VerificationError::new(
                ErrorCode::InvalidCertificateTable,
                Stage::CertificateTable,
                "nonzero trailing data in WIN_CERTIFICATE",
            )
            .detail("trailing_bytes", rest.len())
            .into());
        }
        verify_signature(node.full, &pe, options, 0, &mut reports)?;
    }
    Ok(VerificationBundle {
        format: "pe_authenticode".into(),
        validation_time: options.now,
        file_sha256: hex(&Hash::Sha256.digest(bytes)),
        signatures: reports,
    })
}

fn verify_signature(
    bytes: &[u8],
    pe: &Pe<'_>,
    options: &VerifyOptions<'_>,
    depth: usize,
    reports: &mut Vec<SignatureReport>,
) -> Result<()> {
    ensure!(
        depth <= 8 && reports.len() < 64,
        "too many nested signatures"
    );
    let sd = tagged(
        SignedData::parse(bytes),
        ErrorCode::MalformedCms,
        Stage::Cms,
    )?;
    let (hash, expected) = tagged(sd.image_digest(), ErrorCode::MalformedCms, Stage::Cms)?;
    if !options.allow_sha1 && hash == Hash::Sha1 {
        return Err(VerificationError::new(
            ErrorCode::WeakAlgorithm,
            Stage::ImageDigest,
            "SHA-1 image digest requires --allow-sha1",
        )
        .into());
    }
    let computed = pe.digest(hash)?;
    let image_digest = DigestReport {
        algorithm: format!("{hash:?}"),
        expected: hex(expected),
        computed: hex(&computed),
    };
    if computed != expected {
        return Err(VerificationError::new(
            ErrorCode::ImageDigestMismatch,
            Stage::ImageDigest,
            "PE image digest mismatch (file was modified)",
        )
        .detail("digest", &image_digest)
        .into());
    }
    let mut page_hashes = None;
    if let Some((hash, expected)) =
        tagged(sd.page_hashes(), ErrorCode::MalformedCms, Stage::PageHashes)?
    {
        if !options.allow_sha1 && hash == Hash::Sha1 {
            return Err(VerificationError::new(
                ErrorCode::WeakAlgorithm,
                Stage::PageHashes,
                "SHA-1 page hashes require --allow-sha1",
            )
            .into());
        }
        let computed = pe.page_hashes(hash)?;
        let report = DigestReport {
            algorithm: format!("{hash:?}"),
            expected: hex(expected),
            computed: hex(&computed),
        };
        if computed != expected {
            return Err(VerificationError::new(
                ErrorCode::PageHashMismatch,
                Stage::PageHashes,
                "PE page hash mismatch",
            )
            .detail("page_hashes", &report)
            .into());
        }
        page_hashes = Some(report);
    }
    for si in &sd.signers {
        let signer = tagged(
            sd.verify(*si, options.allow_sha1)
                .context("CMS signature verification"),
            ErrorCode::InvalidSignature,
            Stage::Cms,
        )?;
        let timestamp_verification = tagged(
            verify_timestamp(&sd, &signer, options),
            ErrorCode::InvalidTimestamp,
            Stage::Timestamp,
        )?;
        let timestamp = timestamp_verification.as_ref().map(|t| t.signing_time);
        let trust_report = if let Some(trust) = options.trust {
            Some(tagged(
                trust.verify(
                    &signer.cert,
                    &sd.certs,
                    trust::CODE_SIGNING,
                    timestamp.unwrap_or(options.now),
                    options.now,
                    options.check_revocation,
                ),
                ErrorCode::CertificateChainInvalid,
                Stage::CertificateChain,
            )?)
        } else {
            None
        };
        let certificate = CertificateReport::parse(&signer.cert)?;
        reports.push(SignatureReport {
            subject: certificate.subject.display.clone(),
            digest_algorithm: format!("{hash:?}"),
            certificate_sha256: certificate.sha256.clone(),
            timestamp,
            chain_trusted: options.trust.is_some(),
            revocation_checked: options.trust.is_some() && options.check_revocation,
            nested_depth: depth,
            certificate,
            embedded_certificates: sd
                .certs
                .iter()
                .map(CertificateReport::parse)
                .collect::<Result<_>>()?,
            image_digest: image_digest.clone(),
            page_hashes: page_hashes.clone(),
            trust: trust_report,
            timestamp_verification,
        });
        for (oid, values) in &signer.unsigned {
            if oid == cms::NESTED {
                for value in values {
                    verify_signature(value.full, pe, options, depth + 1, reports)?;
                }
            }
        }
    }
    Ok(())
}

fn verify_timestamp(
    sd: &SignedData<'_>,
    signer: &cms::Signer<'_>,
    options: &VerifyOptions<'_>,
) -> Result<Option<TimestampReport>> {
    let mut timestamp = None;
    for (oid, values) in &signer.unsigned {
        if oid.as_slice() == cms::RFC3161 || oid.as_slice() == cms::CMS_TIMESTAMP {
            ensure!(
                values.len() == 1 && timestamp.is_none(),
                "multiple timestamps are unsupported"
            );
            let mut token = SignedData::parse(values[0].full)?;
            token.certs.extend(sd.certs.iter().cloned());
            ensure!(
                token.content_type == cms::TST_INFO && token.signers.len() == 1,
                "invalid RFC3161 token"
            );
            let info = token.content.children()?;
            ensure!(info.len() >= 5, "truncated TSTInfo");
            let imprint = der::fields(info[2].expect(0x30)?, 2)?;
            let hash = cms::algorithm(imprint[0])?;
            ensure!(
                options.allow_sha1 || hash != Hash::Sha1,
                "SHA-1 timestamp requires --allow-sha1"
            );
            let expected = imprint[1].expect(4)?.body;
            let computed = hash.digest(signer.signature);
            if expected != computed {
                return Err(VerificationError::new(
                    ErrorCode::TimestampImprintMismatch,
                    Stage::Timestamp,
                    "timestamp imprint mismatch",
                )
                .detail("expected", hex(expected))
                .detail("computed", hex(&computed))
                .into());
            }
            let at = parse_time(info[4])?;
            if at > options.now {
                return Err(VerificationError::new(
                    ErrorCode::TimestampInFuture,
                    Stage::Timestamp,
                    "timestamp is in the future",
                )
                .detail("signing_time", at)
                .detail("validation_time", options.now)
                .into());
            }
            let tsa = token.verify(token.signers[0], options.allow_sha1)?;
            let trust_report = if let Some(trust) = options.trust {
                Some(trust.verify(
                    &tsa.cert,
                    &token.certs,
                    trust::TIME_STAMPING,
                    at,
                    options.now,
                    options.check_revocation,
                )?)
            } else {
                None
            };
            timestamp = Some(TimestampReport {
                kind: "rfc3161".into(),
                signing_time: at,
                certificate: CertificateReport::parse(&tsa.cert)?,
                trust: trust_report,
            });
        } else if oid.as_slice() == cms::COUNTERSIGN {
            ensure!(
                values.len() == 1 && timestamp.is_none(),
                "multiple timestamps are unsupported"
            );
            let tsa = sd.verify_signer(values[0], signer.signature, None, options.allow_sha1)?;
            let time = cms::attribute(&tsa.signed, &[42, 134, 72, 134, 247, 13, 1, 9, 5])?
                .context("countersignature lacks signingTime")?;
            let at = parse_time(time)?;
            if at > options.now {
                return Err(VerificationError::new(
                    ErrorCode::TimestampInFuture,
                    Stage::Timestamp,
                    "timestamp is in the future",
                )
                .detail("signing_time", at)
                .detail("validation_time", options.now)
                .into());
            }
            let trust_report = if let Some(trust) = options.trust {
                Some(trust.verify(
                    &tsa.cert,
                    &sd.certs,
                    trust::TIME_STAMPING,
                    at,
                    options.now,
                    options.check_revocation,
                )?)
            } else {
                None
            };
            timestamp = Some(TimestampReport {
                kind: "pkcs9_countersignature".into(),
                signing_time: at,
                certificate: CertificateReport::parse(&tsa.cert)?,
                trust: trust_report,
            });
        }
    }
    Ok(timestamp)
}

fn parse_time(node: Node<'_>) -> Result<u64> {
    match node.tag {
        0x17 => Ok(::der::asn1::UtcTime::from_der(node.full)?
            .to_unix_duration()
            .as_secs()),
        0x18 => Ok(::der::asn1::GeneralizedTime::from_der(node.full)?
            .to_unix_duration()
            .as_secs()),
        _ => anyhow::bail!("invalid timestamp time encoding"),
    }
}
