//! Authenticode signer orchestration: integrity, CMS, timestamp, trust, report.
use super::{
    VerifyOptions,
    container::{Container, cms_der},
    integrity, tagged,
    timestamp::{check_fractional_validity, verify_timestamp},
};
use crate::{
    cms::{self, SignedData},
    crypto::Hash,
    domain::*,
    format::Format,
    trust,
};
use anyhow::{Context, Result};

pub(super) fn verify_container(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
    format: Format,
    mut container: Container<'_>,
) -> Result<VerificationBundle> {
    let mut reports = Vec::new();
    for signature in container.signatures()? {
        verify_signature(
            cms_der(&signature, format)?,
            &mut container,
            options,
            0,
            &mut reports,
        )?;
    }
    let mut verification = VerificationBundle {
        format: format.report_name().into(),
        validation_time: options.now,
        file_sha256: hex(&Hash::Sha256.digest(bytes)),
        signatures: reports,
        rdp: None,
        appx: match &container {
            Container::Appx(appx) => appx.report.clone(),
            _ => None,
        },
    };
    if let Container::Appx(appx) = &container
        && appx.is_bundle()
    {
        super::appx::verify_bundle(appx, &mut verification, options)?;
    }
    Ok(verification)
}

fn verify_signature(
    bytes: &[u8],
    container: &mut Container<'_>,
    options: &VerifyOptions<'_>,
    depth: usize,
    reports: &mut Vec<SignatureReport>,
) -> Result<()> {
    if depth > 8 || reports.len() >= 64 {
        return Err(VerificationError::new(
            ErrorCode::MalformedCms,
            Stage::Cms,
            "too many nested signatures",
        )
        .into());
    }
    let sd = tagged(
        SignedData::parse(bytes),
        ErrorCode::MalformedCms,
        Stage::Cms,
    )?;
    let integrity = integrity::verify(container, &sd, options.allow_sha1)?;
    for si in &sd.signers {
        let signer = tagged(
            sd.verify(*si, options.allow_sha1)
                .context("CMS signature verification"),
            ErrorCode::InvalidSignature,
            Stage::Cms,
        )?;
        if let Container::Appx(appx) = container {
            tagged(
                appx.publisher(&signer.cert),
                ErrorCode::AppxPublisherMismatch,
                Stage::Appx,
            )?;
        }
        let timestamp_verification = tagged(
            verify_timestamp(&sd.certs, &signer, options),
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
        if let Some(timestamp) = &timestamp_verification {
            check_fractional_validity(
                trust_report.as_ref(),
                timestamp.signing_time,
                timestamp.fractional_seconds.as_deref(),
            )?;
        }
        reports.push(SignatureReport {
            unverified_certificate_choices: sd.unverified_certificate_choices.clone(),
            subject: certificate.subject.display.clone(),
            digest_algorithm: format!("{:?}", integrity.hash),
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
            image_digest: integrity.image_digest.clone(),
            package_digest: integrity.package_digest.clone(),
            script_digest: integrity.script_digest.clone(),
            extended_digest: integrity.extended_digest.clone(),
            page_hashes: integrity.page_hashes.clone(),
            trust: trust_report,
            timestamp_verification,
        });
        for (oid, values) in &signer.unsigned {
            if oid == cms::NESTED {
                for value in values {
                    verify_signature(value.full, container, options, depth + 1, reports)?;
                }
            }
        }
    }
    Ok(())
}
