//! Timestamp binding, TSA trust, and exact fractional-time policy.
use super::VerifyOptions;
use crate::{
    cms::{self, SignedData},
    crypto::Hash,
    der::{self, Node},
    domain::*,
    trust,
};
use anyhow::{Context, Result, ensure};

pub(crate) fn verify_timestamp(
    certificates: &[x509_cert::Certificate],
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
            token.certs.extend(certificates.iter().cloned());
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
            let (at, fractional_seconds) = parse_time(info[4])?;
            if at > options.now || (at == options.now && fractional_seconds.is_some()) {
                return Err(VerificationError::new(
                    ErrorCode::TimestampInFuture,
                    Stage::Timestamp,
                    "timestamp is in the future",
                )
                .detail("signing_time", at)
                .detail("fractional_seconds", &fractional_seconds)
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
            check_fractional_validity(trust_report.as_ref(), at, fractional_seconds.as_deref())?;
            timestamp = Some(TimestampReport {
                fractional_seconds,
                kind: "rfc3161".into(),
                unverified_certificate_choices: token.unverified_certificate_choices,
                signing_time: at,
                certificate: CertificateReport::parse(&tsa.cert)?,
                trust: trust_report,
            });
        } else if oid.as_slice() == cms::COUNTERSIGN {
            ensure!(
                values.len() == 1 && timestamp.is_none(),
                "multiple timestamps are unsupported"
            );
            let tsa = cms::verify_countersigner(
                certificates,
                values[0],
                signer.signature,
                options.allow_sha1,
            )?;
            let time = cms::attribute(&tsa.signed, &[42, 134, 72, 134, 247, 13, 1, 9, 5])?
                .context("countersignature lacks signingTime")?;
            let (at, fractional_seconds) = parse_time(time)?;
            if at > options.now || (at == options.now && fractional_seconds.is_some()) {
                return Err(VerificationError::new(
                    ErrorCode::TimestampInFuture,
                    Stage::Timestamp,
                    "timestamp is in the future",
                )
                .detail("signing_time", at)
                .detail("fractional_seconds", &fractional_seconds)
                .detail("validation_time", options.now)
                .into());
            }
            let trust_report = if let Some(trust) = options.trust {
                Some(trust.verify(
                    &tsa.cert,
                    certificates,
                    trust::TIME_STAMPING,
                    at,
                    options.now,
                    options.check_revocation,
                )?)
            } else {
                None
            };
            check_fractional_validity(trust_report.as_ref(), at, fractional_seconds.as_deref())?;
            timestamp = Some(TimestampReport {
                fractional_seconds,
                kind: "pkcs9_countersignature".into(),
                unverified_certificate_choices: Vec::new(),
                signing_time: at,
                certificate: CertificateReport::parse(&tsa.cert)?,
                trust: trust_report,
            });
        }
    }
    Ok(timestamp)
}

pub(crate) fn check_fractional_validity(
    trust: Option<&TrustReport>,
    seconds: u64,
    fraction: Option<&str>,
) -> Result<()> {
    if let (Some(trust), Some(fraction)) = (trust, fraction) {
        // webpki checks notBefore and notAfter at whole seconds. Also check the
        // nonzero fraction against leaf/intermediate expiry. Trust anchors are
        // configured keys and retain webpki's validity policy.
        for cert in trust.chain.iter().take(trust.chain.len().saturating_sub(1)) {
            if cert.not_after <= seconds {
                return Err(VerificationError::new(
                    ErrorCode::CertificateExpired,
                    Stage::CertificateChain,
                    "fractional timestamp exceeds certificate validity",
                )
                .detail("certificate", cert)
                .detail("validation_time", seconds)
                .detail("fractional_seconds", fraction)
                .into());
            }
        }
    }
    Ok(())
}

fn parse_time(node: Node<'_>) -> Result<(u64, Option<String>)> {
    let time = crate::parse::ParsedTime::parse(node.full).map_err(|error| error.inner)?;
    Ok((
        time.unix_seconds(),
        time.fractional_seconds().map(Into::into),
    ))
}

#[cfg(test)]
mod time_tests {
    use super::*;
    use crate::{TrustStore, verify_pe};

    fn time(text: &str) -> Result<(u64, Option<String>)> {
        let mut bytes = vec![0x18, text.len() as u8];
        bytes.extend_from_slice(text.as_bytes());
        parse_time(der::one(&bytes, 0x18)?)
    }

    #[test]
    fn generalized_time_preserves_fraction_and_requires_canonical_bounded_precision() {
        assert_eq!(time("20270115080000Z").unwrap(), (1800000000, None));
        assert_eq!(
            time("20270115080000.009Z").unwrap(),
            (1800000000, Some("009".into()))
        );
        assert!(time(&format!("20270115080000.{}1Z", "0".repeat(63))).is_ok());
        assert!(time(&format!("20270115080000.{}1Z", "0".repeat(64))).is_err());
        for text in [
            "20270115080000.Z",
            "20270115080000.0Z",
            "20270115080000.50Z",
            "20270115080000,5Z",
            "20270115080000.5+0000",
            "20270115080000.aZ",
            "20270230080000.5Z",
            "20270115086000.5Z",
        ] {
            assert!(time(text).is_err(), "{text}");
        }
    }

    #[test]
    fn fractional_expiry_checks_leaf_and_intermediates_but_not_configured_anchor() {
        let bytes = include_bytes!("../../tests/fixtures/good-intermediate.exe");
        let mut store = TrustStore::default();
        store
            .add_roots(include_bytes!("../../tests/fixtures/root.der"))
            .unwrap();
        let options = VerifyOptions {
            trust: Some(&store),
            check_revocation: false,
            allow_sha1: false,
            now: 1800000000,
        };
        let verified = verify_pe(bytes, &options).unwrap();
        let trust = verified.signatures[0].trust.as_ref().unwrap();
        assert_eq!(trust.chain.len(), 3);
        for index in 0..trust.chain.len() {
            let mut trust = trust.clone();
            trust.chain[index].not_after = options.now;
            assert!(check_fractional_validity(Some(&trust), options.now, None).is_ok());
            let result = check_fractional_validity(Some(&trust), options.now, Some("001"));
            if index < 2 {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok());
            }
        }
    }
}
