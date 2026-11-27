//! Timestamp binding, TSA trust and canonical time decoding.
use super::{VerifyOptions, budget::Budget};
use crate::{
    cms::{self, SignedData},
    crypto::Hash,
    der::{self, Node},
    domain::*,
    trust,
};
#[cfg(test)]
use alloc::{format, vec};
use alloc::{string::String, vec::Vec};
use anyhow::{Context, Result, ensure};

pub(crate) fn verify_timestamp(
    certificates: &[x509_cert::Certificate],
    signer: &cms::Signer<'_, '_>,
    options: &VerifyOptions<'_>,
    budget: &Budget,
) -> Result<Option<TimestampReport>> {
    // TSA-004: a signer has at most one timestamp. Count them before judging any,
    // so a second timestamp is never masked by the first one's own failure.
    let timestamps: usize = signer
        .unsigned
        .iter()
        .filter(|(oid, _)| {
            matches!(
                oid.as_slice(),
                cms::RFC3161 | cms::CMS_TIMESTAMP | cms::COUNTERSIGN
            )
        })
        .map(|(_, values)| values.len())
        .sum();
    ensure!(timestamps <= 1, "multiple timestamps are unsupported");
    let mut timestamp = None;
    for (oid, values) in &signer.unsigned {
        if oid.as_slice() == cms::RFC3161 || oid.as_slice() == cms::CMS_TIMESTAMP {
            ensure!(
                values.len() == 1 && timestamp.is_none(),
                "multiple timestamps are unsupported"
            );
            budget.cms(values[0].full)?;
            let mut token = SignedData::parse(values[0].full)?;
            budget.certificates.charge(certificates.len())?;
            budget.certificate_bytes(certificates)?;
            token.certs.extend(certificates.iter().cloned());
            ensure!(
                token.content_type == cms::TST_INFO && token.signers.len() == 1,
                "invalid RFC3161 token"
            );
            let parsed =
                crate::parse::TstInfo::parse(token.content.full).map_err(|error| error.inner)?;
            ensure!(
                parsed.version_der == [2, 1, 1],
                "unsupported TSTInfo version"
            );
            // These fields need separate identity/extension rules before support.
            for field in &parsed.optional_fields {
                ensure!(field[0] != 0xa0, "TSTInfo tsa identity is unsupported");
                ensure!(field[0] != 0xa1, "TSTInfo extensions are unsupported");
            }
            let info = token.content.children()?;
            let imprint = der::fields(info[2].expect(0x30)?, 2)?;
            let hash = cms::algorithm(imprint[0])?;
            ensure!(
                options.allow_sha1 || hash != Hash::Sha1,
                "SHA-1 timestamp requires --allow-sha1"
            );
            let expected = imprint[1].expect(4)?.body;
            budget.hash_bytes.charge(signer.signature.len())?;
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
            let at = parsed.parsed_time.unix_seconds();
            let fractional_seconds: Option<String> =
                parsed.parsed_time.fractional_seconds().map(Into::into);
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
            budget.signer()?;
            budget.crypto.charge(1)?;
            budget.report(1)?;
            budget.hash_bytes.charge(token.content.full.len())?;
            budget.hash_bytes.charge(token.signers[0].full.len())?;
            let tsa = token.verify(token.signers[0], options.allow_sha1)?;
            let trust_report = if let Some(trust) = options.trust {
                Some(trust.verify(
                    trust::ChainRequest {
                        leaf: tsa.cert,
                        certificates: &token.certs,
                        eku: trust::TIME_STAMPING,
                        signing_time: Some(trust::SigningTime {
                            seconds: at,
                            fraction: fractional_seconds.as_deref(),
                        }),
                        now: options.now,
                        revocation: options.check_revocation,
                    },
                    budget,
                )?)
            } else {
                None
            };
            budget.certificate_bytes(core::slice::from_ref(tsa.cert))?;
            let certificate = CertificateReport::parse(tsa.cert)?;
            timestamp = Some(TimestampReport {
                fractional_seconds,
                kind: "rfc3161".into(),
                unverified_certificate_choices: token.unverified_certificate_choices,
                signing_time: at,
                certificate,
                trust: trust_report,
            });
        } else if oid.as_slice() == cms::COUNTERSIGN {
            ensure!(
                values.len() == 1 && timestamp.is_none(),
                "multiple timestamps are unsupported"
            );
            budget.cms_bytes.charge(values[0].full.len())?;
            budget.signer()?;
            budget.crypto.charge(1)?;
            budget.report(1)?;
            budget.hash_bytes.charge(signer.signature.len())?;
            budget.hash_bytes.charge(values[0].full.len())?;
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
                    trust::ChainRequest {
                        leaf: tsa.cert,
                        certificates,
                        eku: trust::TIME_STAMPING,
                        signing_time: Some(trust::SigningTime {
                            seconds: at,
                            fraction: fractional_seconds.as_deref(),
                        }),
                        now: options.now,
                        revocation: options.check_revocation,
                    },
                    budget,
                )?)
            } else {
                None
            };
            budget.certificate_bytes(core::slice::from_ref(tsa.cert))?;
            timestamp = Some(TimestampReport {
                fractional_seconds,
                kind: "pkcs9_countersignature".into(),
                unverified_certificate_choices: Vec::new(),
                signing_time: at,
                certificate: CertificateReport::parse(tsa.cert)?,
                trust: trust_report,
            });
        }
    }
    Ok(timestamp)
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
}
