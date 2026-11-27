//! RDP signs selected settings, not the whole text file. No client is launched.
use crate::{
    cms::{self, DetachedData},
    crypto::Hash,
    domain::*,
    verify::{VerifyOptions, budget::Budget, timestamp::verify_timestamp},
};
#[cfg(test)]
use alloc::vec;
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use anyhow::Result;
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
use crate::parse::rdp::{MAX_FILE, MAX_SETTINGS};
struct Rdp {
    signature: Vec<u8>,
    canonical: Vec<u8>,
    coverage: RdpCoverage,
}
impl Rdp {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let parsed = crate::parse::Rdp::parse(bytes).map_err(VerificationError::from)?;
        let settings = |values: &[crate::parse::RdpSetting]| {
            values
                .iter()
                .map(|setting| RdpSetting {
                    name: setting.name.clone(),
                    value: setting.value.clone(),
                    value_type: match setting.value_type {
                        crate::parse::RdpValueType::String => RdpValueType::String,
                        crate::parse::RdpValueType::Integer => RdpValueType::Integer,
                        crate::parse::RdpValueType::Binary => RdpValueType::Binary,
                    },
                })
                .collect()
        };
        Ok(Self {
            signature: parsed.signature().to_vec(),
            canonical: parsed.canonical_bytes().to_vec(),
            coverage: RdpCoverage {
                full_file_signed: false,
                signscope: parsed.signscope().to_vec(),
                signed_settings: settings(parsed.signed_settings()),
                unsigned_settings: settings(parsed.unsigned_settings()),
                canonical_sha256: hex(&Hash::Sha256.digest(parsed.canonical_bytes())),
            },
        })
    }
}
#[cfg(test)]
pub(crate) fn has_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|v| v.to_str())
        .is_some_and(|v| v.eq_ignore_ascii_case("rdp"))
}
pub(crate) fn looks_like(bytes: &[u8]) -> bool {
    ["signscope:s:", "signature:s:"].iter().any(|marker| {
        let le: Vec<_> = marker.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let be: Vec<_> = marker.encode_utf16().flat_map(u16::to_be_bytes).collect();
        [marker.as_bytes(), &le, &be]
            .iter()
            .any(|s| bytes.windows(s.len()).any(|w| w == *s))
    })
}
fn at<T>(result: Result<T>, code: ErrorCode, stage: Stage) -> Result<T> {
    result.map_err(|e| VerificationError::from_internal(e, code, stage).into())
}
pub(crate) fn verify(bytes: &[u8], options: &VerifyOptions<'_>) -> Result<VerificationBundle> {
    let budget = Budget::default();
    budget.container(bytes)?;
    verify_budget(bytes, options, &budget)
}
pub(crate) fn verify_budget(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
    budget: &Budget,
) -> Result<VerificationBundle> {
    let rdp = at(Rdp::parse(bytes), ErrorCode::InvalidRdp, Stage::Rdp)?;
    at(
        budget.cms(&rdp.signature),
        ErrorCode::MalformedCms,
        Stage::Cms,
    )?;
    let sd = at(
        DetachedData::parse(&rdp.signature),
        ErrorCode::MalformedCms,
        Stage::Cms,
    )?;
    let mut signatures = Vec::new();
    for si in &sd.signers {
        budget.report(sd.certs.len() + 1)?;
        budget.certificate_bytes(&sd.certs)?;
        for choice in &sd.unverified_certificate_choices {
            budget.decoded_bytes.charge(choice.der.len())?;
        }
        budget.signer()?;
        budget.hash_bytes.charge(si.full.len())?;
        budget.crypto.charge(1)?;
        budget.hash_bytes.charge(rdp.canonical.len())?;
        let signer = at(
            sd.verify(*si, &rdp.canonical, options.allow_sha1),
            ErrorCode::InvalidSignature,
            Stage::Cms,
        )?;
        if signer.unsigned.iter().any(|(id, _)| id == cms::NESTED) {
            return Err(VerificationError::new(
                ErrorCode::MalformedCms,
                Stage::Cms,
                "nested RDP signatures are unsupported",
            )
            .into());
        }
        let timestamp_verification = at(
            verify_timestamp(&sd.certs, &signer, options, budget),
            ErrorCode::InvalidTimestamp,
            Stage::Timestamp,
        )?;
        let timestamp = timestamp_verification.as_ref().map(|t| t.signing_time);
        let trust = if let Some(store) = options.trust {
            Some(at(
                verify_trust(store, signer.cert, &sd.certs, timestamp, options, budget),
                ErrorCode::CertificateChainInvalid,
                Stage::CertificateChain,
            )?)
        } else {
            None
        };
        let certificate = CertificateReport::parse(signer.cert)?;
        crate::verify::log_signer(budget, &certificate, timestamp, trust.as_ref());
        if let Some(timestamp) = &timestamp_verification {
            crate::verify::timestamp::check_fractional_validity(
                trust.as_ref(),
                timestamp.signing_time,
                timestamp.fractional_seconds.as_deref(),
            )?;
        }
        signatures.push(SignatureReport {
            unverified_certificate_choices: sd.unverified_certificate_choices.clone(),
            subject: certificate.subject.display.clone(),
            digest_algorithm: format!("{:?}", signer.hash),
            certificate_sha256: certificate.sha256.clone(),
            timestamp,
            chain_trusted: options.trust.is_some(),
            revocation_checked: options.trust.is_some() && options.check_revocation,
            nested_depth: 0,
            certificate,
            embedded_certificates: sd
                .certs
                .iter()
                .map(CertificateReport::parse)
                .collect::<Result<_>>()?,
            image_digest: None,
            package_digest: None,
            script_digest: None,
            extended_digest: None,
            page_hashes: None,
            trust,
            timestamp_verification,
        });
    }
    budget.hash_bytes.charge(bytes.len())?;
    Ok(VerificationBundle {
        crl_retrieval: None,
        format: "rdp_signed_settings".into(),
        validation_time: options.now,
        file_sha256: hex(&Hash::Sha256.digest(bytes)),
        signatures,
        rdp: Some(rdp.coverage),
        appx: None,
    })
}
fn verify_trust(
    store: &crate::TrustStore,
    leaf: &x509_cert::Certificate,
    certificates: &[x509_cert::Certificate],
    signing_time: Option<u64>,
    options: &VerifyOptions<'_>,
    budget: &Budget,
) -> Result<TrustReport> {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    const USAGES: &[&[u8]] = &[
        crate::trust::CODE_SIGNING,
        &[43, 6, 1, 5, 5, 7, 3, 1],
        &[43, 6, 1, 4, 1, 130, 55, 54, 1, 2],
    ];
    // PATH-013 for the signer before its EKU is read, as `verify` makes it
    // for every other format. Without a configured root it passes, and a
    // malformed extKeyUsage then fails reading the EKU below.
    store.check_signer(leaf, budget)?;
    let usage = leaf
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(crate::compat_error)?;
    let mut failures = Vec::new();
    for eku in USAGES {
        if usage
            .as_ref()
            .is_some_and(|(_, u)| u.0.iter().any(|v| v.as_bytes() == *eku))
        {
            match store.verify(
                crate::trust::ChainRequest {
                    leaf,
                    certificates,
                    eku,
                    signing_time,
                    now: options.now,
                    revocation: options.check_revocation,
                },
                budget,
            ) {
                Ok(report) => return Ok(report),
                Err(e) => {
                    if e.chain().any(|cause| {
                        cause
                            .downcast_ref::<VerificationError>()
                            .is_some_and(|error| error.code == ErrorCode::ResourceLimitExceeded)
                    }) {
                        return Err(e);
                    }
                    failures.push(e);
                }
            }
        }
    }
    Err(choose_usage_failure(failures).unwrap_or_else(|| {
        VerificationError::new(
            ErrorCode::InvalidEku,
            Stage::Certificate,
            "RDP signer requires codeSigning, serverAuth, or Remote Desktop Authentication EKU",
        )
        .detail("certificate", CertificateReport::parse(leaf).ok())
        .into()
    }))
}

/// The failure reported when no usage verifies, as for candidate paths: a
/// revocation is definite and is the result (the first, if several), naming
/// every certificate any other usage reports without a CRL
/// (`certificates_without_crl`), with only expired ones
/// (`certificates_with_expired_crl`) or with only ones a source's CRL could
/// replace (`certificates_with_replaceable_crl`), once each, so that
/// `--fetch-crls` can still complete that usage. Otherwise a usage that
/// only lacks CRLs a source could supply is reported ahead of another
/// usage's failure; on a tie, the first.
fn choose_usage_failure(failures: Vec<anyhow::Error>) -> Option<anyhow::Error> {
    // A failure's code is the first verification error in its chain, as
    // `VerificationError::from_internal` reports it.
    let revoked_at = failures.iter().position(|e| {
        e.chain()
            .find_map(|cause| cause.downcast_ref::<VerificationError>())
            .is_some_and(|error| error.code == ErrorCode::CertificateRevoked)
    });
    let Some(position) = revoked_at else {
        let mut chosen: Option<anyhow::Error> = None;
        for e in failures {
            if chosen
                .as_ref()
                .is_none_or(|kept| completable_by_crl(&e) > completable_by_crl(kept))
            {
                chosen = Some(e);
            }
        }
        return chosen;
    };
    let mut gaps: [Vec<serde_json::Value>; KEYS.len()] = Default::default();
    for e in &failures {
        for error in e
            .chain()
            .filter_map(|cause| cause.downcast_ref::<VerificationError>())
        {
            for (key, into) in KEYS.iter().zip(gaps.iter_mut()) {
                let listed = error.details.get(*key).and_then(|v| v.as_array());
                for report in listed.into_iter().flatten() {
                    // Once each, by SHA-256; an entry without one is kept.
                    let sha256 = report.get("sha256").and_then(|v| v.as_str());
                    if sha256.is_none_or(|sha256| {
                        !into
                            .iter()
                            .any(|kept| kept.get("sha256").and_then(|v| v.as_str()) == Some(sha256))
                    }) {
                        into.push(report.clone());
                    }
                }
            }
        }
    }
    let mut revoked = failures.into_iter().nth(position)?;
    let add = |error: &mut VerificationError, gaps: [Vec<serde_json::Value>; KEYS.len()]| {
        for (key, list) in KEYS.iter().zip(gaps) {
            if !list.is_empty() {
                error
                    .details
                    .insert((*key).into(), serde_json::Value::Array(list));
            }
        }
    };
    // The revocation takes the names in place, keeping any context around
    // it, so the reported causes are the same with or without them.
    if let Some(error) = revoked
        .downcast_mut::<VerificationError>()
        .filter(|error| error.code == ErrorCode::CertificateRevoked)
    {
        add(error, gaps);
        return Some(revoked);
    }
    // Otherwise (the revocation is the source of another error type, not an
    // anyhow context), it is reported at the top with the names. The outer
    // error's messages stay in the chain as contexts around it, so
    // `from_internal` reports them in its causes. Only the messages survive:
    // nothing downcasts to the outer type, and the revocation has no sources.
    let messages: Vec<String> = revoked.chain().map(ToString::to_string).collect();
    let depth = revoked
        .chain()
        .position(|cause| cause.downcast_ref::<VerificationError>().is_some())?;
    let mut error = revoked
        .chain()
        .nth(depth)?
        .downcast_ref::<VerificationError>()?
        .clone();
    add(&mut error, gaps);
    let mut merged = anyhow::Error::new(error);
    for message in messages[..depth].iter().rev() {
        merged = merged.context(message.clone());
    }
    Some(merged)
}

/// How far CRLs from a source could complete a failed usage that is not a
/// revocation (a revocation is chosen before any ranking): 2 when the
/// failure is an unknown status or an expired or replaceable CRL that names
/// the certificates to ask about, and 0 otherwise. An empty list names nothing:
/// it is what the verifier returns when no path passes the path checks.
fn completable_by_crl(e: &anyhow::Error) -> u8 {
    e.chain()
        .filter_map(|cause| cause.downcast_ref::<VerificationError>())
        .map(|error| {
            let named = KEYS.iter().any(|key| {
                error
                    .details
                    .get(*key)
                    .and_then(|v| v.as_array())
                    .is_some_and(|list| !list.is_empty())
            });
            if named && error.code != ErrorCode::CertificateRevoked {
                2
            } else {
                0
            }
        })
        .max()
        .unwrap_or(0)
}

/// The details that name certificates a CRL source could be asked about.
/// `choose_usage_failure` keeps one merged list per key, in this order: its
/// `gaps` array must have as many entries as there are keys.
const KEYS: [&str; 3] = [
    "certificates_without_crl",
    "certificates_with_expired_crl",
    crate::trust::WITH_REPLACEABLE_CRL,
];

#[cfg(test)]
mod tests {
    use super::*;
    use ::der::Encode;
    #[test]
    fn a_revoked_usage_is_reported_and_names_another_usages_gaps() {
        let report = |sha: &str| serde_json::json!({"sha256": sha});
        let error = |code| VerificationError::new(code, Stage::Revocation, "x");
        let revoked = |gaps: Vec<serde_json::Value>| {
            let e = error(ErrorCode::CertificateRevoked);
            anyhow::Error::from(if gaps.is_empty() {
                e
            } else {
                e.detail("certificates_without_crl", gaps)
            })
        };
        let unknown = |gaps: Vec<serde_json::Value>| {
            anyhow::Error::from(
                error(ErrorCode::RevocationUnknown).detail("certificates_without_crl", gaps),
            )
        };
        let expired = || {
            anyhow::Error::from(
                error(ErrorCode::CrlExpired)
                    .detail("certificates_with_expired_crl", vec![report("e")]),
            )
        };
        let code = |e: &anyhow::Error| e.downcast_ref::<VerificationError>().unwrap().code;
        let details = |e: &anyhow::Error| {
            e.downcast_ref::<VerificationError>()
                .unwrap()
                .details
                .clone()
        };
        // Either order: the revocation is the result, naming the gaps of the
        // usage that only lacks a CRL, so a source can still complete it.
        for failures in [
            vec![revoked(vec![]), unknown(vec![report("a")])],
            vec![unknown(vec![report("a")]), revoked(vec![])],
        ] {
            let chosen = choose_usage_failure(failures).unwrap();
            assert_eq!(code(&chosen), ErrorCode::CertificateRevoked);
            assert_eq!(
                details(&chosen)["certificates_without_crl"],
                serde_json::json!([report("a")])
            );
        }
        // Two revocations: the first is reported, and a later one's gaps are
        // kept; every certificate is named once.
        let chosen = choose_usage_failure(vec![
            revoked(vec![report("a")]),
            revoked(vec![report("b"), report("a")]),
            unknown(vec![report("b")]),
        ])
        .unwrap();
        assert_eq!(
            details(&chosen)["certificates_without_crl"],
            serde_json::json!([report("a"), report("b")])
        );
        // A certificate whose only CRL expired is named too, as for
        // candidate paths: a source can refresh it.
        let chosen = choose_usage_failure(vec![revoked(vec![]), expired(), expired()]).unwrap();
        assert_eq!(code(&chosen), ErrorCode::CertificateRevoked);
        assert!(!details(&chosen).contains_key("certificates_without_crl"));
        assert_eq!(
            details(&chosen)["certificates_with_expired_crl"],
            serde_json::json!([report("e")])
        );
        // A certificate whose only CRL a source's CRL could replace is named
        // too, once each, beside the other lists.
        let replaceable = || {
            anyhow::Error::from(
                error(ErrorCode::CrlNotYetValid)
                    .detail(crate::trust::WITH_REPLACEABLE_CRL, vec![report("u")]),
            )
        };
        let chosen = choose_usage_failure(vec![
            revoked(vec![]),
            replaceable(),
            replaceable(),
            unknown(vec![report("a")]),
        ])
        .unwrap();
        assert_eq!(code(&chosen), ErrorCode::CertificateRevoked);
        assert_eq!(
            details(&chosen)[crate::trust::WITH_REPLACEABLE_CRL],
            serde_json::json!([report("u")])
        );
        assert_eq!(
            details(&chosen)["certificates_without_crl"],
            serde_json::json!([report("a")])
        );
        assert_eq!(completable_by_crl(&replaceable()), 2);
        // A revocation under added context takes the names and keeps it.
        let wrapped = revoked(vec![]).context("usage");
        let chosen = choose_usage_failure(vec![wrapped, unknown(vec![report("a")])]).unwrap();
        assert_eq!(chosen.to_string(), "usage");
        assert_eq!(code(&chosen), ErrorCode::CertificateRevoked);
        assert_eq!(
            details(&chosen)["certificates_without_crl"],
            serde_json::json!([report("a")])
        );
        // Entries without a SHA-256 are all kept.
        let bare = || serde_json::json!({"subject": "x"});
        let chosen =
            choose_usage_failure(vec![revoked(vec![]), unknown(vec![bare(), bare()])]).unwrap();
        assert_eq!(
            details(&chosen)["certificates_without_crl"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        // Without a revocation, the completable usage is preferred.
        let other = || anyhow::Error::from(error(ErrorCode::InvalidEku));
        let chosen = choose_usage_failure(vec![other(), unknown(vec![report("a")])]).unwrap();
        assert_eq!(code(&chosen), ErrorCode::RevocationUnknown);
        let chosen = choose_usage_failure(vec![other(), revoked(vec![])]).unwrap();
        assert_eq!(code(&chosen), ErrorCode::CertificateRevoked);
        assert!(choose_usage_failure(Vec::new()).is_none());
    }
    #[test]
    fn a_revocation_that_is_another_errors_source_keeps_the_outer_causes() {
        #[derive(Debug)]
        struct Outer(VerificationError);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("outer failure")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let revoked = VerificationError::new(ErrorCode::CertificateRevoked, Stage::Revocation, "x");
        let unknown = VerificationError::new(ErrorCode::RevocationUnknown, Stage::Revocation, "y")
            .detail(
                "certificates_without_crl",
                vec![serde_json::json!({"sha256": "a"})],
            );
        let chosen = choose_usage_failure(vec![
            anyhow::Error::new(Outer(revoked)).context("usage"),
            anyhow::Error::from(unknown),
        ])
        .unwrap();
        // As `at` reports it: `from_internal` rebuilds the causes from the chain.
        let error = VerificationError::from_internal(
            chosen,
            ErrorCode::CertificateChainInvalid,
            Stage::CertificateChain,
        );
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert!(error.details.contains_key("certificates_without_crl"));
        assert_eq!(error.causes, vec!["usage", "outer failure", "x"]);
    }
    #[test]
    fn only_a_named_missing_crl_ranks_a_usage_failure_as_completable() {
        let named = serde_json::json!([{"sha256": "a"}]);
        let error = |code| VerificationError::new(code, Stage::Revocation, "x");
        let rank = |e: VerificationError| completable_by_crl(&anyhow::Error::from(e));
        // Unknown or expired, naming certificates a source could cover.
        assert_eq!(
            rank(error(ErrorCode::RevocationUnknown).detail("certificates_without_crl", &named)),
            2
        );
        assert_eq!(
            rank(error(ErrorCode::CrlExpired).detail("certificates_with_expired_crl", &named)),
            2
        );
        // A revocation is chosen before any ranking: it ranks nothing.
        assert_eq!(
            rank(error(ErrorCode::CertificateRevoked).detail("certificates_without_crl", &named)),
            0
        );
        // An empty list names nothing to ask: no path passes the path checks.
        let empty = serde_json::json!([]);
        assert_eq!(
            rank(error(ErrorCode::RevocationUnknown).detail("certificates_without_crl", &empty)),
            0
        );
        assert_eq!(rank(error(ErrorCode::RevocationUnknown)), 0);
        assert_eq!(rank(error(ErrorCode::CertificateRevoked)), 0);
        // Found through added context too.
        let wrapped = anyhow::Error::from(
            error(ErrorCode::RevocationUnknown).detail("certificates_without_crl", &named),
        )
        .context("usage");
        assert_eq!(completable_by_crl(&wrapped), 2);
    }
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn rdp_eku_retry_propagates_later_budget_exhaustion() {
        let bytes = fixture("good-rdp-multiple-ekus.rdp");
        let store = crate::TrustStore::default();
        let options = VerifyOptions::trusted_with_revocation(
            &store,
            1800000000,
            crate::verify::RevocationPolicy::Disabled,
        );
        let ordinary = verify_budget(&bytes, &options, &Budget::default()).unwrap_err();
        let ordinary =
            VerificationError::from_internal(ordinary, ErrorCode::InternalError, Stage::Cms);
        assert_eq!(ordinary.code, ErrorCode::UntrustedRoot);

        // Leave exactly one webpki search reservation. The first accepted EKU
        // fails for lack of anchors; the second must propagate budget exhaustion.
        let budget = Budget::default();
        budget.path_work.charge(12_600_000).unwrap();
        let error = verify_budget(&bytes, &options, &budget).unwrap_err();
        let error = VerificationError::from_internal(error, ErrorCode::InternalError, Stage::Cms);
        assert_eq!(error.code, ErrorCode::ResourceLimitExceeded);
        assert_eq!(error.stage, Stage::Cms);
        let json = serde_json::to_value(error).unwrap();
        assert_eq!(json["code"], "resource_limit_exceeded");
        assert_eq!(
            json["details"],
            serde_json::json!({
                "resource": "path_work", "limit": 12_800_000,
                "used": 12_800_000, "requested": 200_000,
            })
        );
    }

    #[test]
    fn signed_and_unsigned_mutations_have_distinct_cryptographic_effects() {
        for (good, bad, unsigned) in [
            (
                "good.rdp",
                "bad-rdp-setting.rdp",
                "good-rdp-unsigned-change.rdp",
            ),
            (
                "rdp-independent-nfedera.rdp",
                "bad-rdp-independent-setting.rdp",
                "good-rdp-independent-unsigned-change.rdp",
            ),
        ] {
            let good = Rdp::parse(&fixture(good)).unwrap();
            let bad = Rdp::parse(&fixture(bad)).unwrap();
            let unsigned = Rdp::parse(&fixture(unsigned)).unwrap();
            assert_eq!(good.signature, bad.signature);
            assert_eq!(good.signature, unsigned.signature);
            assert_ne!(good.canonical, bad.canonical);
            assert_eq!(good.canonical, unsigned.canonical);
            let sd = DetachedData::parse(&bad.signature).unwrap();
            sd.verify(sd.signers[0], &good.canonical, false).unwrap();
            assert!(sd.verify(sd.signers[0], &bad.canonical, false).is_err());
            assert!(!good.coverage.full_file_signed);
            assert_eq!(unsigned.coverage.unsigned_settings[0].value, "2048");
        }
        let good = Rdp::parse(&fixture("good-rdp-attributes.rdp")).unwrap();
        let bad = Rdp::parse(&fixture("bad-rdp-attributes-setting.rdp")).unwrap();
        assert_eq!(good.signature, bad.signature);
        let sd = DetachedData::parse(&bad.signature).unwrap();
        sd.verify(sd.signers[0], &good.canonical, false).unwrap();
        let error = sd
            .verify(sd.signers[0], &bad.canonical, false)
            .err()
            .unwrap();
        assert_eq!(
            error.downcast_ref::<VerificationError>().unwrap().code,
            ErrorCode::ContentDigestMismatch
        );
    }
    #[test]
    fn direct_signatures_do_not_relax_authenticode_or_countersignature_policy() {
        let pe_bytes = fixture("bad-rdp-pe-no-attributes.exe");
        let pe = crate::pe::Pe::parse(&pe_bytes).unwrap();
        let cms = pe.certificates().unwrap()[0];
        let sd = cms::SignedData::parse(cms).unwrap();
        let (hash, expected) = sd.image_digest().unwrap();
        assert_eq!(pe.digest(hash).unwrap(), expected);
        let si = sd.signers[0].children().unwrap();
        assert_eq!(si.len(), 5);
        let signer = sd
            .certs
            .iter()
            .find(|cert| {
                cert.tbs_certificate.serial_number.to_der().unwrap()
                    == si[1].children().unwrap()[1].full
            })
            .unwrap();
        crate::crypto::verify_spki(
            &signer
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            hash,
            si[3].children().unwrap()[0].body,
            sd.content.body,
            si[4].body,
        )
        .unwrap();
        assert!(sd.verify(sd.signers[0], false).is_err());
        let rdp = Rdp::parse(&fixture("good.rdp")).unwrap();
        assert!(cms::SignedData::parse(&rdp.signature).is_err());
        let detached = DetachedData::parse(&rdp.signature).unwrap();
        assert!(
            cms::verify_countersigner(&detached.certs, detached.signers[0], &rdp.canonical, false)
                .is_err()
        );
    }
    #[test]
    fn truncation_and_parser_budgets_fail_closed() {
        for (name, newline_bytes) in [
            ("good.rdp", 2),
            ("good-rdp-utf16le.rdp", 4),
            ("good-rdp-utf16be.rdp", 4),
        ] {
            let bytes = fixture(name);
            for end in 0..bytes.len() {
                if end == bytes.len() - newline_bytes {
                    assert!(Rdp::parse(&bytes[..end]).is_ok());
                } else {
                    assert!(
                        Rdp::parse(&bytes[..end]).is_err(),
                        "accepted {name} prefix {end}"
                    );
                }
            }
        }
        assert!(
            Rdp::parse(&vec![b'a'; MAX_FILE + 1])
                .err()
                .unwrap()
                .to_string()
                .contains("limit")
        );
        let many: String = (0..MAX_SETTINGS + 1)
            .map(|i| format!("setting{i}:s:x\n"))
            .collect();
        assert!(
            Rdp::parse(many.as_bytes())
                .err()
                .unwrap()
                .to_string()
                .contains("too many")
        );
        let good = String::from_utf8(fixture("good.rdp")).unwrap();
        for prefix in [
            "x:b:0\n",
            "x:b:zz\n",
            "x:z:a\n",
            "x:i:2147483648\n",
            "x:s:a\0b\n",
            "x:s:\u{7}\n",
        ] {
            assert!(Rdp::parse(format!("{prefix}{good}").as_bytes()).is_err());
        }
        let mut utf16 = fixture("good-rdp-utf16le.rdp");
        utf16[2..4].copy_from_slice(&0xd800u16.to_le_bytes());
        assert!(Rdp::parse(&utf16).is_err());
        let text = "full address:s:example.invalid\r\n";
        let no_bom: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(Rdp::parse(&no_bom).is_err());
        let with_binary = format!("password 51:b:0011aaff\r\n{good}");
        let parsed = Rdp::parse(with_binary.as_bytes()).unwrap();
        assert!(matches!(
            parsed.coverage.unsigned_settings[0].value_type,
            RdpValueType::Binary
        ));
        assert!(has_extension(Path::new("connection.RDP")));
        assert!(!has_extension(Path::new("connection")));
        assert!(!has_extension(Path::new("connection.exe")));
    }
    /// The only fixture with a revoked usage beside another usage's failure
    /// reports the revocation as that usage's own error, so its causes, as
    /// `at` reports them, are its message alone. A change that makes the
    /// revocation another error type's source adds the outer messages here,
    /// and needs an end-to-end case for that branch of `choose_usage_failure`.
    #[test]
    fn a_revoked_usage_from_a_fixture_is_not_another_errors_source() {
        let mut trust = crate::TrustStore::default();
        trust.add_roots(&fixture("root.der")).unwrap();
        trust.add_crl(&fixture("good.crl")).unwrap();
        trust
            .add_crl(&fixture("rdp-eku-retry-ca-revoked.crl"))
            .unwrap();
        let options = VerifyOptions {
            trust: Some(&trust),
            check_revocation: true,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        let error = verify(&fixture("good-rdp-eku-retry-ca.rdp"), &options).unwrap_err();
        let error = error.downcast_ref::<VerificationError>().unwrap();
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert_eq!(error.causes, vec![error.message.clone()]);
    }
    #[test]
    fn trust_selection_and_serialized_coverage_are_explicit() {
        let mut trust = crate::TrustStore::default();
        trust.add_roots(&fixture("root.der")).unwrap();
        trust.add_crl(&fixture("good.crl")).unwrap();
        let options = VerifyOptions {
            trust: Some(&trust),
            check_revocation: true,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        for (name, usage) in [
            ("good.rdp", "1.3.6.1.5.5.7.3.3"),
            ("good-rdp-server-auth.rdp", "1.3.6.1.5.5.7.3.1"),
            ("good-rdp-remote-auth.rdp", "1.3.6.1.4.1.311.54.1.2"),
        ] {
            let bytes = fixture(name);
            for report in [
                crate::verify(&bytes, &options).unwrap(),
                crate::verify_rdp(&bytes, &options).unwrap(),
            ] {
                let rdp = report.rdp.as_ref().unwrap();
                assert!(!rdp.full_file_signed);
                assert_eq!(
                    rdp.signscope,
                    ["Full Address", "Server Port", "RedirectClipboard"]
                );
                assert_eq!(rdp.signed_settings[0].name, "full address");
                assert_eq!(rdp.unsigned_settings[0].name, "desktopwidth");
                let json = serde_json::to_value(report).unwrap();
                assert_eq!(json["rdp"]["signed_settings"][1]["value_type"], "i");
                assert_eq!(json["signatures"][0]["trust"]["required_eku"]["oid"], usage);
                let roundtrip: VerificationBundle = serde_json::from_value(json.clone()).unwrap();
                assert_eq!(serde_json::to_value(roundtrip).unwrap(), json);
            }
        }
        let err = crate::verify_rdp(&fixture("unsigned.rdp"), &options).unwrap_err();
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], "unsigned");
        assert_eq!(json["stage"], "rdp");
    }
}
