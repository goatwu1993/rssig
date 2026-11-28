//! RDP signs selected settings, not the whole text file. No client is launched.
use crate::{
    cms::{self, DetachedData},
    crypto::Hash,
    domain::*,
    verify::{VerifyOptions, budget::Budget, timestamp::verify_timestamp},
};
use alloc::{
    format,
    string::{String, ToString},
    vec,
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
                verify_trust(
                    store,
                    signer.cert,
                    &sd.certs,
                    timestamp_verification
                        .as_ref()
                        .map(crate::trust::SigningTime::of),
                    options,
                    budget,
                ),
                ErrorCode::CertificateChainInvalid,
                Stage::CertificateChain,
            )?)
        } else {
            None
        };
        let certificate = CertificateReport::parse(signer.cert)?;
        crate::verify::log_signer(budget, &certificate, timestamp, trust.as_ref());
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
/// The usages an RDP signer is tried under, in order: codeSigning,
/// serverAuth and Remote Desktop Authentication.
const USAGES: &[&[u8]] = &[
    crate::trust::CODE_SIGNING,
    &[43, 6, 1, 5, 5, 7, 3, 1],
    &[43, 6, 1, 4, 1, 130, 55, 54, 1, 2],
];
fn verify_trust(
    store: &crate::TrustStore,
    leaf: &x509_cert::Certificate,
    certificates: &[x509_cert::Certificate],
    signing_time: Option<crate::trust::SigningTime<'_>>,
    options: &VerifyOptions<'_>,
    budget: &Budget,
) -> Result<TrustReport> {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    // Without a configured root every format reports `untrusted_root` before
    // judging the signer (PATH-001, PATH-013, PATH-014): ask `verify` once, as the
    // other formats do, before the EKU is read (RDP-T005).
    if store.root_count() == 0 {
        return store.verify(
            crate::trust::ChainRequest {
                leaf,
                certificates,
                eku: USAGES[0],
                signing_time,
                now: options.now,
                revocation: options.check_revocation,
            },
            budget,
        );
    }
    // PATH-013 and PATH-014 for the signer before its EKU is read, as
    // `verify` makes them for every other format.
    store.check_signer(leaf, budget)?;
    let usage = leaf
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(crate::compat_error)?;
    // LIMIT-T007: each usage reserves a whole webpki search, so a failure no
    // other usage can change ends the search. Every usage after it would fail
    // the same way, naming only another `required_eku`, so the failure
    // `choose_usage_failure` ranks from the usages tried (the first, with
    // its own CRL gaps) is the one it would rank from all of them (CRL-027).
    // When in doubt the search goes on: stopping can only reject.
    // Whether a certificate can steer the path is asked once, and only after
    // a failure that the signer alone does not explain.
    let mut steers = None;
    let mut failures = Vec::new();
    let accepted: Vec<&'static [u8]> = USAGES
        .iter()
        .copied()
        .filter(|eku| {
            usage
                .as_ref()
                .is_some_and(|(_, u)| u.0.iter().any(|v| v.as_bytes() == *eku))
        })
        .collect();
    for (tried, eku) in accepted.iter().enumerate() {
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
                // The last usage asks nothing: no search is left to skip.
                let settled = tried + 1 == accepted.len()
                    || (signer_alone(&e)
                        && crate::trust::fails_before_any_path(leaf, signing_time))
                    || !match steers {
                        Some(steers) => steers,
                        None => *steers.insert(usage_steers_the_path(leaf, certificates, budget)?),
                    };
                failures.push(e);
                if settled {
                    break;
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

/// Whether the usage tried can change the paths webpki builds, and so the
/// result of `TrustStore::verify` (LIMIT-T007). webpki 0.103.16 judges the
/// requested usage only in a certificate on a candidate path that carries an
/// extKeyUsage (`KeyUsage::required_if_present`, in
/// `check_issuer_independent_properties`), and a configured anchor carries
/// none: webpki keeps only its name, key and name constraints
/// (`TrustAnchor`). The signer's own list holds every usage tried, and has
/// decoded as a SEQUENCE OF OBJECT IDENTIFIER, so webpki finds each of them
/// in it. That leaves the embedded certificates other than the signer that
/// can be on a path: webpki takes an intermediate only when its subject is
/// the issuer of the path's head, so one is a candidate when its subject is
/// the signer's issuer or another candidate's. Names are compared
/// re-encoded, the same bytes webpki compares: `TrustStore::verify` hands it
/// the re-encoded signer and certificates (`to_der`), which this rests on.
/// A timestamp authority's certificate beside them is one only if its subject
/// is on that issuer chain, which it usually is not. While no
/// candidate carries an extKeyUsage, every usage builds the same paths with
/// the same results, and its failure differs only in the `required_eku` it
/// names. Any such extension, however malformed, counts as steering.
fn usage_steers_the_path(
    leaf: &x509_cert::Certificate,
    certificates: &[x509_cert::Certificate],
    budget: &Budget,
) -> Result<bool> {
    use ::der::{Encode, oid::AssociatedOid};
    use alloc::collections::{BTreeMap, BTreeSet};
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    // Names are compared re-encoded, as webpki sees them. Each
    // certificate is encoded and looked up once, so the work is linear in
    // the certificates, and the encoded names are charged as decoded bytes.
    // A name that does not re-encode counts as steering.
    let mut by_subject: BTreeMap<Vec<u8>, Vec<&x509_cert::Certificate>> = BTreeMap::new();
    for certificate in certificates
        .iter()
        .filter(|certificate| *certificate != leaf)
    {
        let Ok(subject) = certificate.tbs_certificate.subject.to_der() else {
            return Ok(true);
        };
        budget.decoded_bytes.charge(subject.len())?;
        by_subject.entry(subject).or_default().push(certificate);
    }
    let Ok(issuer) = leaf.tbs_certificate.issuer.to_der() else {
        return Ok(true);
    };
    budget.decoded_bytes.charge(issuer.len())?;
    let mut seen = BTreeSet::new();
    let mut pending = vec![issuer];
    while let Some(name) = pending.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        for certificate in by_subject.get(&name).into_iter().flatten() {
            if certificate
                .tbs_certificate
                .extensions
                .iter()
                .flatten()
                .any(|extension| extension.extn_id == ExtendedKeyUsage::OID)
            {
                return Ok(true);
            }
            let Ok(issuer) = certificate.tbs_certificate.issuer.to_der() else {
                return Ok(true);
            };
            budget.decoded_bytes.charge(issuer.len())?;
            pending.push(issuer);
        }
    }
    Ok(false)
}

/// Whether a usage's failure is one of the signer alone that
/// `fails_before_any_path` describes: the signer's KeyUsage
/// (`invalid_key_usage` at `certificate`) or its lifetime signing time
/// (`certificate_not_yet_valid` with `lifetime_signing`). Both must agree
/// before the search stops, so a usage-dependent rejection placed ahead of
/// those checks keeps it going.
fn signer_alone(e: &anyhow::Error) -> bool {
    e.chain()
        .find_map(|cause| cause.downcast_ref::<VerificationError>())
        .is_some_and(|error| match error.code {
            ErrorCode::InvalidKeyUsage => error.stage == Stage::Certificate,
            ErrorCode::CertificateNotYetValid => {
                error.details.get("lifetime_signing") == Some(&serde_json::Value::Bool(true))
            }
            _ => false,
        })
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
    // A failure's code is the first verification error that is an entry of
    // its chain. `VerificationError::from_internal` also takes a parser error
    // that is an entry; no usage failure carries one yet (CRL-T061).
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
    // `from_internal` reports them in its causes, ahead of any causes the
    // revocation already carries. Only the messages survive:
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
        merged = merged.context(String::clone(message));
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
        // As `at` reports it: `from_internal` takes the context messages above the
        // typed error, then its message (it carries no causes yet).
        let error = VerificationError::from_internal(
            chosen,
            ErrorCode::CertificateChainInvalid,
            Stage::CertificateChain,
        );
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert!(error.details.contains_key("certificates_without_crl"));
        assert_eq!(error.causes, vec!["usage", "outer failure", "x"]);
        // As the public `verify_rdp` boundary converts `at`'s result again:
        // the outer messages survive it (CLI-T004).
        let error = VerificationError::from_internal(
            anyhow::Error::new(error),
            ErrorCode::InvalidCertificate,
            Stage::Certificate,
        );
        assert_eq!(error.code, ErrorCode::CertificateRevoked);
        assert_eq!(error.causes, vec!["usage", "outer failure", "x"]);
        // A revocation an earlier conversion gave causes keeps them behind
        // the outer messages through the rebuild and both conversions.
        let mut converted =
            VerificationError::new(ErrorCode::CertificateRevoked, Stage::Revocation, "x");
        converted.causes = vec!["inner".into(), "x".into()];
        let chosen = choose_usage_failure(vec![
            anyhow::Error::new(Outer(converted)).context("usage"),
            anyhow::Error::from(VerificationError::new(
                ErrorCode::RevocationUnknown,
                Stage::Revocation,
                "y",
            )),
        ])
        .unwrap();
        let once = VerificationError::from_internal(
            chosen,
            ErrorCode::CertificateChainInvalid,
            Stage::CertificateChain,
        );
        let error = VerificationError::from_internal(
            anyhow::Error::new(once),
            ErrorCode::InvalidCertificate,
            Stage::Certificate,
        );
        assert_eq!(error.causes, vec!["usage", "outer failure", "inner", "x"]);
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
    fn disabled_revocation(store: &crate::TrustStore) -> VerifyOptions<'_> {
        VerifyOptions::trusted_with_revocation(
            store,
            1800000000,
            crate::verify::RevocationPolicy::Disabled,
        )
    }
    fn json(error: anyhow::Error) -> serde_json::Value {
        serde_json::to_value(VerificationError::from_internal(
            error,
            ErrorCode::InternalError,
            Stage::Cms,
        ))
        .unwrap()
    }
    /// Leave exactly one webpki search reservation in a fresh budget.
    fn one_search_left() -> Budget<'static> {
        let budget = Budget::default();
        budget
            .path_work
            .charge(budget.path_work.limit() - 200_000)
            .unwrap();
        budget
    }
    fn signers_certificates(name: &str) -> Vec<x509_cert::Certificate> {
        let rdp = Rdp::parse(&fixture(name)).unwrap();
        DetachedData::parse(&rdp.signature).unwrap().certs
    }
    /// LIMIT-T007: in `good-rdp-multiple-ekus.rdp` only the signer carries an
    /// extKeyUsage, so codeSigning and serverAuth build the same paths and
    /// the first usage's failure is final: one search is reserved, not one
    /// per usage, and the result is the one a second search would rank.
    #[test]
    fn rdp_stops_after_a_path_failure_no_other_eku_can_change() {
        let bytes = fixture("good-rdp-multiple-ekus.rdp");
        let certificates = signers_certificates("good-rdp-multiple-ekus.rdp");
        assert!(
            !usage_steers_the_path(&certificates[0], &certificates, &Budget::default()).unwrap()
        );
        // A configured root that issued nothing here: the path fails
        // `untrusted_root` whatever the usage.
        let mut store = crate::TrustStore::default();
        store.add_roots(&fixture("unrelated-root.der")).unwrap();
        let options = disabled_revocation(&store);
        let budget = Budget::default();
        let error = json(verify_budget(&bytes, &options, &budget).unwrap_err());
        assert_eq!(error["code"], "untrusted_root");
        assert_eq!(error["details"]["required_eku"], "1.3.6.1.5.5.7.3.3");
        assert_eq!(budget.path_work.used(), 200_000);
        // One reservation is enough, and the result is the same.
        let limited = json(verify_budget(&bytes, &options, &one_search_left()).unwrap_err());
        assert_eq!(limited, error);
    }
    /// What `usage_steers_the_path` rests on, on the fixtures that exercise
    /// it: while only the signer carries an extKeyUsage, `TrustStore::verify`
    /// gives every usage the same result apart from the `required_eku` it
    /// names, failing or verifying. A webpki update, or a path check that
    /// reads the usage, that breaks this fails here.
    #[test]
    fn without_a_steering_certificate_every_usage_has_the_same_result() {
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        let certificates = signers_certificates("good-rdp-multiple-ekus.rdp");
        let original = &certificates[0];
        assert_eq!(
            original.tbs_certificate.subject.to_string(),
            "CN=rssig test publisher"
        );
        // The signer rewritten to list all three usages: its own signature no
        // longer verifies, but every usage meets that the same way.
        let mut every = original.clone();
        let extension = every
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id == <ExtendedKeyUsage as ::der::oid::AssociatedOid>::OID)
            .unwrap();
        extension.extn_value = ::der::asn1::OctetString::new(
            ExtendedKeyUsage(
                USAGES
                    .iter()
                    .map(|eku| ::der::asn1::ObjectIdentifier::from_bytes(eku).unwrap())
                    .collect(),
            )
            .to_der()
            .unwrap(),
        )
        .unwrap();
        let without_usage = |mut value: serde_json::Value| {
            if let Some(object) = value.as_object_mut() {
                object.remove("required_eku");
                if let Some(details) = object.get_mut("details").and_then(|d| d.as_object_mut()) {
                    details.remove("required_eku");
                }
            }
            value
        };
        for (leaf, usages) in [(original, &USAGES[..2]), (&every, USAGES)] {
            assert!(!usage_steers_the_path(leaf, &certificates, &Budget::default()).unwrap());
            for (root, crls, revocation, outcome) in [
                ("unrelated-root.der", &[][..], false, "untrusted_root"),
                ("root.der", &[][..], false, "verified"),
                ("root.der", &["good.crl"][..], true, "verified"),
                ("root.der", &[][..], true, "revocation_unknown"),
                (
                    "root.der",
                    &["crl-root-expired-revoked.crl"][..],
                    true,
                    "crl_expired",
                ),
            ] {
                let mut store = crate::TrustStore::default();
                store.add_roots(&fixture(root)).unwrap();
                for crl in crls {
                    store.add_crl(&fixture(crl)).unwrap();
                }
                let results: Vec<_> = usages
                    .iter()
                    .map(|eku| {
                        let result = store.verify(
                            crate::trust::ChainRequest {
                                leaf,
                                certificates: &certificates,
                                eku,
                                signing_time: None,
                                now: 1_800_000_000,
                                revocation,
                            },
                            &Budget::default(),
                        );
                        without_usage(match result {
                            Ok(report) => serde_json::to_value(report).unwrap(),
                            Err(error) => json(error),
                        })
                    })
                    .collect();
                if leaf == original {
                    let code = results[0]["code"].as_str().unwrap_or("verified");
                    assert_eq!(code, outcome, "{root} {crls:?}");
                }
                for other in &results[1..] {
                    assert_eq!(&results[0], other, "{root} {crls:?}");
                }
            }
        }
    }
    /// Which embedded certificates can steer: a CA on the signer's path
    /// that carries an extKeyUsage does; a timestamp authority's certificate
    /// beside the signer's, which issues nothing on it, does not.
    #[test]
    fn only_a_certificate_that_can_be_on_the_path_steers_it() {
        let retry = signers_certificates("good-rdp-eku-retry-ca.rdp");
        let leaf = retry
            .iter()
            .find(|c| c.tbs_certificate.subject.to_string() == "CN=rssig test RDP publisher")
            .unwrap();
        assert!(usage_steers_the_path(leaf, &retry, &Budget::default()).unwrap());
        let without_ca: Vec<_> = retry
            .iter()
            .filter(|c| c.tbs_certificate.subject.to_string() != "CN=rssig test RDP server CA")
            .cloned()
            .collect();
        assert!(!usage_steers_the_path(leaf, &without_ca, &Budget::default()).unwrap());
        let timestamped = signers_certificates("time-rdp-expired-timestamped.rdp");
        let tsa = timestamped
            .iter()
            .find(|c| c.tbs_certificate.subject.to_string() == "CN=rssig test TSA")
            .unwrap();
        assert!(
            tsa.tbs_certificate
                .get::<x509_cert::ext::pkix::ExtendedKeyUsage>()
                .unwrap()
                .is_some()
        );
        let signer = timestamped
            .iter()
            .find(|c| c.tbs_certificate.subject.to_string() == "CN=SEC-09 rdp-expired-timestamped")
            .unwrap();
        assert!(!usage_steers_the_path(signer, &timestamped, &Budget::default()).unwrap());
        // The argument is webpki 0.103.16's: an update must re-audit it.
        let lock =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.lock")).unwrap();
        // Exactly one webpki is resolved, and it is that version.
        let lines: Vec<_> = lock.lines().map(str::trim).collect();
        let versions: Vec<_> = lines
            .windows(2)
            .filter(|w| w[0] == "name = \"rustls-webpki\"")
            .map(|w| w[1])
            .collect();
        assert_eq!(versions, ["version = \"0.103.16\""]);
        crate::trust::path_checks_hold_no_usage();
        // webpki keeps no extension of a configured anchor, so a root's
        // extKeyUsage cannot steer: this stops compiling if `TrustAnchor`
        // gains a field.
        let rustls_pki_types::TrustAnchor {
            subject: _,
            subject_public_key_info: _,
            name_constraints: _,
        } = webpki::anchor_from_trusted_cert(&rustls_pki_types::CertificateDer::from(fixture(
            "root.der",
        )))
        .unwrap();
    }
    /// Only the signer's own KeyUsage and lifetime failures count as the
    /// signer alone; an intermediate's KeyUsage, or a validity failure that is
    /// not lifetime signing's, does not.
    #[test]
    fn only_the_signers_own_failures_are_the_signer_alone() {
        let error = |code, stage| VerificationError::new(code, stage, "x");
        let alone = |e: VerificationError| signer_alone(&anyhow::Error::from(e).context("usage"));
        assert!(alone(error(ErrorCode::InvalidKeyUsage, Stage::Certificate)));
        assert!(!alone(error(
            ErrorCode::InvalidKeyUsage,
            Stage::CertificateChain
        )));
        assert!(alone(
            error(ErrorCode::CertificateNotYetValid, Stage::CertificateChain)
                .detail("lifetime_signing", true)
        ));
        assert!(!alone(error(
            ErrorCode::CertificateNotYetValid,
            Stage::CertificateChain
        )));
        assert!(!alone(error(
            ErrorCode::UntrustedRoot,
            Stage::CertificateChain
        )));
    }
    /// LIMIT-T007: a failure of the signer alone, found before any path is
    /// built, is the same for every usage, so it ends the search even where
    /// a CA's extKeyUsage steers the path: a KeyUsage without
    /// digitalSignature, and a lifetime signer issued after its signing time.
    #[test]
    fn rdp_stops_after_a_signer_failure_no_other_eku_can_change() {
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        let embedded = signers_certificates("good-rdp-eku-retry-ca.rdp");
        let publisher = |c: &x509_cert::Certificate| {
            c.tbs_certificate.subject.to_string() == "CN=rssig test RDP publisher"
        };
        let original = embedded.iter().find(|c| publisher(c)).unwrap();
        let with = |oid: &str, value: Vec<u8>| {
            let mut leaf = original.clone();
            let extensions = leaf.tbs_certificate.extensions.as_mut().unwrap();
            let extension = extensions
                .iter_mut()
                .find(|e| e.extn_id.to_string() == oid)
                .unwrap();
            extension.extn_value = ::der::asn1::OctetString::new(value).unwrap();
            leaf
        };
        let oid = |s: &str| s.parse::<::der::asn1::ObjectIdentifier>().unwrap();
        let lifetime = ExtendedKeyUsage(vec![
            oid("1.3.6.1.5.5.7.3.3"),
            oid("1.3.6.1.5.5.7.3.1"),
            oid("1.3.6.1.4.1.311.10.3.13"),
        ])
        .to_der()
        .unwrap();
        let not_before = original
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let mut store = crate::TrustStore::default();
        store.add_roots(&fixture("root.der")).unwrap();
        let options = disabled_revocation(&store);
        for (leaf, signed_at, code) in [
            // keyEncipherment only.
            (
                with("2.5.29.15", vec![3, 2, 5, 0x20]),
                None,
                "invalid_key_usage",
            ),
            (
                with("2.5.29.37", lifetime),
                Some(not_before - 1),
                "certificate_not_yet_valid",
            ),
        ] {
            // The rewritten signer replaces the original, so only the CA's
            // extKeyUsage (serverAuth alone) steers the path.
            let certificates: Vec<_> = embedded
                .iter()
                .map(|c| {
                    if publisher(c) {
                        leaf.clone()
                    } else {
                        c.clone()
                    }
                })
                .collect();
            assert!(usage_steers_the_path(&leaf, &certificates, &Budget::default()).unwrap());
            let signing_time = signed_at.map(|seconds| crate::trust::SigningTime {
                seconds,
                fraction: None,
            });
            let run = |budget: &Budget| {
                verify_trust(&store, &leaf, &certificates, signing_time, &options, budget)
                    .unwrap_err()
            };
            let budget = Budget::default();
            let error = json(run(&budget));
            assert_eq!(error["code"], code);
            assert_eq!(budget.path_work.used(), 200_000);
            assert_eq!(json(run(&one_search_left())), error);
        }
    }
    /// `good-rdp-eku-retry-ca.rdp`'s CA admits serverAuth only, so the
    /// codeSigning path fails and serverAuth is searched again; budget
    /// exhaustion on that retry propagates with its typed details.
    #[test]
    fn rdp_eku_retry_propagates_later_budget_exhaustion() {
        let bytes = fixture("good-rdp-eku-retry-ca.rdp");
        let certificates = signers_certificates("good-rdp-eku-retry-ca.rdp");
        let leaf = certificates
            .iter()
            .find(|c| c.tbs_certificate.subject.to_string() == "CN=rssig test RDP publisher")
            .unwrap();
        assert!(usage_steers_the_path(leaf, &certificates, &Budget::default()).unwrap());
        let mut store = crate::TrustStore::default();
        store.add_roots(&fixture("root.der")).unwrap();
        let options = disabled_revocation(&store);
        let budget = Budget::default();
        let report = verify_budget(&bytes, &options, &budget).unwrap();
        let trust = report.signatures[0].trust.as_ref().unwrap();
        assert_eq!(trust.required_eku.oid, "1.3.6.1.5.5.7.3.1");
        assert_eq!(budget.path_work.used(), 400_000);

        // The first accepted EKU fails on its path; the second must
        // propagate budget exhaustion.
        let error = verify_budget(&bytes, &options, &one_search_left()).unwrap_err();
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
    /// PATH-014's RDP case rests on the signer of `bad-rdp-repeated-eku.rdp`
    /// being that of `good-rdp-multiple-ekus.rdp` with one copy of its
    /// extKeyUsage appended, and every other certificate unchanged.
    #[test]
    fn the_repeated_eku_rdp_signer_differs_only_by_the_appended_copy() {
        let certs = |name: &str| {
            let rdp = Rdp::parse(&fixture(name)).unwrap();
            DetachedData::parse(&rdp.signature).unwrap().certs
        };
        let (good, bad) = (
            certs("good-rdp-multiple-ekus.rdp"),
            certs("bad-rdp-repeated-eku.rdp"),
        );
        assert_eq!(bad.len(), good.len());
        let mut changed = Vec::new();
        for (good, bad) in good.iter().zip(&bad).filter(|(good, bad)| good != bad) {
            let mut bad = bad.tbs_certificate.clone();
            let extensions = bad.extensions.as_mut().unwrap();
            let copy = extensions.pop().unwrap();
            assert_eq!(copy.extn_id.to_string(), "2.5.29.37");
            assert!(extensions.contains(&copy));
            assert_eq!(bad, good.tbs_certificate);
            changed.push(good.tbs_certificate.subject.to_string());
        }
        assert_eq!(changed, ["CN=rssig test publisher"]);
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
