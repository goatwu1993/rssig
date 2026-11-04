//! Parsing gives untrusted structure; only verification establishes integrity/trust.
use rssig::{
    VerifyOptions,
    domain::ErrorCode,
    parse::{Pe, SignedData},
    verify_parsed_pe,
};

const GOOD: &[u8] = include_bytes!("fixtures/good-pe64.exe");

fn options() -> VerifyOptions<'static> {
    VerifyOptions {
        trust: None,
        check_revocation: false,
        allow_sha1: false,
        now: 1800000000,
    }
}

#[test]
fn parsing_does_not_claim_integrity_and_verification_reuses_the_parsed_pe() {
    let good = Pe::parse(GOOD).unwrap();
    assert_eq!(good.as_bytes(), GOOD);
    let signatures = good.signatures().unwrap();
    let cms = SignedData::parse(signatures[0]).unwrap();
    assert_eq!(cms.content_type().to_string(), "1.3.6.1.4.1.311.2.1.4");
    assert_eq!(
        cms.digest_algorithms()[0].oid().to_string(),
        "2.16.840.1.101.3.4.2.1"
    );
    assert_eq!(cms.certificate_choices().len(), 2);
    assert_eq!(cms.signer_infos().len(), 1);
    assert!(cms.content_der().is_some());
    let report = verify_parsed_pe(good, &options()).unwrap();
    assert!(!report.signatures[0].chain_trusted);
    assert_eq!(
        serde_json::to_value(report).unwrap(),
        serde_json::to_value(rssig::verify_pe(GOOD, &options()).unwrap()).unwrap()
    );
    for (bytes, code) in [
        (
            include_bytes!("fixtures/bad-image-digest.exe").as_slice(),
            ErrorCode::ImageDigestMismatch,
        ),
        (
            include_bytes!("fixtures/bad-cms-signature.exe").as_slice(),
            ErrorCode::InvalidSignature,
        ),
    ] {
        let pe = Pe::parse(bytes).unwrap();
        SignedData::parse(pe.signatures().unwrap()[0]).unwrap();
        assert_eq!(verify_parsed_pe(pe, &options()).unwrap_err().code, code);
    }
}

#[test]
fn parser_preserves_unknown_algorithms_but_verifier_rejects_them() {
    let bytes = include_bytes!("fixtures/unsupported-digest-algorithm.exe");
    let pe = Pe::parse(bytes).unwrap();
    let cms = SignedData::parse(pe.signatures().unwrap()[0]).unwrap();
    assert_eq!(cms.as_der(), pe.signatures().unwrap()[0]);
    assert!(
        cms.as_der()
            .windows(11)
            .any(|b| b == [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 127])
    );
    assert_eq!(
        verify_parsed_pe(pe, &options()).unwrap_err().code,
        ErrorCode::UnsupportedAlgorithm
    );
}

#[test]
fn parser_preserves_certificate_choices_separately_from_x509() {
    let pe = Pe::parse(include_bytes!("fixtures/good-pe-certificate-choice.exe")).unwrap();
    let cms = SignedData::parse(pe.signatures().unwrap()[0]).unwrap();
    let choices = cms.certificate_choices();
    assert_eq!(choices.len(), 3);
    assert_eq!(choices.iter().filter(|c| c.x509().is_some()).count(), 2);
    let opaque = &choices[2];
    assert_eq!(opaque.tag(), 0xa1);
    assert_eq!(
        opaque.as_der(),
        include_bytes!("fixtures/attribute-certificate-v1.der")
    );
    assert!(opaque.x509().is_none());
}

#[test]
fn parser_enforces_container_and_der_bounds() {
    assert!(Pe::parse(include_bytes!("fixtures/bad-truncated.exe")).is_err());
    let pe = Pe::parse(GOOD).unwrap();
    let bytes = pe.signatures().unwrap()[0];
    for end in 0..bytes.len() {
        assert!(
            SignedData::parse(&bytes[..end]).is_err(),
            "truncation at {end}"
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(SignedData::parse(&trailing).is_err());
}

#[test]
fn parsed_cab_and_navx_preserve_all_fixture_reports_and_policy() {
    use rssig::{
        TrustStore,
        parse::{Cab, Navx},
        verify::{verify_parsed_cab, verify_parsed_navx},
    };
    let mut trust = TrustStore::default();
    trust
        .add_roots(include_bytes!("fixtures/root.der"))
        .unwrap();
    trust.add_crl(include_bytes!("fixtures/good.crl")).unwrap();
    let mut revoked = TrustStore::default();
    revoked
        .add_roots(include_bytes!("fixtures/root.der"))
        .unwrap();
    revoked
        .add_crl(include_bytes!("fixtures/revoked.crl"))
        .unwrap();
    let empty = TrustStore::default();
    let policies = [
        options(),
        VerifyOptions {
            trust: Some(&trust),
            check_revocation: true,
            ..options()
        },
        VerifyOptions {
            trust: Some(&revoked),
            check_revocation: true,
            ..options()
        },
        VerifyOptions {
            trust: Some(&empty),
            check_revocation: true,
            ..options()
        },
        VerifyOptions {
            allow_sha1: true,
            ..options()
        },
    ];
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut count = 0;
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let Some(extension) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if !matches!(extension, "cab" | "navx") {
            continue;
        }
        count += 1;
        let bytes = std::fs::read(&path).unwrap();
        for policy in &policies {
            let (parsed, raw) = if extension == "cab" {
                (
                    Cab::parse(&bytes)
                        .map_err(rssig::VerificationError::from)
                        .and_then(|cab| verify_parsed_cab(cab, policy)),
                    rssig::verify_cab(&bytes, policy),
                )
            } else {
                (
                    Navx::parse(&bytes)
                        .map_err(rssig::VerificationError::from)
                        .and_then(|navx| verify_parsed_navx(navx, policy)),
                    rssig::verify_navx(&bytes, policy),
                )
            };
            assert_eq!(
                serde_json::to_value(parsed).unwrap(),
                serde_json::to_value(raw).unwrap(),
                "{}",
                path.display()
            );
        }
    }
    assert!(
        count >= 50,
        "the complete CAB/NAVX corpus must be exercised"
    );
}

#[test]
fn parsed_cab_and_navx_do_not_bypass_integrity_or_trust_checks() {
    use rssig::{
        parse::{Cab, Navx},
        verify_parsed_cab, verify_parsed_navx,
    };
    for (bytes, expected) in [
        (
            include_bytes!("fixtures/bad-cab-digest.cab").as_slice(),
            ErrorCode::CabDigestMismatch,
        ),
        (
            include_bytes!("fixtures/bad-cab-cms-signature.cab").as_slice(),
            ErrorCode::InvalidSignature,
        ),
        (
            include_bytes!("fixtures/bad-cab-framing-and-digest.cab").as_slice(),
            ErrorCode::MalformedCms,
        ),
    ] {
        let parsed = Cab::parse(bytes).unwrap();
        assert_eq!(
            verify_parsed_cab(parsed, &options()).unwrap_err().code,
            expected
        );
    }
    for (bytes, expected) in [
        (
            include_bytes!("fixtures/bad-navx-digest.navx").as_slice(),
            ErrorCode::NavxDigestMismatch,
        ),
        (
            include_bytes!("fixtures/bad-navx-cms-signature.navx").as_slice(),
            ErrorCode::InvalidSignature,
        ),
        (
            include_bytes!("fixtures/bad-navx-framing-and-digest.navx").as_slice(),
            ErrorCode::MalformedCms,
        ),
    ] {
        let parsed = Navx::parse(bytes).unwrap();
        assert_eq!(
            verify_parsed_navx(parsed, &options()).unwrap_err().code,
            expected
        );
    }
    let empty = rssig::TrustStore::default();
    let policy = VerifyOptions {
        trust: Some(&empty),
        check_revocation: true,
        ..options()
    };
    assert_eq!(
        verify_parsed_cab(
            Cab::parse(include_bytes!("fixtures/good.cab")).unwrap(),
            &policy
        )
        .unwrap_err()
        .code,
        ErrorCode::UntrustedRoot
    );
    assert_eq!(
        verify_parsed_navx(
            Navx::parse(include_bytes!("fixtures/good.navx")).unwrap(),
            &policy
        )
        .unwrap_err()
        .code,
        ErrorCode::UntrustedRoot
    );
}
