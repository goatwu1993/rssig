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
