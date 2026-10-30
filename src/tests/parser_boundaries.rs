//! Structural parser invariants that need no signing or on-disk regeneration.
use super::*;

fn envelope(choice: Vec<u8>) -> Vec<u8> {
    seq(&[
        oid(cms::SIGNED_DATA),
        tlv(
            0xa0,
            &seq(&[
                vec![2, 1, 1],
                tlv(0x31, &sha256_alg()),
                seq(&[oid(cms::DATA)]),
                tlv(0xa0, &choice),
                tlv(0x31, &[]),
            ]),
        ),
    ])
}

#[test]
fn opaque_choices_preserve_envelopes_without_becoming_certificates() {
    let attribute = include_bytes!("../../tests/fixtures/attribute-certificate-v1.der");
    for tag in [0xa0, 0xa1, 0xa2, 0xa3] {
        let choice = if tag == 0xa3 {
            tlv(tag, &[oid(&[42, 3, 4]), tlv(4, b"opaque")].concat())
        } else {
            let mut bytes = attribute.to_vec();
            bytes[0] = tag;
            bytes
        };
        let bytes = envelope(choice.clone());
        let parsed = parse::SignedData::parse(&bytes).unwrap();
        assert_eq!(parsed.certificate_choices()[0].as_der(), choice);
        assert!(parsed.certificate_choices()[0].x509().is_none());
        assert!(parsed.content_der().is_none());
        assert!(parsed.signer_infos().is_empty());
        assert!(cms::DetachedData::parse(&bytes).is_err());
    }
}

#[test]
fn opaque_choice_framing_and_recursive_limits_are_enforced() {
    let other = |body: Vec<u8>| envelope(tlv(0xa3, &[oid(&[42, 3, 4]), body].concat()));
    // Correct outer lengths do not hide a truncated inner value.
    assert!(parse::SignedData::parse(&other(tlv(0x30, &[4, 2, 1]))).is_err());
    let mut deep = tlv(4, b"payload");
    for _ in 0..33 {
        deep = seq(&[deep]);
    }
    let error = parse::SignedData::parse(&other(deep)).unwrap_err();
    assert!(error.to_string().contains("DER limit exceeded"));
    let wide = tlv(0x30, &[5, 0].repeat(16384));
    let error = parse::SignedData::parse(&other(wide)).unwrap_err();
    assert!(error.to_string().contains("DER limit exceeded"));
}

#[test]
fn parser_retains_unknown_algorithm_identifiers_and_parameters() {
    let algorithm = seq(&[oid(&[42, 3, 127]), tlv(4, b"unknown parameters")]);
    let bytes = seq(&[
        oid(cms::SIGNED_DATA),
        tlv(
            0xa0,
            &seq(&[
                vec![2, 1, 1],
                tlv(0x31, &algorithm),
                seq(&[oid(cms::DATA)]),
                tlv(0x31, &[]),
            ]),
        ),
    ]);
    let parsed = parse::SignedData::parse(&bytes).unwrap();
    assert_eq!(parsed.digest_algorithms()[0].oid().to_string(), "1.2.3.127");
    assert_eq!(parsed.digest_algorithms()[0].as_der(), algorithm);
    assert_eq!(
        parsed.digest_algorithms()[0].parameters_der(),
        Some(tlv(4, b"unknown parameters").as_slice())
    );
    assert!(cms::DetachedData::parse(&bytes).is_err());
}
