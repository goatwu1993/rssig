use rssig::parse::{ErrorKind, InspectionBudget, InspectionLimits, SignedData};
const RFC: &[u8] = include_bytes!("fixtures/parse-rfc3161.der");

#[test]
fn recursive_inspection_borrows_and_shares_a_work_budget() {
    let mut budget = InspectionBudget::default();
    let cms = SignedData::inspect(RFC, &mut budget).unwrap();
    let child = &cms.signers[0].children[0];
    assert_eq!(child.kind, rssig::parse::InspectionKind::Rfc3161);
    let time = child.parsed_time.as_ref().unwrap();
    assert!(time.as_der().as_ptr() >= RFC.as_ptr());
    assert!(time.as_der().as_ptr_range().end <= RFC.as_ptr_range().end);
    assert_eq!(time.unix_seconds(), 1800000000);
    let mut budget = InspectionBudget::new(InspectionLimits {
        max_objects: 1,
        ..Default::default()
    });
    assert_eq!(
        SignedData::inspect(RFC, &mut budget).unwrap_err().kind(),
        ErrorKind::InspectionLimit
    );
    assert_eq!(
        SignedData::inspect(RFC, &mut budget).unwrap_err().kind(),
        ErrorKind::InspectionLimit
    );
}

#[test]
fn nested_inspection_enforces_depth_bytes_and_nodes() {
    for limits in [
        InspectionLimits {
            max_depth: 0,
            ..Default::default()
        },
        InspectionLimits {
            max_bytes: RFC.len() - 1,
            ..Default::default()
        },
        InspectionLimits {
            max_der_nodes: 1,
            ..Default::default()
        },
    ] {
        assert_eq!(
            SignedData::inspect(RFC, &mut InspectionBudget::new(limits))
                .unwrap_err()
                .kind(),
            ErrorKind::InspectionLimit
        );
    }
    assert_eq!(
        SignedData::inspect(
            include_bytes!("fixtures/parse-rfc3161-bad-time.der"),
            &mut InspectionBudget::default()
        )
        .unwrap_err()
        .kind(),
        ErrorKind::MalformedCms
    );
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if body.len() < 128 {
        bytes.push(body.len() as u8);
    } else {
        let len = body.len().to_be_bytes();
        let len = &len[len.iter().position(|b| *b != 0).unwrap()..];
        bytes.push(0x80 | len.len() as u8);
        bytes.extend_from_slice(len);
    }
    bytes.extend_from_slice(body);
    bytes
}
fn envelope(children: &[&[u8]]) -> Vec<u8> {
    let alg = [0x30, 5, 6, 3, 42, 3, 4];
    let mut si = vec![2, 1, 1, 0x80, 1, 7];
    si.extend_from_slice(&alg);
    si.extend_from_slice(&alg);
    si.extend_from_slice(&[4, 1, 9]);
    if !children.is_empty() {
        let mut attr = vec![6, 10, 43, 6, 1, 4, 1, 130, 55, 2, 4, 1];
        attr.extend(der(0x31, &children.concat()));
        si.extend(der(0xa1, &der(0x30, &attr)));
    }
    let mut sd = vec![2, 1, 1];
    sd.extend(der(0x31, &alg));
    sd.extend(der(0x30, &[6, 3, 42, 3, 4]));
    sd.extend(der(0x31, &der(0x30, &si)));
    let mut ci = vec![6, 9, 42, 134, 72, 134, 247, 13, 1, 7, 2];
    ci.extend(der(0xa0, &der(0x30, &sd)));
    der(0x30, &ci)
}

#[test]
fn sibling_values_and_repeated_calls_cannot_reset_the_budget() {
    let leaf = envelope(&[]);
    let siblings = envelope(&[&leaf, &leaf]);
    let limits = InspectionLimits {
        max_objects: 5,
        ..Default::default()
    };
    let error = SignedData::inspect(&siblings, &mut InspectionBudget::new(limits)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InspectionLimit);
    // A leaf costs one CMS and one signer, shared across distinct calls.
    let mut budget = InspectionBudget::new(InspectionLimits {
        max_objects: 3,
        ..Default::default()
    });
    SignedData::inspect(&leaf, &mut budget).unwrap();
    assert_eq!(
        SignedData::inspect(&leaf, &mut budget).unwrap_err().kind(),
        ErrorKind::InspectionLimit
    );
}

#[test]
fn depth_eight_is_supported_and_caller_cannot_raise_the_hard_depth_limit() {
    let mut bytes = envelope(&[]);
    for _ in 0..8 {
        bytes = envelope(&[&bytes]);
    }
    assert_eq!(bytes, include_bytes!("fixtures/parse-nested-depth8.der"));
    SignedData::inspect(&bytes, &mut InspectionBudget::default()).unwrap();
    bytes = envelope(&[&bytes]);
    assert_eq!(bytes, include_bytes!("fixtures/parse-nested-depth9.der"));
    let mut budget = InspectionBudget::new(InspectionLimits {
        max_depth: usize::MAX,
        ..Default::default()
    });
    assert_eq!(
        SignedData::inspect(&bytes, &mut budget).unwrap_err().kind(),
        ErrorKind::InspectionLimit
    );
}

#[test]
fn time_assertions_preserve_exact_fractions_and_reject_malformed_encodings() {
    use rssig::parse::ParsedTime;
    let bytes = der(0x18, b"20270115080000.009Z");
    let time = ParsedTime::parse(&bytes).unwrap();
    assert_eq!(time.unix_seconds(), 1800000000);
    assert_eq!(time.fractional_seconds(), Some("009"));
    assert_eq!(time.as_der(), bytes);
    assert_eq!(
        ParsedTime::parse(&der(0x17, b"270115080000Z"))
            .unwrap()
            .unix_seconds(),
        1800000000
    );
    for text in [
        "20270115080000.0Z",
        "20270230080000Z",
        "20270115080000.50Z",
        "20270115080000.Z",
        "20270115080000,5Z",
    ] {
        assert_eq!(
            ParsedTime::parse(&der(0x18, text.as_bytes()))
                .unwrap_err()
                .kind(),
            ErrorKind::MalformedCms
        );
    }
}

#[test]
fn recursive_inspection_is_not_signature_or_imprint_verification() {
    use rssig::parse::Pe;
    for bytes in [
        include_bytes!("fixtures/bad-nested-signature.exe").as_slice(),
        include_bytes!("fixtures/bad-countersignature-signature.exe").as_slice(),
        include_bytes!("fixtures/bad-timestamp-imprint.exe").as_slice(),
    ] {
        let pe = Pe::parse(bytes).unwrap();
        SignedData::inspect(
            pe.signatures().unwrap()[0],
            &mut InspectionBudget::default(),
        )
        .unwrap();
    }
}

#[test]
fn recursive_fixtures_are_exact_extractions_and_one_byte_time_mutation() {
    use rssig::parse::Pe;
    for (pe, cms) in [
        (include_bytes!("fixtures/good-rfc3161.exe").as_slice(), RFC),
        (
            include_bytes!("fixtures/good-countersignature.exe").as_slice(),
            include_bytes!("fixtures/parse-countersignature.der").as_slice(),
        ),
        (
            include_bytes!("fixtures/good-nested.exe").as_slice(),
            include_bytes!("fixtures/parse-nested.der").as_slice(),
        ),
    ] {
        assert_eq!(Pe::parse(pe).unwrap().signatures().unwrap()[0], cms);
    }
    let mut expected = RFC.to_vec();
    let cms = SignedData::inspect(RFC, &mut InspectionBudget::default()).unwrap();
    let time = cms.signers[0].children[0]
        .parsed_time
        .as_ref()
        .unwrap()
        .as_der();
    let at = time.as_ptr() as usize - RFC.as_ptr() as usize + time.len() - 1;
    assert_eq!(expected[at], b'Z');
    expected[at] = b'X';
    assert_eq!(
        expected,
        include_bytes!("fixtures/parse-rfc3161-bad-time.der")
    );
}

#[test]
fn recursive_cms_and_tst_info_reject_all_truncated_prefixes() {
    use rssig::parse::TstInfo;
    for end in 0..RFC.len() {
        assert!(SignedData::inspect(&RFC[..end], &mut InspectionBudget::default()).is_err());
    }
    let cms = SignedData::inspect(RFC, &mut InspectionBudget::default()).unwrap();
    let info = cms.signers[0].children[0]
        .cms
        .as_ref()
        .unwrap()
        .tst_info
        .as_ref()
        .unwrap();
    assert_eq!(info.version_der, [2, 1, 1]);
    assert_eq!(
        info.imprint_algorithm.oid().to_string(),
        "2.16.840.1.101.3.4.2.1"
    );
    assert_eq!(info.imprint.len(), 32);
    for end in 0..info.as_der().len() {
        assert!(TstInfo::parse(&info.as_der()[..end]).is_err());
    }
}
