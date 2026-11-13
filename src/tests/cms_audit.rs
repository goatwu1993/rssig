use super::*;

pub(super) fn write(dir: &std::path::Path) {
    let id = identity();
    for (name, sd_version, si_version, values, null_signature) in [
        ("good-sec04-cms.exe", 1, 1, vec![1, 2], false),
        ("bad-sec04-signeddata-version.exe", 9, 1, vec![1, 2], false),
        ("bad-sec04-signer-version.exe", 1, 3, vec![1, 2], false),
        ("bad-sec04-value-order.exe", 1, 1, vec![2, 1], false),
        ("bad-sec04-ecdsa-parameters.exe", 1, 1, vec![1, 2], true),
    ] {
        let base = base_pe(true);
        let content = image_content(&base, true, None);
        let custom = seq(&[
            oid(&[42, 3, 4]),
            tlv(
                0x31,
                &values
                    .iter()
                    .flat_map(|v| tlv(2, &[*v]))
                    .collect::<Vec<_>>(),
            ),
        ]);
        let signer = signer_info(
            id,
            der::one(&content, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![custom],
            vec![],
        );
        let mut parts: Vec<Vec<u8>> = der::one(&signer, 0x30)
            .unwrap()
            .children()
            .unwrap()
            .iter()
            .map(|n| n.full.to_vec())
            .collect();
        parts[0] = tlv(2, &[si_version]);
        if null_signature {
            parts[4] = seq(&[oid(&[42, 134, 72, 206, 61, 4, 3, 2]), tlv(5, &[])]);
        }
        let cms = signed_data(id, content, cms::INDIRECT, seq(&parts));
        let outer = der::one(&cms, 0x30).unwrap().children().unwrap();
        let mut fields: Vec<Vec<u8>> = der::one(outer[1].body, 0x30)
            .unwrap()
            .children()
            .unwrap()
            .iter()
            .map(|n| n.full.to_vec())
            .collect();
        fields[0] = tlv(2, &[sd_version]);
        let cms = seq(&[outer[0].full.to_vec(), tlv(0xa0, &seq(&fields))]);
        std::fs::write(dir.join(name), attach(base, &cms, true)).unwrap();
    }
}
#[test]
#[ignore = "explicit fixture maintenance"]
fn regenerate_sec04_fixtures() {
    write(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"));
}

#[test]
fn sec04_fixtures_preserve_signature_math() {
    for name in [
        "good-sec04-cms.exe",
        "bad-sec04-signeddata-version.exe",
        "bad-sec04-signer-version.exe",
        "bad-sec04-value-order.exe",
        "bad-sec04-ecdsa-parameters.exe",
    ] {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap();
        let pe = pe::Pe::parse(&bytes).unwrap();
        let envelopes = pe.certificates().unwrap();
        let sd = crate::parse::SignedData::parse(envelopes[0]).unwrap();
        let si = der::one(sd.signer_infos()[0], 0x30)
            .unwrap()
            .children()
            .unwrap();
        let mut attrs = si[3].full.to_vec();
        attrs[0] = 0x31;
        crypto::verify_spki(
            &identity()
                .cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            cms::algorithm(si[2]).unwrap(),
            si[4].children().unwrap()[0].body,
            &attrs,
            si[5].body,
        )
        .unwrap();
    }
}

#[test]
fn sec04_attribute_and_integer_boundaries() {
    let attribute = attr(&[42, 3, 4], tlv(2, &[1]));
    assert!(
        crate::parse::Attributes::parse(&tlv(0xa0, &[attribute.clone(), attribute].concat()))
            .is_err()
    );
    let empty = seq(&[oid(&[42, 3, 4]), tlv(0x31, &[])]);
    assert!(crate::parse::Attributes::parse(&tlv(0xa0, &empty)).is_err());
    let id = identity();
    let signer = signer_info(id, b"content", None, vec![], vec![]);
    let nodes = der::one(&signer, 0x30).unwrap().children().unwrap();
    let mut parts: Vec<_> = nodes.iter().map(|n| n.full.to_vec()).collect();
    parts[0] = tlv(2, &[0, 1]);
    assert!(
        cms::verify_countersigner(
            core::slice::from_ref(&id.cert),
            der::one(&seq(&parts), 0x30).unwrap(),
            b"content",
            false
        )
        .is_err()
    );
    parts[0] = tlv(2, &[1]);
    parts.remove(3);
    assert!(
        cms::verify_countersigner(
            core::slice::from_ref(&id.cert),
            der::one(&seq(&parts), 0x30).unwrap(),
            b"content",
            false
        )
        .is_err()
    );
}
