use super::*;

fn conflict(same_key: bool) -> Certificate {
    let id = identity();
    let mut cert = id.cert.clone();
    if same_key {
        cert.tbs_certificate.subject = Name::from_str("CN=conflicting publisher").unwrap();
    } else {
        cert.tbs_certificate.subject_public_key_info = tsa_identity()
            .cert
            .tbs_certificate
            .subject_public_key_info
            .clone();
    }
    let signature: Signature = id.root_key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    cert
}

pub(super) fn write(dir: &std::path::Path) {
    let id = identity();
    for (name, certs) in [
        (
            "good-sec05-duplicate.exe",
            vec![id.cert.clone(), id.cert.clone(), id.root.clone()],
        ),
        (
            "good-sec05-reordered.exe",
            vec![id.root.clone(), id.cert.clone(), id.cert.clone()],
        ),
        (
            "bad-sec05-key-first.exe",
            vec![conflict(false), id.cert.clone(), id.root.clone()],
        ),
        (
            "bad-sec05-key-last.exe",
            vec![id.cert.clone(), conflict(false), id.root.clone()],
        ),
        (
            "bad-sec05-policy-first.exe",
            vec![conflict(true), id.cert.clone(), id.root.clone()],
        ),
        (
            "bad-sec05-policy-last.exe",
            vec![id.cert.clone(), conflict(true), id.root.clone()],
        ),
        ("bad-sec05-missing.exe", vec![id.root.clone()]),
    ] {
        let base = base_pe(true);
        let content = image_content(&base, true, None);
        let signer = signer_info(
            id,
            der::one(&content, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![],
            vec![],
        );
        let cms = signed_data(id, content, cms::INDIRECT, signer);
        let outer = der::one(&cms, 0x30).unwrap().children().unwrap();
        let mut fields: Vec<Vec<u8>> = der::one(outer[1].body, 0x30)
            .unwrap()
            .children()
            .unwrap()
            .iter()
            .map(|n| n.full.to_vec())
            .collect();
        fields[3] = tlv(
            0xa0,
            &certs
                .iter()
                .flat_map(|c| c.to_der().unwrap())
                .collect::<Vec<_>>(),
        );
        let cms = seq(&[outer[0].full.to_vec(), tlv(0xa0, &seq(&fields))]);
        std::fs::write(dir.join(name), attach(base, &cms, true)).unwrap();
    }
}
#[test]
#[ignore = "explicit fixture maintenance"]
fn regenerate_sec05_fixtures() {
    write(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"));
}

#[test]
fn sec05_shared_timestamp_and_detached_selection() {
    let id = identity();
    for name in [
        "good-sec05-duplicate.exe",
        "bad-sec05-key-first.exe",
        "bad-sec05-key-last.exe",
        "bad-sec05-policy-first.exe",
        "bad-sec05-policy-last.exe",
    ] {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap();
        let pe = pe::Pe::parse(&bytes).unwrap();
        let cms_bytes = pe.certificates().unwrap();
        let original = cms::SignedData::parse(cms_bytes[0]).unwrap();
        let content = seq(&[tlv(2, &[1])]);
        let counter = signer_info(id, &content, None, vec![], vec![]);
        let counter_result = cms::verify_countersigner(
            &original.certs,
            der::one(&counter, 0x30).unwrap(),
            &content,
            false,
        );
        let certs = original
            .certs
            .iter()
            .flat_map(|c| c.to_der().unwrap())
            .collect::<Vec<_>>();
        let ts_signer = signer_info(id, &content, Some(cms::TST_INFO), vec![], vec![]);
        let token_bytes = seq(&[
            oid(cms::SIGNED_DATA),
            tlv(
                0xa0,
                &seq(&[
                    tlv(2, &[3]),
                    tlv(0x31, &sha256_alg()),
                    seq(&[oid(cms::TST_INFO), tlv(0xa0, &tlv(4, &content))]),
                    tlv(0xa0, &certs),
                    tlv(0x31, &ts_signer),
                ]),
            ),
        ]);
        let token = cms::SignedData::parse(&token_bytes).unwrap();
        let timestamp_result = token.verify(token.signers[0], false);
        // A direct detached signature exercises RDP's attribute-free path.
        let signature: Signature = id.key.sign(&content);
        let direct = seq(&[
            tlv(2, &[1]),
            seq(&[
                id.cert.tbs_certificate.issuer.to_der().unwrap(),
                id.cert.tbs_certificate.serial_number.to_der().unwrap(),
            ]),
            sha256_alg(),
            seq(&[oid(&[42, 134, 72, 206, 61, 4, 3, 2])]),
            tlv(4, signature.to_der().as_bytes()),
        ]);
        let detached_bytes = seq(&[
            oid(cms::SIGNED_DATA),
            tlv(
                0xa0,
                &seq(&[
                    tlv(2, &[1]),
                    tlv(0x31, &sha256_alg()),
                    seq(&[oid(cms::DATA)]),
                    tlv(0xa0, &certs),
                    tlv(0x31, &direct),
                ]),
            ),
        ]);
        let detached = cms::DetachedData::parse(&detached_bytes).unwrap();
        let detached_result = detached.verify(detached.signers[0], &content, false);
        for result in [counter_result, timestamp_result, detached_result] {
            if name.starts_with("good") {
                assert!(result.is_ok());
            } else {
                let error = result.err().unwrap();
                let typed = error.downcast_ref::<domain::VerificationError>().unwrap();
                assert_eq!(typed.code, domain::ErrorCode::AmbiguousSignerCertificate);
            }
        }
    }
}

#[test]
fn sec05_embedded_duplicates_do_not_supply_trust() {
    let bytes = include_bytes!("../../tests/fixtures/good-sec05-duplicate.exe");
    let empty = trust::TrustStore::default();
    let error = verify::verify_pe(bytes, &verify::VerifyOptions::trusted(&empty, NOW)).unwrap_err();
    assert_eq!(error.code, domain::ErrorCode::UntrustedRoot);
}
