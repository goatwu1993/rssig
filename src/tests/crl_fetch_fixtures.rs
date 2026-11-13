use super::*;
pub(super) fn write(dir: &std::path::Path) {
    for (name, url) in [
        (
            "good-crl-discovery.exe",
            "http://crl.example.invalid/test.crl",
        ),
        ("bad-crl-private-url.exe", "http://127.0.0.1/test.crl"),
    ] {
        let original = identity();
        let mut cert = original.cert.clone();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(x509_cert::ext::Extension {
                extn_id: "2.5.29.31".parse().unwrap(),
                critical: false,
                extn_value: ::der::asn1::OctetString::new(seq(&[seq(&[tlv(
                    0xa0,
                    &tlv(0xa0, &tlv(0x86, url.as_bytes())),
                )])]))
                .unwrap(),
            });
        let signature: Signature = original
            .root_key
            .sign(&cert.tbs_certificate.to_der().unwrap());
        cert.signature = BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
        let id = Identity {
            key: original.key.clone(),
            cert,
            root: original.root.clone(),
            root_key: original.root_key.clone(),
        };
        let base = base_pe(true);
        let content = image_content(&base, true, None);
        let si = signer_info(
            &id,
            der::one(&content, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![],
            vec![],
        );
        let bytes = attach(base, &signed_data(&id, content, cms::INDIRECT, si), true);
        std::fs::write(dir.join(name), &bytes).unwrap();
        if name == "good-crl-discovery.exe" {
            let mut bad = bytes;
            bad[700] ^= 1;
            std::fs::write(dir.join("bad-crl-discovery-image.exe"), bad).unwrap();
        }
    }
}
#[test]
#[ignore = "explicit fixture maintenance"]
fn regenerate_crl_discovery_fixtures() {
    write(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"));
}
