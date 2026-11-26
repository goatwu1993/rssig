use super::*;
use ::der::Decode;
pub(super) fn write(dir: &std::path::Path) {
    // Distinct, correctly signed CRLs isolate the retained-artifact boundary.
    let mut bundle = String::new();
    let id = identity();
    for number in 1..=65u8 {
        let mut list = x509_cert::crl::CertificateList::from_der(&crl(false, false)).unwrap();
        list.tbs_cert_list.crl_extensions.as_mut().unwrap()[0].extn_value =
            ::der::asn1::OctetString::new([2, 1, number]).unwrap();
        let signature: Signature = id.root_key.sign(&list.tbs_cert_list.to_der().unwrap());
        list.signature = BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
        bundle.push_str(
            &::der::pem::encode_string(
                "X509 CRL",
                ::der::pem::LineEnding::LF,
                &list.to_der().unwrap(),
            )
            .unwrap(),
        );
        if number >= 64 {
            std::fs::write(dir.join(format!("limit-fetch-{number}-crls.pem")), &bundle).unwrap();
        }
    }
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
                extn_value: ::der::asn1::OctetString::new(seq(&[seq(&[single_uri_point(url)])]))
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
    write(&std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/fixtures"));
}
