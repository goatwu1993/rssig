//! SEC-10 maintenance builders: CRLs whose freshness or structure is faulty,
//! issued either by the test root or by an unrelated issuer.
use super::*;
use x509_cert::{
    Version,
    crl::{CertificateList, TbsCertList},
};

fn crl(issuer: &str, key: &SigningKey, this_update: u64, next_update: Option<u64>) -> Vec<u8> {
    let algorithm = identity().root.signature_algorithm.clone();
    let tbs = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer: Name::from_str(issuer).unwrap(),
        this_update: tm(this_update),
        next_update: next_update.map(tm),
        revoked_certificates: None,
        crl_extensions: Some(vec![x509_cert::ext::Extension {
            extn_id: ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20"),
            critical: false,
            extn_value: ::der::asn1::OctetString::new([2, 1, 1]).unwrap(),
        }]),
    };
    let sig: Signature = key.sign(&tbs.to_der().unwrap());
    CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
    }
    .to_der()
    .unwrap()
}

pub(super) fn crls() -> Vec<(&'static str, Vec<u8>)> {
    let root = "CN=rssig test root";
    let other = "CN=unrelated test root";
    let other_key = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
    let root_key = &identity().root_key;
    vec![
        (
            "sec10-root-no-next-update.crl",
            crl(root, root_key, NOW - 100, None),
        ),
        (
            "sec10-unrelated-expired.crl",
            crl(other, &other_key, NOW - 200, Some(NOW - 1)),
        ),
        (
            "sec10-unrelated-not-yet-valid.crl",
            crl(other, &other_key, NOW + 100, Some(NOW + 1000)),
        ),
        (
            "sec10-unrelated-no-next-update.crl",
            crl(other, &other_key, NOW - 100, None),
        ),
    ]
}

#[test]
#[ignore = "explicit fixture maintenance"]
fn regenerate_sec10_fixtures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (name, bytes) in crls() {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}
