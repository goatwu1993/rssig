//! SEC-10 maintenance builders: CRLs whose freshness or structure is faulty,
//! issued either by the test root or by an unrelated issuer.
use super::*;
use x509_cert::{
    Version,
    crl::{CertificateList, TbsCertList},
};

fn crl(issuer: &str, key: &SigningKey, this_update: u64, next_update: Option<u64>) -> Vec<u8> {
    crl_with_aki(issuer, key, this_update, next_update, None)
}

/// `aki` is the raw DER extnValue of an authorityKeyIdentifier extension.
fn crl_with_aki(
    issuer: &str,
    key: &SigningKey,
    this_update: u64,
    next_update: Option<u64>,
    aki: Option<Vec<u8>>,
) -> Vec<u8> {
    let algorithm = identity().root.signature_algorithm.clone();
    let tbs = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer: Name::from_str(issuer).unwrap(),
        this_update: tm(this_update),
        next_update: next_update.map(tm),
        revoked_certificates: None,
        crl_extensions: Some(
            aki.map(|value| x509_cert::ext::Extension {
                extn_id: ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.35"),
                critical: false,
                extn_value: ::der::asn1::OctetString::new(value).unwrap(),
            })
            .into_iter()
            .chain([x509_cert::ext::Extension {
                extn_id: ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20"),
                critical: false,
                extn_value: ::der::asn1::OctetString::new([2, 1, 1]).unwrap(),
            }])
            .collect(),
        ),
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

fn aki_value(id: &[u8]) -> Vec<u8> {
    x509_cert::ext::pkix::AuthorityKeyIdentifier {
        key_identifier: Some(::der::asn1::OctetString::new(id).unwrap()),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    }
    .to_der()
    .unwrap()
}

fn ski(cert: &Certificate) -> Vec<u8> {
    use ::der::Decode;
    let ext = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.extn_id.to_string() == "2.5.29.14")
        .unwrap();
    x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes())
        .unwrap()
        .0
        .as_bytes()
        .to_vec()
}

pub(super) fn crls() -> Vec<(&'static str, Vec<u8>)> {
    let root = "CN=rssig test root";
    let other = "CN=unrelated test root";
    let other_key = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
    let root_key = &identity().root_key;
    let root_ski = ski(&identity().root);
    vec![
        // The root's name and key, but an authorityKeyIdentifier naming another key.
        (
            "sec10-root-name-other-aki-expired.crl",
            crl_with_aki(
                root,
                root_key,
                NOW - 200,
                Some(NOW - 1),
                Some(aki_value(&[0xaa; 20])),
            ),
        ),
        // Same, but carrying the root's own key identifier.
        (
            "sec10-root-aki-expired.crl",
            crl_with_aki(
                root,
                root_key,
                NOW - 200,
                Some(NOW - 1),
                Some(aki_value(&root_ski)),
            ),
        ),
        // An authorityKeyIdentifier that is not a SEQUENCE: fail closed, do not
        // fall back to name-only matching.
        (
            "sec10-root-malformed-aki.crl",
            crl_with_aki(
                root,
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                Some(vec![0x30, 0x05, 0x80]),
            ),
        ),
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
