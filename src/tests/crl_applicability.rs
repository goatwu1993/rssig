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
    crl_full(issuer, key, this_update, next_update, aki, vec![], None)
}

/// A fresh root CRL carrying one extra extension.
fn crl_with_extension(oid: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    let extension = x509_cert::ext::Extension {
        extn_id: ::der::asn1::ObjectIdentifier::new_unwrap(oid),
        critical,
        extn_value: ::der::asn1::OctetString::new(value).unwrap(),
    };
    crl_full(
        "CN=rssig test root",
        &identity().root_key,
        NOW - 100,
        Some(NOW + 1000),
        None,
        vec![extension],
        None,
    )
}

/// A fresh root CRL revoking an unrelated serial through an entry that carries
/// an unknown critical extension.
fn crl_with_entry_extension() -> Vec<u8> {
    let entry = x509_cert::crl::RevokedCert {
        serial_number: SerialNumber::from(999u32),
        revocation_date: tm(NOW - 50),
        crl_entry_extensions: Some(vec![x509_cert::ext::Extension {
            extn_id: ::der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4"),
            critical: true,
            extn_value: ::der::asn1::OctetString::new([5, 0]).unwrap(),
        }]),
    };
    crl_full(
        "CN=rssig test root",
        &identity().root_key,
        NOW - 100,
        Some(NOW + 1000),
        None,
        vec![],
        Some(vec![entry]),
    )
}

pub(super) fn crl_full(
    issuer: &str,
    key: &SigningKey,
    this_update: u64,
    next_update: Option<u64>,
    aki: Option<Vec<u8>>,
    extra: Vec<x509_cert::ext::Extension>,
    revoked: Option<Vec<x509_cert::crl::RevokedCert>>,
) -> Vec<u8> {
    let algorithm = identity().root.signature_algorithm.clone();
    let tbs = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer: Name::from_str(issuer).unwrap(),
        this_update: tm(this_update),
        next_update: next_update.map(tm),
        revoked_certificates: revoked,
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
            .chain(extra)
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

/// IDP whose distributionPoint fullName is one URI.
pub(super) fn idp_named_point(uri: &str) -> Vec<u8> {
    let general_name = tlv(0x86, uri.as_bytes());
    seq(&[tlv(0xa0, &tlv(0xa0, &general_name))])
}

/// AuthorityKeyIdentifier [1] authorityCertIssuer (directoryName) and
/// [2] authorityCertSerialNumber, without [0] keyIdentifier.
fn aki_issuer_serial() -> Vec<u8> {
    let name = Name::from_str("CN=rssig test root")
        .unwrap()
        .to_der()
        .unwrap();
    seq(&[tlv(0xa1, &tlv(0xa4, &name)), tlv(0x82, &[1])])
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
        // The root's name, but signed by another key that its authorityKeyIdentifier
        // names: a CRL of a rolled-over issuer, not of the chain's root.
        (
            "sec10-root-name-other-aki-expired.crl",
            crl_with_aki(
                root,
                &other_key,
                NOW - 200,
                Some(NOW - 1),
                Some(aki_value(&[0xaa; 20])),
            ),
        ),
        // Signed by the root's own key, but with a mismatched authorityKeyIdentifier:
        // a valid signature from a chain issuer is never excluded.
        (
            "sec10-root-signed-other-aki-expired.crl",
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
        // An unrelated issuer's CRL is excluded before its extensions are read.
        (
            "sec10-unrelated-malformed-aki.crl",
            crl_with_aki(
                other,
                &other_key,
                NOW - 100,
                Some(NOW + 1000),
                Some(vec![0x30, 0x05, 0x80]),
            ),
        ),
        // Unsupported CRL features from the chain's issuer must fail closed.
        (
            "sec10-root-unknown-critical-extension.crl",
            crl_with_extension("1.2.3.4", true, &[5, 0]),
        ),
        // The same unknown extension, non-critical: ignorable, so accepted.
        (
            "sec10-root-unknown-noncritical-extension.crl",
            crl_with_extension("1.2.3.4", false, &[5, 0]),
        ),
        // webpki reads entries lazily; this must still fail closed as invalid_crl.
        (
            "sec10-root-entry-critical-extension.crl",
            crl_with_entry_extension(),
        ),
        // deltaCRLIndicator: BaseCRLNumber 1.
        (
            "sec10-root-delta.crl",
            crl_with_extension("2.5.29.27", true, &[2, 1, 1]),
        ),
        // Expired as well: the unsupported feature is reported, not freshness.
        (
            "sec10-root-delta-expired.crl",
            crl_full(
                root,
                root_key,
                NOW - 200,
                Some(NOW - 1),
                None,
                vec![x509_cert::ext::Extension {
                    extn_id: ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.27"),
                    critical: true,
                    extn_value: ::der::asn1::OctetString::new([2, 1, 1]).unwrap(),
                }],
                None,
            ),
        ),
        // issuingDistributionPoint with indirectCRL TRUE.
        (
            "sec10-root-indirect.crl",
            crl_with_extension("2.5.29.28", true, &[0x30, 3, 0x84, 1, 0xff]),
        ),
        // issuingDistributionPoint with only a scope flag and no distribution point:
        // webpki 0.103 rejects it at load, so it fails closed.
        (
            "sec10-root-idp-user-certs.crl",
            crl_with_extension("2.5.29.28", true, &[0x30, 3, 0x81, 1, 0xff]),
        ),
        (
            "sec10-root-idp-ca-certs.crl",
            crl_with_extension("2.5.29.28", true, &[0x30, 3, 0x82, 1, 0xff]),
        ),
        // A named distribution point; the test certificates list none, so the
        // CRL may be a partition that does not cover them.
        (
            "sec10-root-idp-named-point.crl",
            crl_with_extension(
                "2.5.29.28",
                true,
                &idp_named_point("http://crl.invalid/root.crl"),
            ),
        ),
        // AKI with authorityCertIssuer and serial but no keyIdentifier: matched by
        // name only, so the stale CRL fails closed.
        (
            "sec10-root-aki-issuer-serial-expired.crl",
            crl_with_aki(
                root,
                root_key,
                NOW - 200,
                Some(NOW - 1),
                Some(aki_issuer_serial()),
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
