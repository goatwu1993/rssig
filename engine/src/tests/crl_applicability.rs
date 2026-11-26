//! CRL-T001 maintenance builders: CRLs whose freshness or structure is faulty,
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
    crl_full_named(
        Name::from_str(issuer).unwrap(),
        key,
        this_update,
        next_update,
        aki,
        extra,
        revoked,
    )
}

/// A name with one commonName whose value has the given string tag
/// (0x0c UTF8String, 0x13 PrintableString): the same text can be encoded
/// either way.
fn common_name(tag: u8, text: &str) -> Name {
    common_name_bytes(tag, text.as_bytes())
}

/// The same with the value's bytes as they are encoded, for a string type
/// whose bytes are not the text's UTF-8 (0x14 TeletexString as Latin-1,
/// 0x1e BMPString as UTF-16BE).
fn common_name_bytes(tag: u8, value: &[u8]) -> Name {
    use ::der::Decode;
    let attribute = seq(&[tlv(6, &[0x55, 4, 3]), tlv(tag, value)]);
    Name::from_der(&seq(&[tlv(0x31, &attribute)])).unwrap()
}

/// UTF-16BE, the encoding of a BMPString.
fn bmp(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

pub(super) fn crl_full_named(
    issuer: Name,
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
        issuer,
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
    aki_issuer_serial_for("CN=rssig test root", 1)
}

/// The same for the named issuer and serial.
fn aki_issuer_serial_for(issuer: &str, serial: u8) -> Vec<u8> {
    let name = Name::from_str(issuer).unwrap().to_der().unwrap();
    seq(&[tlv(0xa1, &tlv(0xa4, &name)), tlv(0x82, &[serial])])
}

/// The test root re-issued with the same key and name but another
/// subjectKeyIdentifier (all 0xbb): to webpki the same trust anchor.
fn root_with_other_ski() -> Certificate {
    use ::der::asn1::OctetString;
    let id = identity();
    let mut cert = id.root.clone();
    let extension = cert
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e.extn_id.to_string() == "2.5.29.14")
        .unwrap();
    extension.extn_value = OctetString::new(tlv(4, &[0xbb; 20])).unwrap();
    let signature: p256::ecdsa::Signature =
        id.root_key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = ::der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    cert
}

/// The test root re-issued with the same key and name and no
/// subjectKeyIdentifier, or with one that does not parse: to webpki the same
/// trust anchor, but its key cannot be named.
fn root_with_ski(extension_value: Option<Vec<u8>>) -> Certificate {
    use ::der::asn1::OctetString;
    let id = identity();
    let mut cert = id.root.clone();
    let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
    match extension_value {
        None => extensions.retain(|e| e.extn_id.to_string() != "2.5.29.14"),
        Some(value) => {
            extensions
                .iter_mut()
                .find(|e| e.extn_id.to_string() == "2.5.29.14")
                .unwrap()
                .extn_value = OctetString::new(value).unwrap();
        }
    }
    let signature: p256::ecdsa::Signature =
        id.root_key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = ::der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    cert
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
        // CRL-T004: a fresh, valid root CRL whose issuer is the root's name with
        // the commonName as a PrintableString, not the UTF8String the root
        // uses: the same name under RFC 5280 section 7.1.
        (
            "crl-root-issuer-printable.crl",
            crl_full_named(
                common_name(0x13, "rssig test root"),
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                None,
                vec![],
                None,
            ),
        ),
        // CRL-041: the root's name with the commonName as a BMPString and as a
        // TeletexString (Latin-1), the other DirectoryString types: the same
        // name, read as OpenSSL and Bouncy Castle read them.
        (
            "crl-root-issuer-bmp.crl",
            crl_full_named(
                common_name_bytes(0x1e, &bmp("rssig test root")),
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                None,
                vec![],
                None,
            ),
        ),
        (
            "crl-root-issuer-teletex.crl",
            crl_full_named(
                common_name_bytes(0x14, b"RSSIG Test Root"),
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                None,
                vec![],
                None,
            ),
        ),
        // CRL-041: the same with a VisibleString, which both references read
        // as ASCII text.
        (
            "crl-root-issuer-visible.crl",
            crl_full_named(
                common_name_bytes(0x1a, b"rssig  Test Root"),
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                None,
                vec![],
                None,
            ),
        ),
        // CRL-041: the same BMPString spelling with one letter changed, signed
        // by the root: not the root's name, so no CRL applies.
        (
            "crl-root-issuer-bmp-other-text.crl",
            crl_full_named(
                common_name_bytes(0x1e, &bmp("rssig test roof")),
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                None,
                vec![],
                None,
            ),
        ),
        // CRL-T004: the same with another case and extra white space, which
        // RFC 5280 section 7.1 also compares equal.
        (
            "crl-root-issuer-case-space.crl",
            crl_full_named(
                common_name(0x0c, "  RSSIG   Test  Root "),
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                None,
                vec![],
                None,
            ),
        ),
        // CRL-T004: a fresh CRL under the root's name in another case, signed by
        // another key and naming no key: a CRL of another CA whose name is
        // equal only under RFC 5280 comparison, set aside rather than forged.
        (
            "crl-root-forged-issuer-case.crl",
            crl_full_named(
                common_name(0x0c, "RSSIG TEST ROOT"),
                &other_key,
                NOW - 100,
                Some(NOW + 1000),
                None,
                vec![],
                None,
            ),
        ),
        // CRL-T004: the same, but naming the root's own key: it claims this
        // issuer, so it is forged, not set aside, whatever its spelling.
        (
            "crl-root-forged-issuer-case-naming-root-key.crl",
            crl_full_named(
                common_name(0x0c, "RSSIG TEST ROOT"),
                &other_key,
                NOW - 100,
                Some(NOW + 1000),
                Some(aki_value(&root_ski)),
                vec![],
                None,
            ),
        ),
        // CRL-T004: a fresh CRL signed by another key whose authorityKeyIdentifier
        // names the root's issuer and a serial the root does not have.
        (
            "crl-root-forged-aki-other-serial.crl",
            crl_with_aki(
                root,
                &other_key,
                NOW - 100,
                Some(NOW + 1000),
                Some(aki_issuer_serial_for("CN=rssig test root", 2)),
            ),
        ),
        // CRL-T004: signed by the root, with the same wrong serial: the signature
        // authenticates it.
        (
            "crl-root-signed-aki-other-serial.crl",
            crl_with_aki(
                root,
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                Some(aki_issuer_serial_for("CN=rssig test root", 2)),
            ),
        ),
        // CRL-T004: signed by another key, naming another issuer and the root's
        // serial.
        (
            "crl-root-forged-aki-other-issuer.crl",
            crl_with_aki(
                root,
                &other_key,
                NOW - 100,
                Some(NOW + 1000),
                Some(aki_issuer_serial_for("CN=unrelated test root", 1)),
            ),
        ),
        // The root's name, a fresh period, signed by another key, naming the
        // subjectKeyIdentifier of `crl-root-other-ski.der`: forged when that
        // root is configured (it is the same anchor), another issuer's CRL
        // otherwise.
        (
            "crl-root-forged-other-ski.crl",
            crl_with_aki(
                root,
                &other_key,
                NOW - 100,
                Some(NOW + 1000),
                Some(aki_value(&[0xbb; 20])),
            ),
        ),
        // The root's name, but signed by another key that its authorityKeyIdentifier
        // names: a CRL of a rolled-over issuer, not of the chain's root.
        (
            "crl-root-name-other-aki-expired.crl",
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
            "crl-root-signed-other-aki-expired.crl",
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
            "crl-root-aki-expired.crl",
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
            "crl-root-malformed-aki.crl",
            crl_with_aki(
                root,
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                Some(vec![0x30, 0x05, 0x80]),
            ),
        ),
        // The same malformed authorityKeyIdentifier on a fresh root CRL that
        // lists the test signer (serial 2): the root signed it, so the listing
        // counts beside a usable CRL that does not list the signer.
        (
            "crl-root-malformed-aki-revoked.crl",
            crl_full(
                root,
                root_key,
                NOW - 100,
                Some(NOW + 1000),
                Some(vec![0x30, 0x05, 0x80]),
                vec![],
                Some(vec![x509_cert::crl::RevokedCert {
                    serial_number: SerialNumber::from(2u32),
                    revocation_date: tm(NOW - 50),
                    crl_entry_extensions: None,
                }]),
            ),
        ),
        // An unrelated issuer's CRL is excluded before its extensions are read.
        (
            "crl-unrelated-malformed-aki.crl",
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
            "crl-root-unknown-critical-extension.crl",
            crl_with_extension("1.2.3.4", true, &[5, 0]),
        ),
        // The same unknown extension, non-critical: ignorable, so accepted.
        (
            "crl-root-unknown-noncritical-extension.crl",
            crl_with_extension("1.2.3.4", false, &[5, 0]),
        ),
        // webpki reads entries lazily; this must still fail closed as invalid_crl.
        (
            "crl-root-entry-critical-extension.crl",
            crl_with_entry_extension(),
        ),
        // deltaCRLIndicator: BaseCRLNumber 1.
        (
            "crl-root-delta.crl",
            crl_with_extension("2.5.29.27", true, &[2, 1, 1]),
        ),
        // Expired as well: the unsupported feature is reported, not freshness.
        (
            "crl-root-delta-expired.crl",
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
            "crl-root-indirect.crl",
            crl_with_extension("2.5.29.28", true, &[0x30, 3, 0x84, 1, 0xff]),
        ),
        // issuingDistributionPoint with only a scope flag and no distribution point:
        // webpki 0.103 rejects it at load, so it fails closed.
        (
            "crl-root-idp-user-certs.crl",
            crl_with_extension("2.5.29.28", true, &[0x30, 3, 0x81, 1, 0xff]),
        ),
        (
            "crl-root-idp-ca-certs.crl",
            crl_with_extension("2.5.29.28", true, &[0x30, 3, 0x82, 1, 0xff]),
        ),
        // The user-certificate partition without a distribution point,
        // listing the test signer (serial 2): in scope for an end entity in
        // OpenSSL and Bouncy Castle, so its listing counts beside a full CRL.
        (
            "crl-root-idp-user-certs-revoked.crl",
            crl_full(
                "CN=rssig test root",
                &identity().root_key,
                NOW - 100,
                Some(NOW + 1000),
                None,
                vec![x509_cert::ext::Extension {
                    extn_id: ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.28"),
                    critical: true,
                    extn_value: ::der::asn1::OctetString::new([0x30, 3, 0x81, 1, 0xff]).unwrap(),
                }],
                Some(vec![x509_cert::crl::RevokedCert {
                    serial_number: SerialNumber::from(2u32),
                    revocation_date: tm(NOW - 150),
                    crl_entry_extensions: None,
                }]),
            ),
        ),
        // A named distribution point; the test certificates list none, so the
        // CRL may be a partition that does not cover them.
        (
            "crl-root-idp-named-point.crl",
            crl_with_extension(
                "2.5.29.28",
                true,
                &idp_named_point("http://crl.invalid/root.crl"),
            ),
        ),
        // PR #64: the same named point on a CRL without nextUpdate. The scope
        // defect decides, as with nextUpdate: a source's CRL can replace it.
        (
            "crl-root-idp-named-point-no-next-update.crl",
            crl_full(
                root,
                root_key,
                NOW - 100,
                None,
                None,
                vec![x509_cert::ext::Extension {
                    extn_id: ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.28"),
                    critical: true,
                    extn_value: ::der::asn1::OctetString::new(idp_named_point(
                        "http://crl.invalid/root.crl",
                    ))
                    .unwrap(),
                }],
                None,
            ),
        ),
        // AKI with authorityCertIssuer and serial but no keyIdentifier: matched by
        // name only, so the stale CRL fails closed.
        (
            "crl-root-aki-issuer-serial-expired.crl",
            crl_with_aki(
                root,
                root_key,
                NOW - 200,
                Some(NOW - 1),
                Some(aki_issuer_serial()),
            ),
        ),
        (
            "crl-root-no-next-update.crl",
            crl(root, root_key, NOW - 100, None),
        ),
        // PR #64: the same, newer than crl-root-no-next-update-revoked.crl:
        // a current, complete CRL that leaves the signer out, so that older
        // listing may be a released hold and does not revoke.
        (
            "crl-root-no-next-update-newer.crl",
            crl(root, root_key, NOW - 10, None),
        ),
        // A root CRL without nextUpdate that lists the test signer and is
        // newer than good.crl: it claims no expiry, so it is not stale. It is
        // not evidence of good status (RFC 5280 requires nextUpdate), but its
        // listing counts and revokes, beside good.crl and alone.
        (
            "crl-root-no-next-update-revoked.crl",
            crl_full(
                root,
                root_key,
                NOW - 50,
                None,
                None,
                vec![],
                Some(vec![x509_cert::crl::RevokedCert {
                    serial_number: SerialNumber::from(2u32),
                    revocation_date: tm(NOW - 60),
                    crl_entry_extensions: None,
                }]),
            ),
        ),
        // An expired root CRL that lists the test signer (serial 2): a listing
        // counts only from a current CRL, so beside a fresh CRL that does not
        // list the signer it is ignored, and alone it is only expired.
        (
            "crl-root-expired-revoked.crl",
            crl_full(
                root,
                root_key,
                NOW - 200,
                Some(NOW - 1),
                None,
                vec![],
                Some(vec![x509_cert::crl::RevokedCert {
                    serial_number: SerialNumber::from(2u32),
                    revocation_date: tm(NOW - 150),
                    crl_entry_extensions: None,
                }]),
            ),
        ),
        // A root CRL still within its validity but older than `good.crl`
        // (thisUpdate NOW - 200 against NOW - 100), listing the test signer:
        // superseded, so its listing does not count beside the newer CRL.
        (
            "crl-root-superseded-revoked.crl",
            crl_full(
                root,
                root_key,
                NOW - 200,
                Some(NOW + 1000),
                None,
                vec![],
                Some(vec![x509_cert::crl::RevokedCert {
                    serial_number: SerialNumber::from(2u32),
                    revocation_date: tm(NOW - 150),
                    crl_entry_extensions: None,
                }]),
            ),
        ),
        (
            "crl-unrelated-expired.crl",
            crl(other, &other_key, NOW - 200, Some(NOW - 1)),
        ),
        (
            "crl-unrelated-not-yet-valid.crl",
            crl(other, &other_key, NOW + 100, Some(NOW + 1000)),
        ),
        (
            "crl-unrelated-no-next-update.crl",
            crl(other, &other_key, NOW - 100, None),
        ),
    ]
}

#[test]
#[ignore = "explicit fixture maintenance"]
fn regenerate_crl_fixtures() {
    let dir =
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/fixtures");
    for (name, bytes) in crls() {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    std::fs::write(
        dir.join("crl-root-other-ski.der"),
        root_with_other_ski().to_der().unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("crl-root-no-ski.der"),
        root_with_ski(None).to_der().unwrap(),
    )
    .unwrap();
    // An empty SEQUENCE where the OCTET STRING key identifier belongs.
    std::fs::write(
        dir.join("crl-root-malformed-ski.der"),
        root_with_ski(Some(vec![0x30, 0x00])).to_der().unwrap(),
    )
    .unwrap();
}
