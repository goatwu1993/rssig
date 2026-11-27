//! PATH-T001 maintenance builders: public deterministic keys, inert signed PE files.
use super::*;
use ::der::asn1::{ObjectIdentifier, OctetString};
use x509_cert::ext::{Extension, pkix::BasicConstraints};

/// CRL-T001 distribution-point fixtures. First the single-point signer: the point
/// it lists, another point, and the issuer CRL partitions as (label, scope,
/// revokes the leaf). `point_forms`, `scope_forms` and `root_scope_forms` below
/// hold the other signer and CRL forms.
const LISTED_POINT: &str = "http://crl.invalid/sec10-a.crl";
const OTHER_POINT: &str = "http://crl.invalid/sec10-b.crl";
const SCOPED_LEAF_SERIAL: u32 = 121;
/// The listed point with its scheme and host in upper case: a different URI.
const CASE_POINT: &str = "HTTP://CRL.INVALID/sec10-a.crl";
/// The three URIs the `multi` signer lists across two points.
const MULTI_POINTS: [&str; 3] = [
    "http://crl.invalid/sec10-c.crl",
    "http://crl.invalid/sec10-d.crl",
    "http://crl.invalid/sec10-e.crl",
];
/// The point the `crl-ca-crl-dp` intermediate lists.
const ISSUER_POINT: &str = "http://crl.invalid/sec10-issuer.crl";
/// The PATH-T001 issuer certificate's serial, revoked by
/// `crl-path-root-revoked-issuer.crl`.
const ISSUER_SERIAL: u32 = 110;
/// PATH-013: the extensions rssig or webpki decode in a path certificate,
/// each given a value that is one well-formed DER element of the wrong type.
const MALFORMED_EXTENSIONS: [(&str, &str); 8] = [
    ("bc", "2.5.29.19"),
    ("ku", "2.5.29.15"),
    ("eku", "2.5.29.37"),
    ("san", "2.5.29.17"),
    ("nc", "2.5.29.30"),
    ("crldp", "2.5.29.31"),
    ("ski", "2.5.29.14"),
    ("aki", "2.5.29.35"),
];
/// PATH-014: the certificate that repeats an extension, a label and the
/// extension. webpki keeps basicConstraints and subjectAltName and rejects
/// their repeat itself; the report decodes basicConstraints and not
/// subjectAltName. 1.2.3.4.5 is an extension nothing decodes.
const REPEATED_EXTENSIONS: [(&str, &str, &str); 6] = [
    ("leaf", "ski", "2.5.29.14"),
    ("leaf", "eku", "2.5.29.37"),
    ("leaf", "unfamiliar", "1.2.3.4.5"),
    ("ca", "ski", "2.5.29.14"),
    ("ca", "bc", "2.5.29.19"),
    ("ca", "san", "2.5.29.17"),
];
/// PATH-014 with PATH-013: the certificate that repeats its
/// authorityKeyIdentifier and, at an earlier position, has a
/// subjectKeyIdentifier that does not decode.
const BOTH_DEFECTS: [&str; 2] = ["leaf", "ca"];
/// SEQUENCE { NULL }: none of the extensions above decodes from it.
const MALFORMED_VALUE: [u8; 4] = [0x30, 0x02, 0x05, 0x00];
const PARTITIONS: [(&str, &str, bool); 5] = [
    ("match", LISTED_POINT, false),
    ("match-revoked", LISTED_POINT, true),
    ("other", OTHER_POINT, false),
    ("other-revoked", OTHER_POINT, true),
    ("case", CASE_POINT, false),
];

/// cRLDistributionPoints with exactly one DistributionPoint naming
/// `LISTED_POINT`. A DistributionPoint that has only a fullName encodes like an
/// issuingDistributionPoint that has only a fullName.
fn listed_points() -> Vec<u8> {
    one_point(LISTED_POINT)
}

/// cRLDistributionPoints with exactly one DistributionPoint naming one URI.
fn one_point(value: &str) -> Vec<u8> {
    seq(&[seq(&[full_name(&[uri(value)])])])
}

use super::{dp_full_name as full_name, uri_general_name as uri};

/// `[0] distributionPoint` holding nameRelativeToCRLIssuer `CN=sec10`.
fn relative_name() -> Vec<u8> {
    let cn = seq(&[tlv(6, &[0x55, 4, 3]), tlv(0x0c, b"sec10")]);
    tlv(0xa0, &tlv(0xa1, &cn))
}

/// A directoryName GeneralName: the PATH-T001 issuer's DN followed by `CN=sec10`.
fn expanded_relative_name() -> Vec<u8> {
    let issuer = name("issuer").to_der().unwrap();
    let cn = seq(&[tlv(6, &[0x55, 4, 3]), tlv(0x0c, b"sec10")]);
    let mut rdns = der::one(&issuer, 0x30).unwrap().body.to_vec();
    rdns.extend(tlv(0x31, &cn));
    tlv(0xa4, &tlv(0x30, &rdns))
}

/// CRL-T001 signers with other cRLDistributionPoints forms, as (label, serial,
/// extension value). Each is `crl-leaf-crl-dp-{label}.exe`.
fn point_forms() -> Vec<(&'static str, u32, Vec<u8>)> {
    let dns = tlv(0x82, b"crl.invalid");
    let reasons = tlv(0x81, &[6, 0x40]);
    let crl_issuer = tlv(0xa2, &tlv(0xa4, &name("upper").to_der().unwrap()));
    vec![
        // Two points; the second has two names.
        (
            "multi",
            122,
            seq(&[
                seq(&[full_name(&[uri(MULTI_POINTS[0])])]),
                seq(&[full_name(&[uri(MULTI_POINTS[1]), uri(MULTI_POINTS[2])])]),
            ]),
        ),
        // A dNSName, which is not a URI.
        ("dns", 123, seq(&[seq(&[full_name(&[dns])])])),
        ("relative", 124, seq(&[seq(&[relative_name()])])),
        // The listed URI, but partitioned by reason (keyCompromise).
        (
            "reasons",
            125,
            seq(&[seq(&[full_name(&[uri(LISTED_POINT)]), reasons])]),
        ),
        // The listed URI, but naming another CRL issuer (an indirect CRL).
        (
            "crl-issuer",
            126,
            seq(&[seq(&[full_name(&[uri(LISTED_POINT)]), crl_issuer])]),
        ),
        // An https URI: the engine passes it to the source, which decides.
        (
            "https",
            128,
            seq(&[seq(&[full_name(&[uri("https://crl.invalid/sec10-a.crl")])])]),
        ),
        // A reason-partitioned point, then the listed URI as a plain point.
        (
            "mixed",
            127,
            seq(&[
                seq(&[full_name(&[uri(MULTI_POINTS[0])]), tlv(0x81, &[6, 0x40])]),
                seq(&[full_name(&[uri(LISTED_POINT)])]),
            ]),
        ),
    ]
}

/// CRL-T001 issuer CRLs with other issuingDistributionPoint forms, as (label,
/// extension value). Each is `crl-issuer-idp-{label}.crl` and revokes nothing.
fn scope_forms() -> Vec<(&'static str, Vec<u8>)> {
    let listed = full_name(&[uri(LISTED_POINT)]);
    vec![
        // The listed URI with onlyContainsUserCerts or onlyContainsCACerts.
        ("match-user", seq(&[listed.clone(), tlv(0x81, &[0xff])])),
        ("match-ca", seq(&[listed, tlv(0x82, &[0xff])])),
        // Two names; only the second is the listed URI.
        (
            "two-names",
            seq(&[full_name(&[uri(OTHER_POINT), uri(LISTED_POINT)])]),
        ),
        // The second name of the `multi` signer's second point.
        ("second-point", seq(&[full_name(&[uri(MULTI_POINTS[2])])])),
        ("dns", seq(&[full_name(&[tlv(0x82, b"crl.invalid")])])),
        ("relative", seq(&[relative_name()])),
        // The directoryName that `CN=sec10` relative to the issuer expands to
        // (RFC 5280 6.3.3): a verifier that expanded relative names would
        // match the `relative` signer with it.
        (
            "relative-expanded",
            seq(&[full_name(&[expanded_relative_name()])]),
        ),
    ]
}

/// CRL-T001 PATH-T001 root CRLs naming `ISSUER_POINT` with a role scope, as (label,
/// extension value). Each is `crl-path-root-idp-{label}.crl`.
fn root_scope_forms() -> Vec<(&'static str, Vec<u8>)> {
    let point = full_name(&[uri(ISSUER_POINT)]);
    vec![
        ("ca", seq(&[point.clone(), tlv(0x82, &[0xff])])),
        ("user", seq(&[point, tlv(0x81, &[0xff])])),
    ]
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes((&[byte; 32]).into()).unwrap()
}
fn name(value: &str) -> Name {
    Name::from_str(&format!("CN=SEC-06 {value}")).unwrap()
}
fn certificate(
    subject: &str,
    serial: u32,
    subject_key: &SigningKey,
    issuer: &str,
    issuer_key: &SigningKey,
    ca: bool,
) -> Certificate {
    let profile = if ca {
        Profile::SubCA {
            issuer: name(issuer),
            path_len_constraint: None,
        }
    } else {
        Profile::Leaf {
            issuer: name(issuer),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        }
    };
    let mut builder = CertificateBuilder::new(
        profile,
        SerialNumber::from(serial),
        Validity {
            not_before: tm(NOW - 10000),
            not_after: tm(NOW + 10000),
        },
        name(subject),
        SubjectPublicKeyInfoOwned::from_key(*subject_key.verifying_key()).unwrap(),
        issuer_key,
    )
    .unwrap();
    if !ca {
        builder
            .add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
                "1.3.6.1.5.5.7.3.3",
            )]))
            .unwrap();
    }
    builder.build::<p256::ecdsa::DerSignature>().unwrap()
}
fn extension(cert: &mut Certificate, oid: &str, critical: bool, value: Option<Vec<u8>>) {
    let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
    extensions.retain(|e| e.extn_id.to_string() != oid);
    if let Some(value) = value {
        extensions.push(Extension {
            extn_id: oid.parse().unwrap(),
            critical,
            extn_value: OctetString::new(value).unwrap(),
        });
    }
}
/// Append a second instance of `cert`'s extension `oid`; when it has none,
/// add a noncritical one holding NULL and a second holding an empty OCTET
/// STRING, so that the two values differ.
fn repeat_extension(cert: &mut Certificate, oid: &str) {
    let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
    let copy = extensions
        .iter()
        .find(|e| e.extn_id.to_string() == oid)
        .cloned()
        .unwrap_or_else(|| {
            let added = Extension {
                extn_id: oid.parse().unwrap(),
                critical: false,
                extn_value: OctetString::new([0x05, 0x00]).unwrap(),
            };
            extensions.push(added.clone());
            Extension {
                extn_value: OctetString::new([0x04, 0x00]).unwrap(),
                ..added
            }
        });
    extensions.push(copy);
}
fn sign(cert: &mut Certificate, key: &SigningKey) {
    let sig: Signature = key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
}
fn bc(cert: &mut Certificate, ca: bool, path_len: Option<u8>) {
    extension(
        cert,
        "2.5.29.19",
        true,
        Some(
            BasicConstraints {
                ca,
                path_len_constraint: path_len,
            }
            .to_der()
            .unwrap(),
        ),
    );
}
fn dns(cert: &mut Certificate, value: &str) {
    extension(
        cert,
        "2.5.29.17",
        false,
        Some(seq(&[tlv(0x82, value.as_bytes())])),
    );
}
fn constraints(cert: &mut Certificate, permitted: &str, excluded: Option<&str>) {
    let mut fields = vec![tlv(0xa0, &seq(&[tlv(0x82, permitted.as_bytes())]))];
    if let Some(excluded) = excluded {
        fields.push(tlv(0xa1, &seq(&[tlv(0x82, excluded.as_bytes())])));
    }
    extension(cert, "2.5.29.30", true, Some(seq(&fields)));
}
/// Generated fixture files by name.
type Files = std::collections::BTreeMap<String, Vec<u8>>;
/// Adds one generated file; a name generated twice would leave only the
/// second on disk, so it fails instead.
fn put(out: &mut Files, name: impl Into<String>, bytes: impl Into<Vec<u8>>) {
    let name = name.into();
    assert!(
        out.insert(name.clone(), bytes.into()).is_none(),
        "{name} generated twice"
    );
}
#[test]
#[should_panic(expected = "path-x.der generated twice")]
fn a_path_fixture_name_generated_twice_fails() {
    let mut out = Files::new();
    put(&mut out, "path-x.der", vec![1]);
    put(&mut out, "path-x.der", vec![2]);
}
fn write_pe(out: &mut Files, label: &str, leaf: &Certificate, candidates: &[Certificate]) {
    let id = Identity {
        key: key(42),
        cert: leaf.clone(),
        root_key: key(41),
        root: candidates[0].clone(),
    };
    let base = base_pe(true);
    let content = image_content(&base, true, None);
    let signer = signer_info(
        &id,
        der::one(&content, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    let certs: Vec<u8> = core::iter::once(leaf)
        .chain(candidates)
        .flat_map(|c| c.to_der().unwrap())
        .collect();
    let cms = seq(&[
        oid(cms::SIGNED_DATA),
        tlv(
            0xa0,
            &seq(&[
                tlv(2, &[1]),
                tlv(0x31, &sha256_alg()),
                seq(&[oid(cms::INDIRECT), tlv(0xa0, &content)]),
                tlv(0xa0, &certs),
                tlv(0x31, &signer),
            ]),
        ),
    ]);
    put(out, format!("{label}.exe"), attach(base, &cms, true));
}
fn write_crl(out: &mut Files, issuer: &Certificate, issuer_key: &SigningKey, label: &str) {
    write_crl_with(out, issuer, issuer_key, label, false, None);
}
/// With `key_identified`, the CRL carries an authorityKeyIdentifier naming
/// the issuer's subjectKeyIdentifier.
fn write_crl_with(
    out: &mut Files,
    issuer: &Certificate,
    issuer_key: &SigningKey,
    label: &str,
    key_identified: bool,
    revoked: Option<u32>,
) {
    write_crl_at(
        out,
        issuer,
        issuer_key,
        label,
        key_identified,
        revoked,
        (NOW - 100, NOW + 1000),
    );
}
/// `window` is (thisUpdate, nextUpdate).
fn write_crl_at(
    out: &mut Files,
    issuer: &Certificate,
    issuer_key: &SigningKey,
    label: &str,
    key_identified: bool,
    revoked: Option<u32>,
    window: (u64, u64),
) {
    write_crl_named(
        out,
        issuer,
        issuer_key,
        label,
        key_identified,
        revoked,
        window,
        issuer.tbs_certificate.subject.clone(),
    );
}

/// `name` with every UTF8String value re-encoded as a PrintableString: the
/// same name under RFC 5280 section 7.1, different bytes.
fn printable_name(name: &Name) -> Name {
    use ::der::{Any, Tag, Tagged};
    let mut name = name.clone();
    for rdn in name.0.iter_mut() {
        let attributes: Vec<_> = rdn
            .0
            .iter()
            .map(|attribute| {
                let mut attribute = attribute.clone();
                if attribute.value.tag() == Tag::Utf8String {
                    attribute.value =
                        Any::new(Tag::PrintableString, attribute.value.value()).unwrap();
                }
                attribute
            })
            .collect();
        rdn.0 = attributes.try_into().unwrap();
    }
    name
}

#[allow(clippy::too_many_arguments)]
fn write_crl_named(
    out: &mut Files,
    issuer: &Certificate,
    issuer_key: &SigningKey,
    label: &str,
    key_identified: bool,
    revoked: Option<u32>,
    window: (u64, u64),
    issuer_name: Name,
) {
    use x509_cert::{
        Version,
        crl::{CertificateList, TbsCertList},
    };
    let algorithm = issuer.signature_algorithm.clone();
    let mut crl_extensions = vec![Extension {
        extn_id: "2.5.29.20".parse().unwrap(),
        critical: false,
        extn_value: OctetString::new([2, 1, 1]).unwrap(),
    }];
    if key_identified {
        let ski = issuer
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id == SKI_OID)
            .expect("issuer subjectKeyIdentifier");
        // SKI is OCTET STRING { id }; AKI is SEQUENCE { [0] id }.
        let id = &ski.extn_value.as_bytes()[2..];
        crl_extensions.push(Extension {
            extn_id: "2.5.29.35".parse().unwrap(),
            critical: false,
            extn_value: OctetString::new(tlv(0x30, &tlv(0x80, id))).unwrap(),
        });
    }
    let tbs = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer: issuer_name,
        this_update: tm(window.0),
        next_update: Some(tm(window.1)),
        revoked_certificates: revoked.map(|serial| {
            vec![x509_cert::crl::RevokedCert {
                serial_number: SerialNumber::from(serial),
                revocation_date: tm(NOW - 50),
                crl_entry_extensions: None,
            }]
        }),
        crl_extensions: Some(crl_extensions),
    };
    let sig: Signature = issuer_key.sign(&tbs.to_der().unwrap());
    let crl = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
    };
    put(out, format!("path-{label}.crl"), crl.to_der().unwrap());
}
/// Write a fresh CRL-T001 CRL from `issuer` with this critical
/// issuingDistributionPoint value, if any, revoking `revoked`, if any.
fn write_scoped_crl(
    out: &mut Files,
    file: &str,
    issuer: (&Certificate, &SigningKey),
    scope: Option<Vec<u8>>,
    revoked: Option<&Certificate>,
) {
    let scope = scope.map(|value| Extension {
        extn_id: "2.5.29.28".parse().unwrap(),
        critical: true,
        extn_value: OctetString::new(value).unwrap(),
    });
    let entries = revoked.map(|cert| {
        vec![x509_cert::crl::RevokedCert {
            serial_number: cert.tbs_certificate.serial_number.clone(),
            revocation_date: tm(NOW - 50),
            crl_entry_extensions: None,
        }]
    });
    let crl = crl_applicability::crl_full(
        &issuer.0.tbs_certificate.subject.to_string(),
        issuer.1,
        NOW - 100,
        Some(NOW + 1000),
        None,
        scope.into_iter().collect(),
        entries,
    );
    put(out, file, crl);
}
fn write_cert(out: &mut Files, label: &str, cert: &Certificate) {
    put(out, format!("path-{label}.der"), cert.to_der().unwrap());
}
/// Writes every path fixture into `dir`.
pub(super) fn write(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    for (name, bytes) in files() {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}
/// Every path fixture, generated in memory.
fn files() -> Files {
    let mut out = Files::new();
    generate(&mut out);
    out
}
fn generate(out: &mut Files) {
    let root_key = key(40);
    let ca_key = key(41);
    let leaf_key = key(42);
    let upper_key = key(43);
    let other_key = key(44);
    let root = certificate("root", 100, &root_key, "root", &root_key, true);
    let other = certificate(
        "other root",
        101,
        &other_key,
        "other root",
        &other_key,
        true,
    );
    let mut ca = certificate("issuer", ISSUER_SERIAL, &ca_key, "root", &root_key, true);
    bc(&mut ca, true, Some(0));
    sign(&mut ca, &root_key);
    let leaf = certificate("publisher", 120, &leaf_key, "issuer", &ca_key, false);
    let mut upper = certificate("upper", 130, &upper_key, "root", &root_key, true);
    bc(&mut upper, true, Some(1));
    sign(&mut upper, &root_key);
    for (label, cert, key) in [
        ("root", &root, &root_key),
        ("issuer", &ca, &ca_key),
        ("upper", &upper, &upper_key),
        ("other-root", &other, &other_key),
    ] {
        write_cert(out, label, cert);
        write_crl(out, cert, key, label);
    }
    write_cert(out, "leaf", &leaf);
    write_pe(out, "good-path-basic", &leaf, core::slice::from_ref(&ca));
    // Each bad variant retains valid image, CMS and certificate signatures.
    for label in [
        "ca-false",
        "ca-missing-bc",
        "ca-critical",
        "ca-noncritical",
        "ca-eku",
        "ca-good-eku",
        "ca-ku",
        "ca-no-ku",
    ] {
        let mut changed = ca.clone();
        match label {
            "ca-false" => bc(&mut changed, false, None),
            "ca-missing-bc" => extension(&mut changed, "2.5.29.19", true, None),
            "ca-critical" | "ca-noncritical" => extension(
                &mut changed,
                "1.2.3.4.5",
                label == "ca-critical",
                Some(tlv(5, &[])),
            ),
            "ca-eku" | "ca-good-eku" => extension(
                &mut changed,
                "2.5.29.37",
                false,
                Some(
                    ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(if label == "ca-eku" {
                        "1.3.6.1.5.5.7.3.1"
                    } else {
                        "1.3.6.1.5.5.7.3.3"
                    })])
                    .to_der()
                    .unwrap(),
                ),
            ),
            // cRLSign but no keyCertSign: CRL checking must not mask the CA rule.
            "ca-ku" => extension(&mut changed, "2.5.29.15", true, Some(tlv(3, &[1, 2]))),
            "ca-no-ku" => extension(&mut changed, "2.5.29.15", true, None),
            _ => unreachable!(),
        }
        sign(&mut changed, &root_key);
        let good = matches!(label, "ca-noncritical" | "ca-no-ku" | "ca-good-eku");
        if good {
            write_cert(out, label, &changed);
        }
        if label == "ca-ku" {
            write_pe(
                out,
                "good-path-ca-ku-first",
                &leaf,
                &[changed.clone(), ca.clone()],
            );
            write_pe(
                out,
                "good-path-ca-ku-last",
                &leaf,
                &[ca.clone(), changed.clone()],
            );
        }
        write_pe(
            out,
            &format!("{}-path-{label}", if good { "good" } else { "bad" }),
            &leaf,
            &[changed],
        );
    }
    // CRL-T001: the issuer signs certificates and the CRL with the same key; only
    // its KeyUsage decides whether that CRL may be used.
    let mut usages = Vec::new();
    for (label, bits) in [("ca-no-crl-sign", [2u8, 0x04]), ("ca-crl-sign", [1, 0x06])] {
        let mut changed = ca.clone();
        extension(&mut changed, "2.5.29.15", true, Some(tlv(3, &bits)));
        sign(&mut changed, &root_key);
        write_pe(
            out,
            &format!("crl-{label}"),
            &leaf,
            core::slice::from_ref(&changed),
        );
        usages.push(changed);
    }
    // The candidate without cRLSign comes first; path building must fall back.
    write_pe(out, "crl-ca-crl-sign-fallback", &leaf, &usages);
    // CRL-T001: the same root key and name as a configured anchor whose KeyUsage
    // lacks cRLSign; anchors are keys, so path-root.crl is still usable.
    let mut anchor = root.clone();
    extension(&mut anchor, "2.5.29.15", true, Some(tlv(3, &[2, 0x04])));
    sign(&mut anchor, &root_key);
    put(out, "crl-root-no-crl-sign.der", anchor.to_der().unwrap());
    // CRL-T001: a leaf with its own serial that lists one CRL distribution point,
    // and issuer CRLs partitioned by issuingDistributionPoint.
    let mut scoped = certificate(
        "publisher",
        SCOPED_LEAF_SERIAL,
        &leaf_key,
        "issuer",
        &ca_key,
        false,
    );
    extension(&mut scoped, "2.5.29.31", false, Some(listed_points()));
    sign(&mut scoped, &ca_key);
    write_pe(out, "crl-leaf-crl-dp", &scoped, core::slice::from_ref(&ca));
    for (label, uri, revoked) in PARTITIONS {
        write_scoped_crl(
            out,
            &format!("crl-issuer-idp-{label}.crl"),
            (&ca, &ca_key),
            Some(crl_applicability::idp_named_point(uri)),
            revoked.then_some(&scoped),
        );
    }
    // CRL-T001: an expired partition for another point. It cannot decide the
    // signer, so its age must not either.
    let other_scope = Extension {
        extn_id: "2.5.29.28".parse().unwrap(),
        critical: true,
        extn_value: OctetString::new(crl_applicability::idp_named_point(OTHER_POINT)).unwrap(),
    };
    put(
        out,
        "crl-issuer-idp-other-expired.crl",
        crl_applicability::crl_full(
            &ca.tbs_certificate.subject.to_string(),
            &ca_key,
            NOW - 200,
            Some(NOW - 1),
            None,
            vec![other_scope],
            None,
        ),
    );
    // CRL-T001: other distribution-point forms on the signer and on issuer CRLs.
    for (label, serial, points) in point_forms() {
        let mut signer = certificate("publisher", serial, &leaf_key, "issuer", &ca_key, false);
        extension(&mut signer, "2.5.29.31", false, Some(points));
        sign(&mut signer, &ca_key);
        write_pe(
            out,
            &format!("crl-leaf-crl-dp-{label}"),
            &signer,
            core::slice::from_ref(&ca),
        );
    }
    for (label, scope) in scope_forms() {
        let file = format!("crl-issuer-idp-{label}.crl");
        write_scoped_crl(out, &file, (&ca, &ca_key), Some(scope), None);
    }
    // CRL-T001: an intermediate that lists a distribution point, and PATH-T001 root
    // CRLs naming it with a CA-only or user-only scope.
    let mut pointed = ca.clone();
    extension(
        &mut pointed,
        "2.5.29.31",
        false,
        Some(one_point(ISSUER_POINT)),
    );
    sign(&mut pointed, &root_key);
    write_pe(out, "crl-ca-crl-dp", &leaf, core::slice::from_ref(&pointed));
    // CRL-T001: both selected certificates list a distribution point, the signer
    // LISTED_POINT and its issuer ISSUER_POINT.
    write_pe(
        out,
        "crl-chain-crl-dp",
        &scoped,
        core::slice::from_ref(&pointed),
    );
    // CRL-050 and CRL-051: the signer and its issuer, two certificates of two
    // issuers, list one point, the signer's LISTED_POINT.
    let mut shared = ca.clone();
    extension(
        &mut shared,
        "2.5.29.31",
        false,
        Some(one_point(LISTED_POINT)),
    );
    sign(&mut shared, &root_key);
    write_pe(
        out,
        "crl-chain-shared-crl-dp",
        &scoped,
        core::slice::from_ref(&shared),
    );
    for (label, scope) in root_scope_forms() {
        let file = format!("crl-path-root-idp-{label}.crl");
        write_scoped_crl(out, &file, (&root, &root_key), Some(scope), None);
    }
    // CRL-T001: a full root CRL that revokes the intermediate issuer.
    write_scoped_crl(
        out,
        "crl-path-root-revoked-issuer.crl",
        (&root, &root_key),
        None,
        Some(&ca),
    );
    // CRL-T001: a full other-root CRL that revokes the cross certificate (the
    // issuer re-signed by the other root, same serial), so that one candidate
    // path is revoked while the other only lacks a root CRL.
    write_scoped_crl(
        out,
        "crl-path-other-root-revoked-cross.crl",
        (&other, &other_key),
        None,
        Some(&ca),
    );
    for label in [
        "leaf-ca",
        "leaf-no-bc",
        "leaf-critical",
        "leaf-noncritical",
        "leaf-no-ku",
        "leaf-no-eku",
    ] {
        let mut changed = leaf.clone();
        match label {
            "leaf-ca" => bc(&mut changed, true, None),
            "leaf-no-bc" => extension(&mut changed, "2.5.29.19", true, None),
            "leaf-no-eku" => extension(&mut changed, "2.5.29.37", false, None),
            "leaf-no-ku" => extension(&mut changed, "2.5.29.15", true, None),
            _ => extension(
                &mut changed,
                "1.2.3.4.5",
                label == "leaf-critical",
                Some(tlv(5, &[])),
            ),
        }
        sign(&mut changed, &ca_key);
        let good = matches!(label, "leaf-no-bc" | "leaf-noncritical" | "leaf-no-ku");
        if good {
            write_cert(out, label, &changed);
        }
        write_pe(
            out,
            &format!("{}-path-{label}", if good { "good" } else { "bad" }),
            &changed,
            &[ca.clone()],
        );
    }
    for (label, oid) in MALFORMED_EXTENSIONS {
        let mut changed_ca = ca.clone();
        extension(&mut changed_ca, oid, false, Some(MALFORMED_VALUE.to_vec()));
        sign(&mut changed_ca, &root_key);
        if label == "ski" {
            // PATH-013 with PATH-009: the malformed candidate comes first, and
            // path building must go on to the valid issuer.
            write_pe(
                out,
                "good-path-ca-malformed-first",
                &leaf,
                &[changed_ca.clone(), ca.clone()],
            );
            // PATH-013 with PATH-008: one candidate lacks keyCertSign and the
            // other has a malformed extension; the malformed extension is
            // reported.
            let mut no_cert_sign = ca.clone();
            extension(&mut no_cert_sign, "2.5.29.15", true, Some(tlv(3, &[1, 2])));
            sign(&mut no_cert_sign, &root_key);
            write_pe(
                out,
                "bad-path-ca-ku-and-malformed",
                &leaf,
                &[changed_ca.clone(), no_cert_sign],
            );
        }
        if label == "bc" {
            // PATH-013: a candidate whose basicConstraints does not decode is
            // set aside by the path, and reported with the extension marked.
            write_pe(
                out,
                "good-path-ca-malformed-bc-first",
                &leaf,
                &[changed_ca.clone(), ca.clone()],
            );
        }
        write_pe(
            out,
            &format!("bad-path-ca-malformed-{label}"),
            &leaf,
            &[changed_ca],
        );
        let mut changed_leaf = leaf.clone();
        extension(
            &mut changed_leaf,
            oid,
            false,
            Some(MALFORMED_VALUE.to_vec()),
        );
        sign(&mut changed_leaf, &ca_key);
        write_pe(
            out,
            &format!("bad-path-leaf-malformed-{label}"),
            &changed_leaf,
            &[ca.clone()],
        );
    }
    // PATH-013: webpki itself rejects a subjectAltName that is no SEQUENCE.
    let mut san_octets = ca.clone();
    extension(&mut san_octets, "2.5.29.17", false, Some(vec![0x04, 0x00]));
    sign(&mut san_octets, &root_key);
    write_pe(
        out,
        "bad-path-ca-san-not-a-sequence",
        &leaf,
        core::slice::from_ref(&san_octets),
    );
    // PATH-013: the signer's issuer is missing, and a malformed CA issues only
    // an unrelated embedded certificate, so it is not the cause.
    let stranger_key = key(47);
    let stranger = certificate("stranger", 140, &stranger_key, "dangling", &key(48), false);
    let mut dangling = certificate("dangling", 141, &key(48), "root", &root_key, true);
    extension(
        &mut dangling,
        "2.5.29.14",
        false,
        Some(MALFORMED_VALUE.to_vec()),
    );
    sign(&mut dangling, &root_key);
    write_pe(
        out,
        "bad-path-unrelated-malformed-issuer",
        &leaf,
        &[stranger, dangling],
    );
    // PATH-013: an rfc822Name with a byte above 0x7F is no IA5String.
    let mut non_ascii = leaf.clone();
    extension(
        &mut non_ascii,
        "2.5.29.17",
        false,
        Some(seq(&[tlv(0x81, b"us\xc3\xa9r@example.invalid")])),
    );
    sign(&mut non_ascii, &ca_key);
    write_pe(
        out,
        "bad-path-leaf-san-non-ascii",
        &non_ascii,
        core::slice::from_ref(&ca),
    );
    // PATH-014: a certificate that repeats an extension, the second instance
    // a copy of the first so that each one decodes.
    for (who, label, oid) in REPEATED_EXTENSIONS {
        let (mut changed_leaf, mut changed_ca) = (leaf.clone(), ca.clone());
        if who == "leaf" {
            repeat_extension(&mut changed_leaf, oid);
            sign(&mut changed_leaf, &ca_key);
        } else {
            if label == "san" {
                dns(&mut changed_ca, "issuer.example.invalid");
            }
            repeat_extension(&mut changed_ca, oid);
            sign(&mut changed_ca, &root_key);
        }
        if (who, label) == ("ca", "ski") {
            // PATH-014 with PATH-009: the repeating candidate comes first,
            // and path building must go on to the valid issuer.
            write_pe(
                out,
                "good-path-ca-repeated-first",
                &leaf,
                &[changed_ca.clone(), ca.clone()],
            );
        }
        if (who, label) == ("ca", "san") {
            // PATH-014 with PATH-009: a candidate webpki rejects comes first,
            // and path building must go on to the valid issuer.
            write_pe(
                out,
                "good-path-ca-repeated-san-first",
                &leaf,
                &[changed_ca.clone(), ca.clone()],
            );
            // PATH-014: the signer's issuer is missing, and a CA that
            // repeats its subjectAltName issues only an unrelated embedded
            // certificate, so it is on no path.
            let stranger_key = key(47);
            let stranger = certificate("stranger", 142, &stranger_key, "dangling", &key(48), false);
            let mut dangling = certificate("dangling", 143, &key(48), "root", &root_key, true);
            dns(&mut dangling, "dangling.example.invalid");
            repeat_extension(&mut dangling, "2.5.29.17");
            sign(&mut dangling, &root_key);
            write_pe(
                out,
                "bad-path-unrelated-repeated-issuer",
                &leaf,
                &[stranger, dangling],
            );
        }
        write_pe(
            out,
            &format!("bad-path-{who}-repeated-{label}"),
            &changed_leaf,
            &[changed_ca],
        );
    }
    // PATH-014 with PATH-013: the repeat is reported, though the malformed
    // value sits before it.
    for who in BOTH_DEFECTS {
        let (mut changed, issuer_key) = if who == "leaf" {
            (leaf.clone(), &ca_key)
        } else {
            (ca.clone(), &root_key)
        };
        changed
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.14")
            .unwrap()
            .extn_value = OctetString::new(MALFORMED_VALUE.to_vec()).unwrap();
        repeat_extension(&mut changed, "2.5.29.35");
        sign(&mut changed, issuer_key);
        let (signer, candidate) = if who == "leaf" {
            (changed, ca.clone())
        } else {
            (leaf.clone(), changed)
        };
        write_pe(
            out,
            &format!("bad-path-{who}-repeated-and-malformed"),
            &signer,
            &[candidate],
        );
    }
    let mut lower = ca.clone();
    lower.tbs_certificate.issuer = name("upper");
    // Remove the old issuer's AKI when cross-signing; issuer DN/signature bind it.
    extension(&mut lower, "2.5.29.35", false, None);
    sign(&mut lower, &upper_key);
    write_cert(out, "lower", &lower);
    write_pe(
        out,
        "good-path-pathlen",
        &leaf,
        &[lower.clone(), upper.clone()],
    );
    let mut short = upper.clone();
    bc(&mut short, true, Some(0));
    sign(&mut short, &root_key);
    write_pe(out, "bad-path-pathlen", &leaf, &[lower, short]);
    let mut constrained = ca.clone();
    constraints(
        &mut constrained,
        "allowed.invalid",
        Some("blocked.allowed.invalid"),
    );
    sign(&mut constrained, &root_key);
    write_cert(out, "constrained", &constrained);
    for (label, host) in [
        ("good", "app.allowed.invalid"),
        ("outside", "outside.invalid"),
        ("excluded", "blocked.allowed.invalid"),
    ] {
        let mut changed = leaf.clone();
        dns(&mut changed, host);
        sign(&mut changed, &ca_key);
        if label == "good" {
            write_cert(out, &format!("dns-{label}"), &changed);
        }
        write_pe(
            out,
            &format!(
                "{}-path-name-{label}",
                if label == "good" { "good" } else { "bad" }
            ),
            &changed,
            &[constrained.clone()],
        );
    }
    // Same DN, wrong key is not an issuer; test both candidate orders.
    let wrong = certificate("issuer", 111, &key(45), "root", &root_key, true);
    write_pe(
        out,
        "bad-path-wrong-key",
        &leaf,
        core::slice::from_ref(&wrong),
    );
    write_pe(
        out,
        "good-path-wrong-key-first",
        &leaf,
        &[wrong.clone(), ca.clone()],
    );
    write_pe(out, "good-path-wrong-key-last", &leaf, &[ca.clone(), wrong]);
    let mut cross = ca.clone();
    cross.tbs_certificate.issuer = name("other root");
    extension(&mut cross, "2.5.29.35", false, None);
    sign(&mut cross, &other_key);
    write_cert(out, "cross", &cross);
    write_pe(
        out,
        "bad-path-cross-untrusted",
        &leaf,
        &[cross.clone(), other.clone()],
    );
    write_pe(
        out,
        "good-path-cross-first",
        &leaf,
        &[cross.clone(), other.clone(), ca.clone()],
    );
    // CRL-T001: a cross certificate whose KeyUsage lacks keyCertSign (cRLSign
    // only), first, so that its path fails the path checks whatever its CRLs say.
    let mut cross_no_cert_sign = cross.clone();
    extension(
        &mut cross_no_cert_sign,
        "2.5.29.15",
        true,
        Some(tlv(3, &[1, 2])),
    );
    sign(&mut cross_no_cert_sign, &other_key);
    write_pe(
        out,
        "crl-path-cross-no-cert-sign",
        &leaf,
        &[cross_no_cert_sign, other.clone(), ca.clone()],
    );
    // CRL-T004: a self-issued key rollover. The root's name is carried by a
    // second key, certified by the root; the signer is issued under that
    // name by the second key. Two certificates on the path therefore have
    // issuers of the same name and different keys, each with its own CRL.
    let rollover_key = key(45);
    let rollover = certificate("root", 140, &rollover_key, "root", &root_key, true);
    let rolled_leaf = certificate("publisher", 141, &leaf_key, "root", &rollover_key, false);
    write_pe(
        out,
        "good-path-self-issued-rollover",
        &rolled_leaf,
        core::slice::from_ref(&rollover),
    );
    write_crl(out, &rollover, &rollover_key, "rollover");
    // CRL-T004: the same CRL with its issuer as a PrintableString. Its bytes
    // differ from the root CRL's issuer, but the two issuers on the path are
    // still one name, so CRL-008 still rejects the path.
    write_crl_named(
        out,
        &rollover,
        &rollover_key,
        "rollover-printable",
        false,
        None,
        (NOW - 100, NOW + 1000),
        printable_name(&rollover.tbs_certificate.subject),
    );
    // The same two CRLs, each naming its issuer's key: the case in which
    // OpenSSL, BoringSSL and Bouncy Castle all tell the two issuers apart.
    // CRL-T001: the root's CRL, expired: on a cross-certified file the root
    // path's only CRL then needs a refresh while the other path is revoked.
    write_crl_at(
        out,
        &root,
        &root_key,
        "root-expired",
        false,
        None,
        (NOW - 2000, NOW - 1000),
    );
    // PR #64: the root's CRL, not yet valid: a CRL a source could replace,
    // named under certificates_with_replaceable_crl rather than as expired.
    write_crl_at(
        out,
        &root,
        &root_key,
        "root-not-yet-valid",
        false,
        None,
        (NOW + 1000, NOW + 2000),
    );
    write_crl_with(out, &root, &root_key, "root-akid", true, None);
    write_crl_with(out, &rollover, &rollover_key, "rollover-akid", true, None);
    // The root key's CRL revoking the rollover certificate, which webpki's
    // confirmation of such a path does not look at.
    write_crl_with(
        out,
        &root,
        &root_key,
        "root-akid-revoked-rollover",
        true,
        Some(140),
    );
    // CRL-T001: an expired cross certificate, first, so that webpki's highest
    // ranked error (expiry) comes from a path other than the one that only
    // lacks a root CRL.
    let mut cross_expired = cross.clone();
    cross_expired.tbs_certificate.validity.not_after = tm(NOW - 1);
    sign(&mut cross_expired, &other_key);
    write_pe(
        out,
        "crl-path-cross-expired-first",
        &leaf,
        &[cross_expired, other.clone(), ca.clone()],
    );
    write_pe(
        out,
        "good-path-cross-last",
        &leaf,
        &[ca.clone(), cross, other],
    );
    // Cryptographically valid A -> B -> A cycle with distinct subject/key pairs.
    let mut cycle_a = ca.clone();
    cycle_a.tbs_certificate.issuer = name("upper");
    bc(&mut cycle_a, true, None);
    extension(&mut cycle_a, "2.5.29.35", false, None);
    sign(&mut cycle_a, &upper_key);
    let mut cycle_b = upper.clone();
    cycle_b.tbs_certificate.issuer = name("issuer");
    bc(&mut cycle_b, true, None);
    extension(&mut cycle_b, "2.5.29.35", false, None);
    sign(&mut cycle_b, &ca_key);
    write_pe(
        out,
        "bad-path-cycle",
        &leaf,
        &[cycle_a.clone(), cycle_b.clone()],
    );
    write_pe(
        out,
        "bad-path-cycle-reversed",
        &leaf,
        &[cycle_b.clone(), cycle_a.clone()],
    );
    write_pe(
        out,
        "good-path-cycle-escape",
        &leaf,
        &[cycle_a.clone(), cycle_b.clone(), ca.clone()],
    );
    write_pe(
        out,
        "good-path-cycle-escape-reversed",
        &leaf,
        &[ca.clone(), cycle_b, cycle_a],
    );
    // Configured anchors are trusted key/name/constraints, not path certificates.
    let mut expired = root.clone();
    expired.tbs_certificate.validity.not_after = tm(NOW - 1);
    sign(&mut expired, &root_key);
    write_cert(out, "root-expired", &expired);
    let mut profile = root.clone();
    bc(&mut profile, false, Some(0));
    extension(&mut profile, "2.5.29.15", true, Some(tlv(3, &[7, 128])));
    extension(
        &mut profile,
        "2.5.29.37",
        false,
        Some(
            ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")])
                .to_der()
                .unwrap(),
        ),
    );
    sign(&mut profile, &root_key);
    write_cert(out, "root-profile", &profile);
    let mut root_nc = root.clone();
    constraints(&mut root_nc, "allowed.invalid", None);
    sign(&mut root_nc, &root_key);
    write_cert(out, "root-constrained", &root_nc);
    let mut root_deny = root.clone();
    constraints(&mut root_deny, "elsewhere.invalid", None);
    sign(&mut root_deny, &root_key);
    write_cert(out, "root-denied", &root_deny);
    let mut named = leaf.clone();
    dns(&mut named, "app.allowed.invalid");
    sign(&mut named, &ca_key);
    write_pe(out, "good-path-root-name", &named, &[ca]);
    use ::der::EncodePem;
    let pem = [
        root_deny.to_pem(::der::pem::LineEnding::LF).unwrap(),
        root_nc.to_pem(::der::pem::LineEnding::LF).unwrap(),
    ]
    .concat();
    put(out, "path-roots-alternative.pem", pem);
}
#[test]
#[ignore = "explicit fixture maintenance; review binaries and update manifest"]
fn regenerate_path_fixtures() {
    write(&std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/fixtures"));
}

#[test]
fn certificate_paths_fixtures_preserve_image_cms_and_certificate_signatures() {
    use ::der::Decode;
    let dir =
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/fixtures");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    // The files checked are the ones `write` generates, in memory, so a
    // fixture added to the generator is checked without a hand-kept list or
    // count to update. They must be exactly the files the manifest attributes
    // to this generator: a generated file the manifest does not attribute to
    // it fails the first assertion, an attributed file `write` no longer
    // produces the second, and a committed file the manifest does not list at
    // all fails `committed_manifest_fixtures_and_cases_are_consistent`, which
    // also checks each committed file's SHA-256 against the manifest. Each
    // committed file must then hold exactly the bytes generated (the
    // generator uses fixed keys and RFC 6979 ECDSA), so a generator change
    // without a regeneration fails here.
    let generated = files();
    let attributed: std::collections::BTreeSet<&str> = manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|artifact| {
            let generator = artifact
                .get("generator")
                .or_else(|| artifact.get("provenance")?.get("generator"));
            // A generator may be followed by whitespace and a note.
            generator.and_then(|g| g.as_str()?.split_whitespace().next())
                == Some("engine/src/tests/certificate_paths.rs::regenerate_path_fixtures")
        })
        .map(|artifact| artifact["file"].as_str().unwrap())
        .collect();
    let names: std::collections::BTreeSet<&str> = generated.keys().map(String::as_str).collect();
    assert_eq!(
        names.difference(&attributed).collect::<Vec<_>>(),
        Vec::<&&str>::new(),
        "generated but not listed with this generator in the manifest"
    );
    assert_eq!(
        attributed.difference(&names).collect::<Vec<_>>(),
        Vec::<&&str>::new(),
        "listed with this generator in the manifest but not generated"
    );
    // Every unreadable or changed file is listed at once; only a changed one
    // calls for regeneration.
    let mut unreadable = Vec::new();
    let mut stale = Vec::new();
    for (name, bytes) in &generated {
        match std::fs::read(dir.join(name)) {
            Err(error) => unreadable.push(format!("{name}: {error}")),
            Ok(committed) if committed != *bytes => stale.push(name.as_str()),
            Ok(_) => {}
        }
    }
    assert_eq!(
        (unreadable, stale),
        (Vec::<String>::new(), Vec::<&str>::new()),
        "committed files that cannot be read (not a reason to regenerate), then committed \
         bytes that differ from the generator's. If the generator changed, run \
         regenerate_path_fixtures, review the binaries and update the manifest (docs/testing.md#fixtures); \
         first rule out a checkout that rewrote line endings, or another generator in \
         regenerate_cli_fixtures writing the same name"
    );
    // The issuers outside each PE, taken from what was just checked.
    let witnesses: Vec<Certificate> = ["root", "issuer", "upper", "other-root"]
        .iter()
        .map(|label| {
            let name = format!("path-{label}.der");
            let der = generated
                .get(&name)
                .unwrap_or_else(|| panic!("the generator no longer writes {name}"));
            Certificate::from_der(der).unwrap()
        })
        .collect();
    let pes: Vec<(&str, &Vec<u8>)> = generated
        .iter()
        .filter(|(name, _)| name.ends_with(".exe"))
        .map(|(name, bytes)| (name.as_str(), bytes))
        .collect();
    assert!(!pes.is_empty());
    for (filename, bytes) in pes {
        // Reduced-policy verification is evidence only of container/CMS integrity.
        let integrity = verify::verify_pe(bytes, &verify::VerifyOptions::integrity_only(NOW));
        // PATH-013 and PATH-014 judge path certificates only, and the report
        // marks an extension it cannot decode, so every fixture verifies.
        if let Err(error) = integrity {
            panic!("{filename}: {error:?}");
        }
        let pe = pe::Pe::parse(bytes).unwrap();
        let envelopes = pe.certificates().unwrap();
        let sd = cms::SignedData::parse(envelopes[0]).unwrap();
        for cert in &sd.certs {
            let valid = sd.certs.iter().chain(&witnesses).any(|issuer| {
                cert.tbs_certificate.issuer == issuer.tbs_certificate.subject
                    && crypto::verify_spki(
                        &issuer
                            .tbs_certificate
                            .subject_public_key_info
                            .to_der()
                            .unwrap(),
                        crypto::Hash::Sha256,
                        cert.signature_algorithm.oid.as_bytes(),
                        &cert.tbs_certificate.to_der().unwrap(),
                        cert.signature.as_bytes().unwrap(),
                    )
                    .is_ok()
            });
            assert!(
                valid,
                "{filename}: certificate signature must be valid before exercising the path checks"
            );
        }
    }
}

fn committed(name: &str) -> Vec<u8> {
    let dir =
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/fixtures");
    std::fs::read(dir.join(name)).unwrap()
}

fn committed_certificate(name: &str) -> Certificate {
    use ::der::Decode;
    Certificate::from_der(&committed(name)).unwrap()
}

/// The first embedded certificate issued by `issuer` in a committed PE.
fn embedded(name: &str, issuer: &Certificate) -> Certificate {
    let signed = committed(name);
    let pe = pe::Pe::parse(&signed).unwrap();
    let sd = cms::SignedData::parse(pe.certificates().unwrap()[0]).unwrap();
    sd.certs
        .iter()
        .find(|c| c.tbs_certificate.issuer == issuer.tbs_certificate.subject)
        .unwrap()
        .clone()
}

fn extension_value(cert: &Certificate, oid: &str) -> Vec<u8> {
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == oid)
        .unwrap()
        .extn_value
        .as_bytes()
        .to_vec()
}

/// PATH-014's cases rest on each fixture changing one certificate so that
/// it carries exactly one extension twice, and the other certificate
/// carrying none. The two instances are equal (so each decodes as the single
/// one did), except those of the unfamiliar extension, which nothing decodes
/// and which differ.
#[test]
fn the_repeated_extension_cases_rest_on_one_repeat_in_one_certificate() {
    let (root, issuer) = (
        committed_certificate("path-root.der"),
        committed_certificate("path-issuer.der"),
    );
    let repeats = |cert: &Certificate| {
        let extensions = cert.tbs_certificate.extensions.as_ref().unwrap();
        let mut repeated = Vec::new();
        for (index, extension) in extensions.iter().enumerate() {
            if let Some(first) = extensions[..index]
                .iter()
                .find(|e| e.extn_id == extension.extn_id)
            {
                let unfamiliar = extension.extn_id.to_string() == "1.2.3.4.5";
                assert_eq!(first == extension, !unfamiliar);
                repeated.push(extension.extn_id.to_string());
            }
        }
        repeated
    };
    for (who, label, oid) in REPEATED_EXTENSIONS {
        let name = format!("bad-path-{who}-repeated-{label}.exe");
        let (leaf, ca) = (embedded(&name, &issuer), embedded(&name, &root));
        let (changed, other) = if who == "leaf" {
            (&leaf, &ca)
        } else {
            (&ca, &leaf)
        };
        assert_eq!(repeats(changed), [oid], "{name}");
        assert!(repeats(other).is_empty(), "{name}");
    }
    // The candidate offered first repeats; the second is the committed issuer.
    let first = embedded("good-path-ca-repeated-first.exe", &root);
    assert_eq!(repeats(&first), ["2.5.29.14"]);
    assert_eq!(
        embedded("bad-path-ca-repeated-ski.exe", &root),
        first,
        "the same repeating intermediate"
    );
    // The same for the subjectAltName webpki rejects, an extension the
    // certificate report does not decode.
    let first = embedded("good-path-ca-repeated-san-first.exe", &root);
    assert_eq!(repeats(&first), ["2.5.29.17"]);
    assert_eq!(embedded("bad-path-ca-repeated-san.exe", &root), first);
    // It is the committed issuer with one subjectAltName added twice, offered
    // before the committed issuer itself.
    let mut unchanged = first.tbs_certificate.clone();
    unchanged
        .extensions
        .as_mut()
        .unwrap()
        .retain(|e| e.extn_id.to_string() != "2.5.29.17");
    assert_eq!(unchanged, issuer.tbs_certificate);
    let signed = committed("good-path-ca-repeated-san-first.exe");
    let pe = pe::Pe::parse(&signed).unwrap();
    let sd = cms::SignedData::parse(pe.certificates().unwrap()[0]).unwrap();
    assert_eq!(sd.certs[1..], [first.clone(), issuer.clone()]);
    // The CA on no path repeats its subjectAltName, and the signer's issuer
    // is neither it nor any other embedded certificate.
    let leaf = committed_certificate("path-leaf.der");
    let signed = committed("bad-path-unrelated-repeated-issuer.exe");
    let pe = pe::Pe::parse(&signed).unwrap();
    let sd = cms::SignedData::parse(pe.certificates().unwrap()[0]).unwrap();
    assert!(
        sd.certs
            .iter()
            .all(|c| c.tbs_certificate.subject != leaf.tbs_certificate.issuer)
    );
    let dangling = embedded("bad-path-unrelated-repeated-issuer.exe", &root);
    assert_eq!(repeats(&dangling), ["2.5.29.17"]);
    // The signer is the committed leaf, and the only other certificate is the
    // one the CA issued, which repeats nothing.
    assert_eq!(sd.certs.len(), 3);
    assert_eq!(sd.certs[0], leaf);
    let stranger = embedded("bad-path-unrelated-repeated-issuer.exe", &dangling);
    assert!(repeats(&stranger).is_empty());
    // With both defects, the subjectKeyIdentifier that does not decode sits
    // before the repeated authorityKeyIdentifier, so a scan that reported
    // the first defect it met would report it instead.
    for who in BOTH_DEFECTS {
        let name = format!("bad-path-{who}-repeated-and-malformed.exe");
        let changed = embedded(&name, if who == "leaf" { &issuer } else { &root });
        assert_eq!(repeats(&changed), ["2.5.29.35"], "{name}");
        let extensions = changed.tbs_certificate.extensions.as_ref().unwrap();
        let position = |oid: &str| {
            extensions
                .iter()
                .rposition(|e| e.extn_id.to_string() == oid)
                .unwrap()
        };
        assert!(position("2.5.29.14") < position("2.5.29.35"), "{name}");
        assert_eq!(
            extension_value(&changed, "2.5.29.14"),
            MALFORMED_VALUE,
            "{name}"
        );
        // Otherwise it is the committed certificate: drop the copy and
        // restore the subjectKeyIdentifier.
        let committed = if who == "leaf" { &leaf } else { &issuer };
        let mut restored = changed.tbs_certificate.clone();
        let extensions = restored.extensions.as_mut().unwrap();
        assert_eq!(extensions.pop().unwrap().extn_id.to_string(), "2.5.29.35");
        let ski = extensions
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.14")
            .unwrap();
        ski.extn_value = OctetString::new(extension_value(committed, "2.5.29.14")).unwrap();
        assert_eq!(&restored, &committed.tbs_certificate, "{name}");
        // The other certificate is the committed one.
        if who == "leaf" {
            assert_eq!(embedded(&name, &root), issuer, "{name}");
        } else {
            assert_eq!(embedded(&name, &issuer), leaf, "{name}");
        }
    }
}

/// A committed CRL is signed by `issuer` over its committed TBS bytes (as
/// production verifies them), carries exactly this critical
/// issuingDistributionPoint value or none, and revokes exactly these serials.
fn assert_crl(name: &str, issuer: &Certificate, scope: Option<&[u8]>, revoked: &[u32]) {
    use ::der::Decode;
    use x509_cert::crl::CertificateList;
    let bytes = committed(name);
    let crl = CertificateList::from_der(&bytes).unwrap();
    let tbs = &crl.tbs_cert_list;
    let signed = der::one(&bytes, 0x30).unwrap().children().unwrap()[0].full;
    assert_eq!(tbs.issuer, issuer.tbs_certificate.subject, "{name}");
    crypto::verify_spki(
        &issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap(),
        crypto::Hash::Sha256,
        crl.signature_algorithm.oid.as_bytes(),
        signed,
        crl.signature.as_bytes().unwrap(),
    )
    .unwrap();
    let idp = tbs
        .crl_extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == "2.5.29.28");
    assert_eq!(idp.map(|e| e.critical), scope.map(|_| true), "{name}");
    assert_eq!(idp.map(|e| e.extn_value.as_bytes()), scope, "{name}");
    let serials: Vec<_> = tbs
        .revoked_certificates
        .iter()
        .flatten()
        .map(|r| r.serial_number.clone())
        .collect();
    let expected: Vec<_> = revoked.iter().map(|s| SerialNumber::from(*s)).collect();
    assert_eq!(serials, expected, "{name}");
}

#[test]
fn crl_partitioned_crls_are_signed_by_the_issuer_and_scoped() {
    let issuer = committed_certificate("path-issuer.der");
    let leaf = embedded("crl-leaf-crl-dp.exe", &issuer);
    assert_eq!(extension_value(&leaf, "2.5.29.31"), listed_points());
    assert_eq!(
        leaf.tbs_certificate.serial_number,
        SerialNumber::from(SCOPED_LEAF_SERIAL)
    );
    for (label, uri, revoked) in PARTITIONS {
        // The whole IDP value: one fullName URI, no scope flags or reasons.
        assert_crl(
            &format!("crl-issuer-idp-{label}.crl"),
            &issuer,
            Some(&crl_applicability::idp_named_point(uri)),
            if revoked { &[SCOPED_LEAF_SERIAL] } else { &[] },
        );
    }
}

#[test]
fn the_shared_point_cases_rest_on_the_fixtures_certificates() {
    let root = committed_certificate("path-root.der");
    let issuer = committed_certificate("path-issuer.der");
    // CRL-050 and CRL-051 rest on two certificates of two issuers listing one
    // point, and their cases name the certificates by hash: signer first, then
    // its issuer.
    let (signer, shared) = (
        embedded("crl-chain-shared-crl-dp.exe", &issuer),
        embedded("crl-chain-shared-crl-dp.exe", &root),
    );
    for cert in [&signer, &shared] {
        assert_eq!(extension_value(cert, "2.5.29.31"), one_point(LISTED_POINT));
    }
    assert_eq!(
        signer.tbs_certificate.serial_number,
        SerialNumber::from(SCOPED_LEAF_SERIAL)
    );
    assert_eq!(
        shared.tbs_certificate.serial_number,
        SerialNumber::from(ISSUER_SERIAL)
    );
    let cases: serde_json::Value = serde_json::from_slice(&committed("../cases.json")).unwrap();
    let hash = |cert: &Certificate| {
        use ::der::Encode;
        use sha2::Digest;
        sha2::Sha256::digest(cert.to_der().unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let (signer_hash, shared_hash) = (hash(&signer), hash(&shared));
    fn collect(value: &serde_json::Value, out: &mut std::collections::BTreeSet<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    if key == "certificate_sha256" {
                        out.insert(value.as_str().unwrap().to_owned());
                    } else if key == "crl_certificate_responses" {
                        out.extend(value.as_object().unwrap().keys().cloned());
                    } else {
                        collect(value, out);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                items.iter().for_each(|item| collect(item, out));
            }
            _ => {}
        }
    }
    let mut named = Vec::new();
    for case in cases["cases"].as_array().unwrap() {
        if case["input"] != "crl-chain-shared-crl-dp.exe" {
            continue;
        }
        // Every certificate hash a case names (`certificate_sha256` values and
        // `crl_certificate_responses` keys) is one of the two certificates',
        // so a stale hash fails here rather than as a mismatch.
        let mut hashes = std::collections::BTreeSet::new();
        collect(case, &mut hashes);
        for found in &hashes {
            assert!(
                *found == signer_hash || *found == shared_hash,
                "{}: {found}",
                case["id"]
            );
        }
        assert!(!hashes.is_empty(), "{}", case["id"]);
        named.push(case["id"].as_str().unwrap().to_owned());
    }
    // Which certificate each case answers by certificate: the first case the
    // signer's (its point is then left unused), the second the issuer
    // certificate's (the signer's point is answered by URL).
    let keys = |id: &str| -> Vec<String> {
        let case = cases["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == id)
            .unwrap();
        case["crl_certificate_responses"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    };
    assert_eq!(
        keys("crl-050-a-point-left-unused-is-offered-for-a-certificate-of-another-issuer"),
        core::slice::from_ref(&signer_hash)
    );
    assert_eq!(
        keys("crl-050-a-certificate-whose-point-another-used-is-still-asked"),
        core::slice::from_ref(&shared_hash)
    );
    // The shared point is the one the cases script, and the crl-051 cases script
    // no answer for it: they are about a point that fails.
    for case in cases["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if case["input"] != "crl-chain-shared-crl-dp.exe" {
            continue;
        }
        // The entry a case names is its id's: CRL-050 or CRL-051.
        assert_eq!(
            case["decision"].as_str().unwrap(),
            id.splitn(3, '-')
                .take(2)
                .collect::<Vec<_>>()
                .join("-")
                .to_uppercase(),
            "{id}"
        );
        let responses = case["crl_responses"].as_object().unwrap();
        if id.starts_with("crl-051-") {
            assert!(responses.is_empty(), "{id}");
            assert!(case.get("crl_certificate_responses").is_none(), "{id}");
        }
        // The URL answers each case rests on: both crl-050 cases script the
        // shared point, the crl-051 cases script none and differ in the error.
        let errors = case.get("crl_errors").and_then(|e| e.as_object());
        match id {
            "crl-050-a-point-left-unused-is-offered-for-a-certificate-of-another-issuer"
            | "crl-050-a-certificate-whose-point-another-used-is-still-asked" => {
                assert_eq!(responses.len(), 1, "{id}");
                assert!(errors.is_none(), "{id}");
                // The pairing each case rests on: the first leaves the
                // signer's point unused, so the root CRL comes from the URL
                // and the issuer's CRL from the answer by certificate; the
                // second is the reverse, and the issuer certificate's scripted
                // answer names the shared point, which the runner accepts only
                // if that certificate's request carried it (CRL-050).
                let (url_file, certificate_file) = if id.contains("unused") {
                    ("path-root.crl", "path-issuer.crl")
                } else {
                    ("path-issuer.crl", "path-root.crl")
                };
                assert_eq!(responses[LISTED_POINT], url_file, "{id}");
                let answers = case["crl_certificate_responses"].as_object().unwrap();
                assert_eq!(answers.len(), 1, "{id}");
                let answer = answers.values().next().unwrap();
                if id.contains("unused") {
                    assert_eq!(answer, certificate_file, "{id}");
                } else {
                    assert_eq!(answer["crls"][0]["file"], certificate_file, "{id}");
                    assert_eq!(answer["crls"][0]["url"], LISTED_POINT, "{id}");
                }
            }
            "crl-051-a-failed-point-is-asked-and-recorded-for-each-certificate" => {
                assert!(errors.is_none(), "{id}");
            }
            "crl-051-a-denied-point-is-recorded-for-each-certificate" => {
                assert_eq!(errors.unwrap().len(), 1, "{id}");
                assert_eq!(errors.unwrap()[LISTED_POINT], "denied", "{id}");
            }
            _ => panic!("{id} is not a known case of the shared-point fixture"),
        }
        for url in responses.keys().chain(
            case.get("crl_errors")
                .iter()
                .flat_map(|e| e.as_object().unwrap().keys()),
        ) {
            assert_eq!(url, LISTED_POINT, "{id}");
        }
    }
    // The manifest lists exactly these cases for the fixture.
    let manifest: serde_json::Value = serde_json::from_slice(&committed("manifest.json")).unwrap();
    let artifact = manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["file"] == "crl-chain-shared-crl-dp.exe")
        .unwrap();
    let listed = artifact["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let described = artifact["description"].as_str().unwrap();
    assert!(described.contains(&signer_hash) && described.contains(&shared_hash));
    let (named, listed): (std::collections::BTreeSet<_>, std::collections::BTreeSet<_>) =
        (named.into_iter().collect(), listed.into_iter().collect());
    assert_eq!(named, listed);
    assert_eq!(
        named,
        [
            "crl-050-a-point-left-unused-is-offered-for-a-certificate-of-another-issuer",
            "crl-050-a-certificate-whose-point-another-used-is-still-asked",
            "crl-051-a-failed-point-is-asked-and-recorded-for-each-certificate",
            "crl-051-a-denied-point-is-recorded-for-each-certificate",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn crl_distribution_point_forms_are_signed_and_encoded() {
    let root = committed_certificate("path-root.der");
    let issuer = committed_certificate("path-issuer.der");
    for (label, serial, points) in point_forms() {
        let name = format!("crl-leaf-crl-dp-{label}.exe");
        let leaf = embedded(&name, &issuer);
        assert_eq!(extension_value(&leaf, "2.5.29.31"), points, "{name}");
        assert_eq!(
            leaf.tbs_certificate.serial_number,
            SerialNumber::from(serial),
            "{name}"
        );
    }
    for (label, scope) in scope_forms() {
        assert_crl(
            &format!("crl-issuer-idp-{label}.crl"),
            &issuer,
            Some(&scope),
            &[],
        );
    }
    let pointed = embedded("crl-ca-crl-dp.exe", &root);
    assert_eq!(
        extension_value(&pointed, "2.5.29.31"),
        one_point(ISSUER_POINT)
    );
    assert_eq!(
        pointed.tbs_certificate.serial_number,
        SerialNumber::from(ISSUER_SERIAL)
    );
    for (label, scope) in root_scope_forms() {
        assert_crl(
            &format!("crl-path-root-idp-{label}.crl"),
            &root,
            Some(&scope),
            &[],
        );
    }
    assert_crl(
        "crl-path-root-revoked-issuer.crl",
        &root,
        None,
        &[ISSUER_SERIAL],
    );
    assert_crl(
        "crl-path-other-root-revoked-cross.crl",
        &committed_certificate("path-other-root.der"),
        None,
        &[ISSUER_SERIAL],
    );
}

/// What a decoded DistributionPointName holds, read with x509-cert's typed
/// decoder rather than the hand-written encoders above.
#[derive(Debug, PartialEq)]
enum NameForm {
    Uris(Vec<String>),
    Dns(String),
    /// A directoryName with this many RDNs.
    Directory(usize),
    Relative,
}

fn name_form(name: &Option<x509_cert::ext::pkix::name::DistributionPointName>) -> NameForm {
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
    let names = match name.as_ref().unwrap() {
        DistributionPointName::NameRelativeToCRLIssuer(_) => return NameForm::Relative,
        DistributionPointName::FullName(names) => names,
    };
    match names.as_slice() {
        [GeneralName::DnsName(dns)] => NameForm::Dns(dns.to_string()),
        [GeneralName::DirectoryName(name)] => NameForm::Directory(name.0.len()),
        names => NameForm::Uris(
            names
                .iter()
                .map(|name| match name {
                    GeneralName::UniformResourceIdentifier(uri) => uri.to_string(),
                    other => panic!("unexpected general name {other:?}"),
                })
                .collect(),
        ),
    }
}

fn uris(values: &[&str]) -> NameForm {
    NameForm::Uris(values.iter().map(|v| v.to_string()).collect())
}

#[test]
fn crl_distribution_point_forms_decode_as_intended() {
    use ::der::Decode;
    use x509_cert::ext::pkix::{CrlDistributionPoints, crl::dp::IssuingDistributionPoint};
    let issuer = committed_certificate("path-issuer.der");
    // Per point: its name, and whether it has reasons or a cRLIssuer.
    let points = |label: &str| -> Vec<(NameForm, bool, bool)> {
        let leaf = embedded(&format!("crl-leaf-crl-dp-{label}.exe"), &issuer);
        CrlDistributionPoints::from_der(&extension_value(&leaf, "2.5.29.31"))
            .unwrap()
            .0
            .iter()
            .map(|p| {
                (
                    name_form(&p.distribution_point),
                    p.reasons.is_some(),
                    p.crl_issuer.is_some(),
                )
            })
            .collect()
    };
    let [c, d, e] = MULTI_POINTS;
    assert_eq!(
        points("multi"),
        [(uris(&[c]), false, false), (uris(&[d, e]), false, false)]
    );
    assert_eq!(
        points("dns"),
        [(NameForm::Dns("crl.invalid".into()), false, false)]
    );
    assert_eq!(points("relative"), [(NameForm::Relative, false, false)]);
    assert_eq!(points("reasons"), [(uris(&[LISTED_POINT]), true, false)]);
    assert_eq!(points("crl-issuer"), [(uris(&[LISTED_POINT]), false, true)]);
    // Per CRL: its name, then onlyContainsUserCerts and onlyContainsCACerts.
    let scope = |file: &str| -> (NameForm, bool, bool) {
        use x509_cert::crl::CertificateList;
        let crl = CertificateList::from_der(&committed(file)).unwrap();
        let value = crl
            .tbs_cert_list
            .crl_extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id.to_string() == "2.5.29.28")
            .unwrap()
            .extn_value
            .as_bytes()
            .to_vec();
        let idp = IssuingDistributionPoint::from_der(&value).unwrap();
        assert!(
            idp.only_some_reasons.is_none() && !idp.indirect_crl,
            "{file}"
        );
        (
            name_form(&idp.distribution_point),
            idp.only_contains_user_certs,
            idp.only_contains_ca_certs,
        )
    };
    let issuer_scope = |label: &str| scope(&format!("crl-issuer-idp-{label}.crl"));
    assert_eq!(
        issuer_scope("match-user"),
        (uris(&[LISTED_POINT]), true, false)
    );
    assert_eq!(
        issuer_scope("match-ca"),
        (uris(&[LISTED_POINT]), false, true)
    );
    assert_eq!(
        issuer_scope("two-names"),
        (uris(&[OTHER_POINT, LISTED_POINT]), false, false)
    );
    assert_eq!(issuer_scope("second-point"), (uris(&[e]), false, false));
    assert_eq!(
        issuer_scope("dns"),
        (NameForm::Dns("crl.invalid".into()), false, false)
    );
    assert_eq!(issuer_scope("relative"), (NameForm::Relative, false, false));
    // The issuer's single RDN followed by CN=sec10.
    assert_eq!(
        issuer_scope("relative-expanded"),
        (NameForm::Directory(2), false, false)
    );
    assert_eq!(
        scope("crl-path-root-idp-ca.crl"),
        (uris(&[ISSUER_POINT]), false, true)
    );
    assert_eq!(
        scope("crl-path-root-idp-user.crl"),
        (uris(&[ISSUER_POINT]), true, false)
    );
    // The intermediate lists the point; its signer is the plain PATH-T001 leaf.
    let root = committed_certificate("path-root.der");
    let pointed = embedded("crl-ca-crl-dp.exe", &root);
    let listed = CrlDistributionPoints::from_der(&extension_value(&pointed, "2.5.29.31")).unwrap();
    assert_eq!(listed.0.len(), 1);
    assert_eq!(
        name_form(&listed.0[0].distribution_point),
        uris(&[ISSUER_POINT])
    );
    let signer = embedded("crl-ca-crl-dp.exe", &issuer);
    assert_eq!(
        signer.tbs_certificate.serial_number,
        SerialNumber::from(120u32)
    );
    assert!(
        signer
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .all(|e| e.extn_id.to_string() != "2.5.29.31")
    );
}

/// PATH-T016: the rejection PATH-T010 kept. When the owner decides, this test
/// and the check in `TrustStore::chain_report` change together.
#[test]
fn a_path_to_a_root_whose_reported_extension_does_not_decode_still_fails() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures");
    let bytes = std::fs::read(dir.join("good-path-basic.exe")).unwrap();
    let root_key = key(40);
    let verify_with = |root: &Certificate| {
        let mut store = crate::TrustStore::default();
        store.add_roots(&root.to_der().unwrap()).unwrap();
        let options = verify::VerifyOptions::trusted_with_revocation(
            &store,
            NOW,
            verify::RevocationPolicy::Disabled,
        );
        verify::verify_pe(&bytes, &options)
    };
    let root = certificate("root", 100, &root_key, "root", &root_key, true);
    verify_with(&root).unwrap();
    for oid in ["2.5.29.19", "2.5.29.15", "2.5.29.37"] {
        let mut changed = root.clone();
        extension(&mut changed, oid, false, Some(MALFORMED_VALUE.to_vec()));
        sign(&mut changed, &root_key);
        let error = verify_with(&changed).unwrap_err();
        assert_eq!(
            error.code,
            crate::domain::ErrorCode::CertificateChainInvalid,
            "{oid}"
        );
        assert!(error.message.contains(oid), "{oid}: {}", error.message);
        assert!(error.details.is_empty(), "{oid}");
    }
    // A root that repeats one of the three never gets that far: webpki
    // refuses it as an anchor when the roots are loaded.
    for oid in ["2.5.29.19", "2.5.29.15", "2.5.29.37"] {
        let mut changed = root.clone();
        repeat_extension(&mut changed, oid);
        sign(&mut changed, &root_key);
        let mut store = crate::TrustStore::default();
        assert!(
            store.add_roots(&changed.to_der().unwrap()).is_err(),
            "{oid}"
        );
    }
    // A root is otherwise not judged: a malformed subjectKeyIdentifier passes.
    let mut changed = root.clone();
    extension(
        &mut changed,
        "2.5.29.14",
        false,
        Some(MALFORMED_VALUE.to_vec()),
    );
    sign(&mut changed, &root_key);
    verify_with(&changed).unwrap();
}

/// A certificate with two defects lists them in the report's own order.
#[test]
fn undecoded_extensions_are_listed_basic_constraints_first() {
    use crate::domain::{CertificateReport, UndecodedReason};
    let mut cert = committed_certificate("path-issuer.der");
    extension(
        &mut cert,
        "2.5.29.37",
        false,
        Some(MALFORMED_VALUE.to_vec()),
    );
    repeat_extension(&mut cert, "2.5.29.19");
    let report = CertificateReport::parse(&cert).unwrap();
    let listed: Vec<_> = report
        .undecoded_extensions
        .iter()
        .map(|u| (u.oid.as_str(), u.reason))
        .collect();
    assert_eq!(
        listed,
        [
            ("2.5.29.19", UndecodedReason::RepeatedExtension),
            ("2.5.29.37", UndecodedReason::MalformedExtension),
        ]
    );
    assert!(report.basic_constraints.is_none() && report.extended_key_usage.is_none());
    assert!(report.key_usage.is_some());
    // Only the three extensions the report decodes are ever listed (PATH-015).
    // `TrustStore::chain_report` rests on it: a root with any other malformed
    // extension must stay unjudged (PATH-011, PATH-T016).
    let mut cert = committed_certificate("path-issuer.der");
    for (_, oid) in MALFORMED_EXTENSIONS {
        extension(&mut cert, oid, false, Some(MALFORMED_VALUE.to_vec()));
    }
    extension(
        &mut cert,
        "1.2.3.4.5",
        false,
        Some(MALFORMED_VALUE.to_vec()),
    );
    repeat_extension(&mut cert, "1.2.3.4.5");
    let report = CertificateReport::parse(&cert).unwrap();
    let listed: Vec<_> = report
        .undecoded_extensions
        .iter()
        .map(|u| u.oid.as_str())
        .collect();
    assert_eq!(listed, ["2.5.29.19", "2.5.29.15", "2.5.29.37"]);
}
