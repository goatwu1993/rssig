//! SEC-06 maintenance builders: public deterministic keys, inert signed PE files.
use super::*;
use ::der::asn1::{ObjectIdentifier, OctetString};
use x509_cert::ext::{Extension, pkix::BasicConstraints};

/// SEC-10 distribution-point fixtures. First the single-point signer: the point
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
/// The point the `sec10-ca-crl-dp` intermediate lists.
const ISSUER_POINT: &str = "http://crl.invalid/sec10-issuer.crl";
/// The SEC-06 issuer certificate's serial, revoked by
/// `sec10-sec06-root-revoked-issuer.crl`.
const ISSUER_SERIAL: u32 = 110;
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

/// A uniformResourceIdentifier GeneralName.
fn uri(value: &str) -> Vec<u8> {
    tlv(0x86, value.as_bytes())
}

/// `[0] distributionPoint` holding a fullName with these GeneralNames.
fn full_name(names: &[Vec<u8>]) -> Vec<u8> {
    tlv(0xa0, &tlv(0xa0, &names.concat()))
}

/// `[0] distributionPoint` holding nameRelativeToCRLIssuer `CN=sec10`.
fn relative_name() -> Vec<u8> {
    let cn = seq(&[tlv(6, &[0x55, 4, 3]), tlv(0x0c, b"sec10")]);
    tlv(0xa0, &tlv(0xa1, &cn))
}

/// A directoryName GeneralName: the SEC-06 issuer's DN followed by `CN=sec10`.
fn expanded_relative_name() -> Vec<u8> {
    let issuer = name("issuer").to_der().unwrap();
    let cn = seq(&[tlv(6, &[0x55, 4, 3]), tlv(0x0c, b"sec10")]);
    let mut rdns = der::one(&issuer, 0x30).unwrap().body.to_vec();
    rdns.extend(tlv(0x31, &cn));
    tlv(0xa4, &tlv(0x30, &rdns))
}

/// SEC-10 signers with other cRLDistributionPoints forms, as (label, serial,
/// extension value). Each is `sec10-leaf-crl-dp-{label}.exe`.
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

/// SEC-10 issuer CRLs with other issuingDistributionPoint forms, as (label,
/// extension value). Each is `sec10-issuer-idp-{label}.crl` and revokes nothing.
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

/// SEC-10 SEC-06 root CRLs naming `ISSUER_POINT` with a role scope, as (label,
/// extension value). Each is `sec10-sec06-root-idp-{label}.crl`.
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
fn write_pe(dir: &std::path::Path, label: &str, leaf: &Certificate, candidates: &[Certificate]) {
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
    std::fs::write(dir.join(format!("{label}.exe")), attach(base, &cms, true)).unwrap();
}
fn write_crl(dir: &std::path::Path, issuer: &Certificate, issuer_key: &SigningKey, label: &str) {
    write_crl_with(dir, issuer, issuer_key, label, false, None);
}
/// With `key_identified`, the CRL carries an authorityKeyIdentifier naming
/// the issuer's subjectKeyIdentifier.
fn write_crl_with(
    dir: &std::path::Path,
    issuer: &Certificate,
    issuer_key: &SigningKey,
    label: &str,
    key_identified: bool,
    revoked: Option<u32>,
) {
    write_crl_at(
        dir,
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
    dir: &std::path::Path,
    issuer: &Certificate,
    issuer_key: &SigningKey,
    label: &str,
    key_identified: bool,
    revoked: Option<u32>,
    window: (u64, u64),
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
            .find(|e| e.extn_id.to_string() == "2.5.29.14")
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
        issuer: issuer.tbs_certificate.subject.clone(),
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
    std::fs::write(
        dir.join(format!("sec06-{label}.crl")),
        crl.to_der().unwrap(),
    )
    .unwrap();
}
/// Write a fresh SEC-10 CRL from `issuer` with this critical
/// issuingDistributionPoint value, if any, revoking `revoked`, if any.
fn write_scoped_crl(
    dir: &std::path::Path,
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
    std::fs::write(dir.join(file), crl).unwrap();
}
fn write_cert(dir: &std::path::Path, label: &str, cert: &Certificate) {
    std::fs::write(
        dir.join(format!("sec06-{label}.der")),
        cert.to_der().unwrap(),
    )
    .unwrap();
}
pub(super) fn write(dir: &std::path::Path) {
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
        write_cert(dir, label, cert);
        write_crl(dir, cert, key, label);
    }
    write_cert(dir, "leaf", &leaf);
    write_pe(dir, "good-sec06-basic", &leaf, core::slice::from_ref(&ca));
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
            // cRLSign but no keyCertSign: CRL checking must not mask the CA policy.
            "ca-ku" => extension(&mut changed, "2.5.29.15", true, Some(tlv(3, &[1, 2]))),
            "ca-no-ku" => extension(&mut changed, "2.5.29.15", true, None),
            _ => unreachable!(),
        }
        sign(&mut changed, &root_key);
        let good = matches!(label, "ca-noncritical" | "ca-no-ku" | "ca-good-eku");
        if good {
            write_cert(dir, label, &changed);
        }
        if label == "ca-ku" {
            write_pe(
                dir,
                "good-sec06-ca-ku-first",
                &leaf,
                &[changed.clone(), ca.clone()],
            );
            write_pe(
                dir,
                "good-sec06-ca-ku-last",
                &leaf,
                &[ca.clone(), changed.clone()],
            );
        }
        write_pe(
            dir,
            &format!("{}-sec06-{label}", if good { "good" } else { "bad" }),
            &leaf,
            &[changed],
        );
    }
    // SEC-10: the issuer signs certificates and the CRL with the same key; only
    // its KeyUsage decides whether that CRL may be used.
    let mut usages = Vec::new();
    for (label, bits) in [("ca-no-crl-sign", [2u8, 0x04]), ("ca-crl-sign", [1, 0x06])] {
        let mut changed = ca.clone();
        extension(&mut changed, "2.5.29.15", true, Some(tlv(3, &bits)));
        sign(&mut changed, &root_key);
        write_pe(
            dir,
            &format!("sec10-{label}"),
            &leaf,
            core::slice::from_ref(&changed),
        );
        usages.push(changed);
    }
    // The candidate without cRLSign comes first; path building must fall back.
    write_pe(dir, "sec10-ca-crl-sign-fallback", &leaf, &usages);
    // SEC-10: the same root key and name as a configured anchor whose KeyUsage
    // lacks cRLSign; anchors are keys, so sec06-root.crl is still usable.
    let mut anchor = root.clone();
    extension(&mut anchor, "2.5.29.15", true, Some(tlv(3, &[2, 0x04])));
    sign(&mut anchor, &root_key);
    std::fs::write(
        dir.join("sec10-root-no-crl-sign.der"),
        anchor.to_der().unwrap(),
    )
    .unwrap();
    // SEC-10: a leaf with its own serial that lists one CRL distribution point,
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
    write_pe(
        dir,
        "sec10-leaf-crl-dp",
        &scoped,
        core::slice::from_ref(&ca),
    );
    for (label, uri, revoked) in PARTITIONS {
        write_scoped_crl(
            dir,
            &format!("sec10-issuer-idp-{label}.crl"),
            (&ca, &ca_key),
            Some(crl_applicability::idp_named_point(uri)),
            revoked.then_some(&scoped),
        );
    }
    // SEC-10: an expired partition for another point. It cannot decide the
    // signer, so its age must not either.
    let other_scope = Extension {
        extn_id: "2.5.29.28".parse().unwrap(),
        critical: true,
        extn_value: OctetString::new(crl_applicability::idp_named_point(OTHER_POINT)).unwrap(),
    };
    std::fs::write(
        dir.join("sec10-issuer-idp-other-expired.crl"),
        crl_applicability::crl_full(
            &ca.tbs_certificate.subject.to_string(),
            &ca_key,
            NOW - 200,
            Some(NOW - 1),
            None,
            vec![other_scope],
            None,
        ),
    )
    .unwrap();
    // SEC-10: other distribution-point forms on the signer and on issuer CRLs.
    for (label, serial, points) in point_forms() {
        let mut signer = certificate("publisher", serial, &leaf_key, "issuer", &ca_key, false);
        extension(&mut signer, "2.5.29.31", false, Some(points));
        sign(&mut signer, &ca_key);
        write_pe(
            dir,
            &format!("sec10-leaf-crl-dp-{label}"),
            &signer,
            core::slice::from_ref(&ca),
        );
    }
    for (label, scope) in scope_forms() {
        let file = format!("sec10-issuer-idp-{label}.crl");
        write_scoped_crl(dir, &file, (&ca, &ca_key), Some(scope), None);
    }
    // SEC-10: an intermediate that lists a distribution point, and SEC-06 root
    // CRLs naming it with a CA-only or user-only scope.
    let mut pointed = ca.clone();
    extension(
        &mut pointed,
        "2.5.29.31",
        false,
        Some(one_point(ISSUER_POINT)),
    );
    sign(&mut pointed, &root_key);
    write_pe(
        dir,
        "sec10-ca-crl-dp",
        &leaf,
        core::slice::from_ref(&pointed),
    );
    // SEC-10: both selected certificates list a distribution point, the signer
    // LISTED_POINT and its issuer ISSUER_POINT.
    write_pe(
        dir,
        "sec10-chain-crl-dp",
        &scoped,
        core::slice::from_ref(&pointed),
    );
    for (label, scope) in root_scope_forms() {
        let file = format!("sec10-sec06-root-idp-{label}.crl");
        write_scoped_crl(dir, &file, (&root, &root_key), Some(scope), None);
    }
    // SEC-10: a full root CRL that revokes the intermediate issuer.
    write_scoped_crl(
        dir,
        "sec10-sec06-root-revoked-issuer.crl",
        (&root, &root_key),
        None,
        Some(&ca),
    );
    // SEC-10: a full other-root CRL that revokes the cross certificate (the
    // issuer re-signed by the other root, same serial), so that one candidate
    // path is revoked while the other only lacks a root CRL.
    write_scoped_crl(
        dir,
        "sec10-sec06-other-root-revoked-cross.crl",
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
            write_cert(dir, label, &changed);
        }
        write_pe(
            dir,
            &format!("{}-sec06-{label}", if good { "good" } else { "bad" }),
            &changed,
            &[ca.clone()],
        );
    }
    let mut lower = ca.clone();
    lower.tbs_certificate.issuer = name("upper");
    // Remove the old issuer's AKI when cross-signing; issuer DN/signature bind it.
    extension(&mut lower, "2.5.29.35", false, None);
    sign(&mut lower, &upper_key);
    write_cert(dir, "lower", &lower);
    write_pe(
        dir,
        "good-sec06-pathlen",
        &leaf,
        &[lower.clone(), upper.clone()],
    );
    let mut short = upper.clone();
    bc(&mut short, true, Some(0));
    sign(&mut short, &root_key);
    write_pe(dir, "bad-sec06-pathlen", &leaf, &[lower, short]);
    let mut constrained = ca.clone();
    constraints(
        &mut constrained,
        "allowed.invalid",
        Some("blocked.allowed.invalid"),
    );
    sign(&mut constrained, &root_key);
    write_cert(dir, "constrained", &constrained);
    for (label, host) in [
        ("good", "app.allowed.invalid"),
        ("outside", "outside.invalid"),
        ("excluded", "blocked.allowed.invalid"),
    ] {
        let mut changed = leaf.clone();
        dns(&mut changed, host);
        sign(&mut changed, &ca_key);
        if label == "good" {
            write_cert(dir, &format!("dns-{label}"), &changed);
        }
        write_pe(
            dir,
            &format!(
                "{}-sec06-name-{label}",
                if label == "good" { "good" } else { "bad" }
            ),
            &changed,
            &[constrained.clone()],
        );
    }
    // Same DN, wrong key is not an issuer; test both candidate orders.
    let wrong = certificate("issuer", 111, &key(45), "root", &root_key, true);
    write_pe(
        dir,
        "bad-sec06-wrong-key",
        &leaf,
        core::slice::from_ref(&wrong),
    );
    write_pe(
        dir,
        "good-sec06-wrong-key-first",
        &leaf,
        &[wrong.clone(), ca.clone()],
    );
    write_pe(
        dir,
        "good-sec06-wrong-key-last",
        &leaf,
        &[ca.clone(), wrong],
    );
    let mut cross = ca.clone();
    cross.tbs_certificate.issuer = name("other root");
    extension(&mut cross, "2.5.29.35", false, None);
    sign(&mut cross, &other_key);
    write_cert(dir, "cross", &cross);
    write_pe(
        dir,
        "bad-sec06-cross-untrusted",
        &leaf,
        &[cross.clone(), other.clone()],
    );
    write_pe(
        dir,
        "good-sec06-cross-first",
        &leaf,
        &[cross.clone(), other.clone(), ca.clone()],
    );
    // SEC-10: a cross certificate whose KeyUsage lacks keyCertSign (cRLSign
    // only), first, so that its path fails path policy whatever its CRLs say.
    let mut cross_no_cert_sign = cross.clone();
    extension(
        &mut cross_no_cert_sign,
        "2.5.29.15",
        true,
        Some(tlv(3, &[1, 2])),
    );
    sign(&mut cross_no_cert_sign, &other_key);
    write_pe(
        dir,
        "sec10-sec06-cross-no-cert-sign",
        &leaf,
        &[cross_no_cert_sign, other.clone(), ca.clone()],
    );
    // SEC-16: a self-issued key rollover. The root's name is carried by a
    // second key, certified by the root; the signer is issued under that
    // name by the second key. Two certificates on the path therefore have
    // issuers of the same name and different keys, each with its own CRL.
    let rollover_key = key(45);
    let rollover = certificate("root", 140, &rollover_key, "root", &root_key, true);
    let rolled_leaf = certificate("publisher", 141, &leaf_key, "root", &rollover_key, false);
    write_pe(
        dir,
        "good-sec06-self-issued-rollover",
        &rolled_leaf,
        core::slice::from_ref(&rollover),
    );
    write_crl(dir, &rollover, &rollover_key, "rollover");
    // The same two CRLs, each naming its issuer's key: the case in which
    // OpenSSL, BoringSSL and Bouncy Castle all tell the two issuers apart.
    // SEC-10: the root's CRL, expired: on a cross-certified file the root
    // path's only CRL then needs a refresh while the other path is revoked.
    write_crl_at(
        dir,
        &root,
        &root_key,
        "root-expired",
        false,
        None,
        (NOW - 2000, NOW - 1000),
    );
    // SEC-23: the root's CRL, not yet valid: a CRL a source could replace,
    // named under certificates_with_replaceable_crl rather than as expired.
    write_crl_at(
        dir,
        &root,
        &root_key,
        "root-not-yet-valid",
        false,
        None,
        (NOW + 1000, NOW + 2000),
    );
    write_crl_with(dir, &root, &root_key, "root-akid", true, None);
    write_crl_with(dir, &rollover, &rollover_key, "rollover-akid", true, None);
    // The root key's CRL revoking the rollover certificate, which webpki's
    // confirmation of such a path does not look at.
    write_crl_with(
        dir,
        &root,
        &root_key,
        "root-akid-revoked-rollover",
        true,
        Some(140),
    );
    // SEC-10: an expired cross certificate, first, so that webpki's highest
    // ranked error (expiry) comes from a path other than the one that only
    // lacks a root CRL.
    let mut cross_expired = cross.clone();
    cross_expired.tbs_certificate.validity.not_after = tm(NOW - 1);
    sign(&mut cross_expired, &other_key);
    write_pe(
        dir,
        "sec10-sec06-cross-expired-first",
        &leaf,
        &[cross_expired, other.clone(), ca.clone()],
    );
    write_pe(
        dir,
        "good-sec06-cross-last",
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
        dir,
        "bad-sec06-cycle",
        &leaf,
        &[cycle_a.clone(), cycle_b.clone()],
    );
    write_pe(
        dir,
        "bad-sec06-cycle-reversed",
        &leaf,
        &[cycle_b.clone(), cycle_a.clone()],
    );
    write_pe(
        dir,
        "good-sec06-cycle-escape",
        &leaf,
        &[cycle_a.clone(), cycle_b.clone(), ca.clone()],
    );
    write_pe(
        dir,
        "good-sec06-cycle-escape-reversed",
        &leaf,
        &[ca.clone(), cycle_b, cycle_a],
    );
    // Configured anchors are trusted key/name/constraints, not path certificates.
    let mut expired = root.clone();
    expired.tbs_certificate.validity.not_after = tm(NOW - 1);
    sign(&mut expired, &root_key);
    write_cert(dir, "root-expired", &expired);
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
    write_cert(dir, "root-profile", &profile);
    let mut root_nc = root.clone();
    constraints(&mut root_nc, "allowed.invalid", None);
    sign(&mut root_nc, &root_key);
    write_cert(dir, "root-constrained", &root_nc);
    let mut root_deny = root.clone();
    constraints(&mut root_deny, "elsewhere.invalid", None);
    sign(&mut root_deny, &root_key);
    write_cert(dir, "root-denied", &root_deny);
    let mut named = leaf.clone();
    dns(&mut named, "app.allowed.invalid");
    sign(&mut named, &ca_key);
    write_pe(dir, "good-sec06-root-name", &named, &[ca]);
    use ::der::EncodePem;
    let pem = [
        root_deny.to_pem(::der::pem::LineEnding::LF).unwrap(),
        root_nc.to_pem(::der::pem::LineEnding::LF).unwrap(),
    ]
    .concat();
    std::fs::write(dir.join("sec06-roots-alternative.pem"), pem).unwrap();
}
#[test]
#[ignore = "explicit fixture maintenance; review binaries and update manifest"]
fn regenerate_sec06_fixtures() {
    write(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"));
}

#[test]
fn sec06_policy_fixtures_preserve_image_cms_and_certificate_signatures() {
    use ::der::Decode;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let witnesses: Vec<Certificate> = ["root", "issuer", "upper", "other-root"]
        .iter()
        .map(|label| {
            Certificate::from_der(&std::fs::read(dir.join(format!("sec06-{label}.der"))).unwrap())
                .unwrap()
        })
        .collect();
    let mut count = 0;
    for artifact in manifest["artifacts"].as_array().unwrap() {
        let filename = artifact["file"].as_str().unwrap();
        // SEC-10 variants built here on the SEC-06 chain.
        let sec10 = [
            "sec10-ca-no-crl-sign.exe",
            "sec10-ca-crl-sign.exe",
            "sec10-ca-crl-sign-fallback.exe",
            "sec10-leaf-crl-dp.exe",
            "sec10-ca-crl-dp.exe",
            "sec10-chain-crl-dp.exe",
        ];
        let form = point_forms()
            .iter()
            .any(|(label, ..)| filename == format!("sec10-leaf-crl-dp-{label}.exe"));
        let sec06 = filename.contains("-sec06-") || sec10.contains(&filename) || form;
        if !sec06 || !filename.ends_with(".exe") {
            continue;
        }
        count += 1;
        let bytes = std::fs::read(dir.join(filename)).unwrap();
        // Reduced-policy verification is evidence only of container/CMS integrity.
        verify::verify_pe(&bytes, &verify::VerifyOptions::integrity_only(NOW)).unwrap();
        let pe = pe::Pe::parse(&bytes).unwrap();
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
                "{filename}: certificate signature must be valid before exercising path policy"
            );
        }
    }
    assert_eq!(count, 42 + point_forms().len());
}

fn committed(name: &str) -> Vec<u8> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
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
fn sec10_partitioned_crls_are_signed_by_the_issuer_and_scoped() {
    let issuer = committed_certificate("sec06-issuer.der");
    let leaf = embedded("sec10-leaf-crl-dp.exe", &issuer);
    assert_eq!(extension_value(&leaf, "2.5.29.31"), listed_points());
    assert_eq!(
        leaf.tbs_certificate.serial_number,
        SerialNumber::from(SCOPED_LEAF_SERIAL)
    );
    for (label, uri, revoked) in PARTITIONS {
        // The whole IDP value: one fullName URI, no scope flags or reasons.
        assert_crl(
            &format!("sec10-issuer-idp-{label}.crl"),
            &issuer,
            Some(&crl_applicability::idp_named_point(uri)),
            if revoked { &[SCOPED_LEAF_SERIAL] } else { &[] },
        );
    }
}

#[test]
fn sec10_distribution_point_forms_are_signed_and_encoded() {
    let root = committed_certificate("sec06-root.der");
    let issuer = committed_certificate("sec06-issuer.der");
    for (label, serial, points) in point_forms() {
        let name = format!("sec10-leaf-crl-dp-{label}.exe");
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
            &format!("sec10-issuer-idp-{label}.crl"),
            &issuer,
            Some(&scope),
            &[],
        );
    }
    let pointed = embedded("sec10-ca-crl-dp.exe", &root);
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
            &format!("sec10-sec06-root-idp-{label}.crl"),
            &root,
            Some(&scope),
            &[],
        );
    }
    assert_crl(
        "sec10-sec06-root-revoked-issuer.crl",
        &root,
        None,
        &[ISSUER_SERIAL],
    );
    assert_crl(
        "sec10-sec06-other-root-revoked-cross.crl",
        &committed_certificate("sec06-other-root.der"),
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
fn sec10_distribution_point_forms_decode_as_intended() {
    use ::der::Decode;
    use x509_cert::ext::pkix::{CrlDistributionPoints, crl::dp::IssuingDistributionPoint};
    let issuer = committed_certificate("sec06-issuer.der");
    // Per point: its name, and whether it has reasons or a cRLIssuer.
    let points = |label: &str| -> Vec<(NameForm, bool, bool)> {
        let leaf = embedded(&format!("sec10-leaf-crl-dp-{label}.exe"), &issuer);
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
    let issuer_scope = |label: &str| scope(&format!("sec10-issuer-idp-{label}.crl"));
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
        scope("sec10-sec06-root-idp-ca.crl"),
        (uris(&[ISSUER_POINT]), false, true)
    );
    assert_eq!(
        scope("sec10-sec06-root-idp-user.crl"),
        (uris(&[ISSUER_POINT]), true, false)
    );
    // The intermediate lists the point; its signer is the plain SEC-06 leaf.
    let root = committed_certificate("sec06-root.der");
    let pointed = embedded("sec10-ca-crl-dp.exe", &root);
    let listed = CrlDistributionPoints::from_der(&extension_value(&pointed, "2.5.29.31")).unwrap();
    assert_eq!(listed.0.len(), 1);
    assert_eq!(
        name_form(&listed.0[0].distribution_point),
        uris(&[ISSUER_POINT])
    );
    let signer = embedded("sec10-ca-crl-dp.exe", &issuer);
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
