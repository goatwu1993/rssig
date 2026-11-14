//! SEC-06 maintenance builders: public deterministic keys, inert signed PE files.
use super::*;
use ::der::asn1::{ObjectIdentifier, OctetString};
use x509_cert::ext::{Extension, pkix::BasicConstraints};

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
    use x509_cert::{
        Version,
        crl::{CertificateList, TbsCertList},
    };
    let algorithm = issuer.signature_algorithm.clone();
    let tbs = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer: issuer.tbs_certificate.subject.clone(),
        this_update: tm(NOW - 100),
        next_update: Some(tm(NOW + 1000)),
        revoked_certificates: None,
        crl_extensions: Some(vec![Extension {
            extn_id: "2.5.29.20".parse().unwrap(),
            critical: false,
            extn_value: OctetString::new([2, 1, 1]).unwrap(),
        }]),
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
    let mut ca = certificate("issuer", 110, &ca_key, "root", &root_key, true);
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
        if !filename.contains("-sec06-") || !filename.ends_with(".exe") {
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
    assert_eq!(count, 33);
}
