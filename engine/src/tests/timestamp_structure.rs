//! TSA-T001 deterministic fixtures. Only explicit maintenance writes files.
use super::*;

pub(super) const FAULTS: &[&str] = &[
    "version",
    "policy",
    "serial-negative",
    "serial-nonminimal",
    "time-tag",
    "unknown",
    "order",
    "duplicate-optional",
    "ordering-false",
    "nonce-negative",
    "accuracy-range",
    "accuracy-order",
    "accuracy-unknown",
    "tsa",
    "extensions",
    "duplicate-rfc",
    "duplicate-counter",
    "duplicate-eku-rfc",
    "duplicate-eku-counter",
    "mixed",
    "mixed-reverse",
    "aliases",
    "multi-value",
    "eku-noncritical",
    "eku-mixed",
    "eku-missing",
    "key-usage",
    "substitution",
    "counter-substitution",
    "signing-time",
    "counter-eku-noncritical",
    "counter-eku-mixed",
    "counter-eku-missing",
    "counter-key-usage",
    // PATH-013: a TSA certificate whose subjectKeyIdentifier does not decode.
    "malformed-ski",
    // PATH-013: a TSA certificate whose extKeyUsage does not decode.
    "malformed-eku",
    // PATH-014: a TSA certificate that repeats its subjectKeyIdentifier.
    "repeated-ski",
];

/// The one extension with `oid` in a TSA certificate's extensions; panics
/// unless exactly one has it.
fn extension<'a>(
    exts: &'a mut [x509_cert::ext::Extension],
    oid: &str,
) -> &'a mut x509_cert::ext::Extension {
    let mut found = exts.iter_mut().filter(|e| e.extn_id.to_string() == oid);
    let ext = found.next().unwrap();
    assert!(found.next().is_none(), "{oid} repeated");
    ext
}

/// The faults (after `counter-` is stripped) that leave the TSA certificate
/// as it is in `tsa-good.exe`.
const UNCHANGED_TSA_CERTIFICATE: &[&str] = &[
    "version",
    "policy",
    "serial-negative",
    "serial-nonminimal",
    "time-tag",
    "unknown",
    "order",
    "duplicate-optional",
    "ordering-false",
    "nonce-negative",
    "accuracy-range",
    "accuracy-order",
    "accuracy-unknown",
    "tsa",
    "extensions",
    "duplicate-rfc",
    "duplicate-counter",
    "mixed",
    "mixed-reverse",
    "aliases",
    "multi-value",
    "substitution",
    "signing-time",
    "good",
    "good-optional",
    "good-counter",
];

fn artifact(fault: &str) -> Vec<u8> {
    let id = identity();
    let mut tsa = tsa_identity();
    // The duplicate-eku fixtures carry two timestamps whose TSA certificate has no
    // EKU, so a verifier that checks the first token before counting them reports
    // invalid_eku instead of the multiplicity rule (TSA-004).
    let policy_fault = match fault {
        "duplicate-eku-rfc" | "duplicate-eku-counter" => "eku-missing",
        other => other.strip_prefix("counter-").unwrap_or(other),
    };
    // Each fault that edits the TSA certificate has its own arm, and the
    // default arm takes only the faults listed as editing nothing, so a new
    // fault with neither fails here instead of copying tsa-good.exe's
    // certificate.
    let edit: Option<fn(&mut Vec<x509_cert::ext::Extension>)> = match policy_fault {
        "repeated-ski" => Some(|exts| {
            let ski = exts
                .iter()
                .find(|e| e.extn_id.to_string() == "2.5.29.14")
                .unwrap()
                .clone();
            exts.push(ski);
        }),
        "malformed-ski" => Some(|exts| {
            exts.retain(|e| e.extn_id.to_string() != "2.5.29.14");
            exts.push(x509_cert::ext::Extension {
                extn_id: "2.5.29.14".parse().unwrap(),
                critical: false,
                extn_value: ::der::asn1::OctetString::new(vec![0x30, 0x02, 0x05, 0x00]).unwrap(),
            });
        }),
        // Only the value changes: the extension keeps its place and its
        // critical flag, and SEQUENCE { NULL } does not decode as one.
        "malformed-eku" => Some(|exts| {
            extension(exts, "2.5.29.37").extn_value =
                ::der::asn1::OctetString::new(vec![0x30, 0x02, 0x05, 0x00]).unwrap();
        }),
        "eku-missing" => Some(|exts| exts.retain(|e| e.extn_id.to_string() != "2.5.29.37")),
        "key-usage" => Some(|exts| {
            extension(exts, "2.5.29.15").extn_value = ::der::asn1::OctetString::new(
                x509_cert::ext::pkix::KeyUsage(
                    x509_cert::ext::pkix::KeyUsages::KeyEncipherment.into(),
                )
                .to_der()
                .unwrap(),
            )
            .unwrap();
        }),
        "eku-noncritical" => Some(|exts| extension(exts, "2.5.29.37").critical = false),
        "eku-mixed" => Some(|exts| {
            extension(exts, "2.5.29.37").extn_value = ::der::asn1::OctetString::new(seq(&[
                oid(trust::TIME_STAMPING),
                oid(trust::CODE_SIGNING),
            ]))
            .unwrap();
        }),
        other => {
            assert!(
                UNCHANGED_TSA_CERTIFICATE.contains(&other),
                "no certificate edit for {fault}"
            );
            None
        }
    };
    if let Some(edit) = edit {
        edit(tsa.cert.tbs_certificate.extensions.as_mut().unwrap());
        let sig: Signature = tsa
            .root_key
            .sign(&tsa.cert.tbs_certificate.to_der().unwrap());
        tsa.cert.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    }
    let base = base_pe(true);
    let content = image_content(&base, true, None);
    let body = der::one(&content, 0x30).unwrap().body;
    let parent_si = signer_info(id, body, Some(cms::INDIRECT), vec![], vec![]);
    let parent = der::one(&parent_si, 0x30).unwrap().children().unwrap()[5].body;
    let bound = if fault.ends_with("substitution") {
        b"different parent".as_slice()
    } else {
        parent
    };
    let mut info = vec![
        tlv(2, &[1]),
        oid(&[42, 3, 4]),
        seq(&[sha256_alg(), tlv(4, &crypto::Hash::Sha256.digest(bound))]),
        tlv(2, &[1]),
        tlv(0x18, b"20270115080000Z"),
    ];
    match fault {
        "version" => info[0] = tlv(2, &[2]),
        "policy" => info[1] = tlv(4, &[42, 3, 4]),
        "serial-negative" => info[3] = tlv(2, &[255]),
        "serial-nonminimal" => info[3] = tlv(2, &[0, 1]),
        "time-tag" => info[4] = tlv(0x17, b"270115080000Z"),
        "unknown" => info.push(tlv(5, &[])),
        "order" => info.extend([tlv(2, &[1]), tlv(1, &[255])]),
        "duplicate-optional" => info.extend([tlv(2, &[1]), tlv(2, &[1])]),
        "ordering-false" => info.push(tlv(1, &[0])),
        "nonce-negative" => info.push(tlv(2, &[255])),
        "accuracy-range" => info.push(seq(&[tlv(0x80, &[0])])),
        "accuracy-order" => info.push(seq(&[tlv(0x81, &[1]), tlv(0x80, &[1])])),
        "accuracy-unknown" => info.push(seq(&[tlv(5, &[])])),
        "tsa" => info.push(tlv(0xa0, &tlv(0x82, b"tsa.example.invalid"))),
        "extensions" => info.push(tlv(0xa1, &seq(&[oid(&[42, 3, 4]), tlv(4, &[])]))),
        "good-optional" => info.extend([
            seq(&[tlv(2, &[1]), tlv(0x80, &[3]), tlv(0x81, &[1])]),
            tlv(1, &[255]),
            tlv(2, &[7]),
        ]),
        _ => {}
    }
    let info = seq(&info);
    let token = signed_data(
        &tsa,
        tlv(4, &info),
        cms::TST_INFO,
        signer_info(&tsa, &info, Some(cms::TST_INFO), vec![], vec![]),
    );
    let rfc = attr(cms::RFC3161, token.clone());
    let counter = attr(
        cms::COUNTERSIGN,
        signer_info(
            &tsa,
            bound,
            None,
            vec![attr(
                &[42, 134, 72, 134, 247, 13, 1, 9, 5],
                if fault == "signing-time" {
                    tlv(0x17, b"270230080000Z")
                } else {
                    tm(NOW).to_der().unwrap()
                },
            )],
            vec![],
        ),
    );
    let unsigned = match fault {
        "duplicate-rfc" => vec![rfc.clone(), rfc],
        "duplicate-counter" => vec![counter.clone(), counter],
        "duplicate-eku-rfc" => vec![rfc.clone(), rfc],
        "duplicate-eku-counter" => vec![counter.clone(), counter],
        "mixed" => vec![rfc, counter],
        "mixed-reverse" => vec![counter, rfc],
        "aliases" => vec![rfc, attr(cms::CMS_TIMESTAMP, token)],
        "multi-value" => vec![seq(&[
            oid(cms::RFC3161),
            tlv(0x31, &[token.clone(), token].concat()),
        ])],
        // Every counter- fault is carried by a countersignature.
        "signing-time" | "good-counter" => vec![counter],
        other if other.starts_with("counter-") => vec![counter],
        _ => vec![rfc],
    };
    let si = signer_info(id, body, Some(cms::INDIRECT), vec![], unsigned);
    attach(
        base,
        &signed_data_extra(
            id,
            content,
            cms::INDIRECT,
            si,
            vec![tsa.cert.to_der().unwrap()],
        ),
        true,
    )
}

/// The good fixtures `write` adds to `FAULTS`.
const GOOD: [&str; 3] = ["good", "good-optional", "good-counter"];

pub(super) fn write(dir: &std::path::Path) {
    for fault in FAULTS.iter().copied().chain(GOOD) {
        std::fs::write(dir.join(format!("tsa-{fault}.exe")), artifact(fault)).unwrap();
    }
}

/// Builds every TSA fixture in memory, so the generator's own checks (each
/// fault edits the TSA certificate or is listed as leaving it unchanged) run
/// in `cargo test`, not only when fixtures are regenerated.
#[test]
fn every_tsa_fault_builds() {
    let tsa = |bytes: &[u8]| {
        certificate_sets(bytes)
            .into_iter()
            .flatten()
            .filter(|c| c.tbs_certificate.subject.to_string() == "CN=rssig test TSA")
            .collect::<Vec<_>>()
    };
    let good = tsa(&artifact("good"));
    assert_eq!(good.len(), 2);
    let mut listed = Vec::new();
    for fault in FAULTS.iter().copied().chain(GOOD) {
        let tsa = tsa(&artifact(fault));
        assert!(!tsa.is_empty(), "{fault}");
        let stripped = fault.strip_prefix("counter-").unwrap_or(fault);
        // A fault listed as leaving the certificate unchanged does so
        // wherever the certificate is embedded.
        if UNCHANGED_TSA_CERTIFICATE.contains(&stripped) {
            assert!(tsa.iter().all(|c| *c == good[0]), "{fault}");
            listed.push(stripped);
        }
    }
    // Every name in the list is a fault the generator writes.
    for name in UNCHANGED_TSA_CERTIFICATE {
        assert!(listed.contains(name), "{name} is not a TSA fault");
    }
}

#[test]
#[ignore = "explicit fixture maintenance"]
fn regenerate_tsa_fixtures() {
    write(&std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/fixtures"));
}

/// Every certificate set of a committed TSA fixture: the signature's, then each
/// timestamp token's.
fn tsa_certificate_sets(name: &str) -> Vec<Vec<Certificate>> {
    certificate_sets(
        &std::fs::read(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap(),
    )
}

/// Every certificate set of a TSA artifact: the signature's, then each RFC
/// 3161 token's (a countersignature has no set of its own).
fn certificate_sets(bytes: &[u8]) -> Vec<Vec<Certificate>> {
    let pe = pe::Pe::parse(bytes).unwrap();
    let sd = cms::SignedData::parse(pe.certificates().unwrap()[0]).unwrap();
    let mut sets = vec![sd.certs.clone()];
    let fields = sd.signers[0].children().unwrap();
    for attr in fields[6].children().unwrap() {
        let attr = attr.children().unwrap();
        if attr[0].body != cms::COUNTERSIGN {
            for value in attr[1].children().unwrap() {
                sets.push(cms::SignedData::parse(value.full).unwrap().certs);
            }
        }
    }
    sets
}

/// For an RFC 3161 fixture, paired with `tsa-good.exe`: asserts that `name`
/// embeds the certificates of `tsa-good.exe` in each of its certificate sets
/// (the signature's and the timestamp token's), except
/// that in every set the TSA certificate's TBSCertificate is the one `undo`
/// turns back into `tsa-good.exe`'s.
fn only_the_tsa_certificate_differs(name: &str, undo: impl Fn(&mut x509_cert::TbsCertificate)) {
    let (good, bad) = (
        tsa_certificate_sets("tsa-good.exe"),
        tsa_certificate_sets(name),
    );
    assert_eq!(bad.len(), good.len());
    // The signature's set and the token's each embed the TSA certificate.
    assert!(good.len() >= 2, "{name}");
    for (good, bad) in good.iter().zip(&bad) {
        assert_eq!(bad.len(), good.len());
        let mut changed = Vec::new();
        for (good, bad) in good.iter().zip(bad).filter(|(good, bad)| good != bad) {
            let mut bad = bad.tbs_certificate.clone();
            undo(&mut bad);
            assert_eq!(bad, good.tbs_certificate, "{name}");
            changed.push(good.tbs_certificate.subject.to_string());
        }
        // Each set changes exactly its TSA certificate.
        assert_eq!(changed, ["CN=rssig test TSA"], "{name}");
    }
}

/// PATH-014's TSA case rests on the TSA certificate of `tsa-repeated-ski.exe`
/// being that of `tsa-good.exe` with one copy of its subjectKeyIdentifier
/// appended, and every other certificate unchanged.
#[test]
fn the_repeated_ski_tsa_certificate_differs_only_by_the_appended_copy() {
    only_the_tsa_certificate_differs("tsa-repeated-ski.exe", |tbs| {
        let extensions = tbs.extensions.as_mut().unwrap();
        let copy = extensions.pop().unwrap();
        assert_eq!(copy.extn_id.to_string(), "2.5.29.14");
        assert!(extensions.contains(&copy));
    });
}

/// PATH-013's TSA extKeyUsage cases rest on the TSA certificate of
/// `tsa-malformed-eku.exe` being that of `tsa-good.exe` with only its
/// extKeyUsage value replaced by SEQUENCE { NULL } (critical flag and place
/// kept), a value that does not decode as that extension, and every other
/// certificate unchanged.
#[test]
fn the_malformed_eku_tsa_certificate_differs_only_by_the_eku_value() {
    use ::der::Decode;
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    let good = tsa_certificate_sets("tsa-good.exe");
    let good_eku = good[0]
        .iter()
        .find(|c| c.tbs_certificate.subject.to_string() == "CN=rssig test TSA")
        .unwrap()
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == "2.5.29.37")
        .unwrap()
        .extn_value
        .clone();
    only_the_tsa_certificate_differs("tsa-malformed-eku.exe", |tbs| {
        let extensions = tbs.extensions.as_mut().unwrap();
        let mut ekus = extensions
            .iter_mut()
            .filter(|e| e.extn_id.to_string() == "2.5.29.37");
        let eku = ekus.next().unwrap();
        assert!(ekus.next().is_none());
        assert!(eku.critical);
        assert_eq!(eku.extn_value.as_bytes(), [0x30, 0x02, 0x05, 0x00]);
        assert!(ExtendedKeyUsage::from_der(eku.extn_value.as_bytes()).is_err());
        eku.extn_value = good_eku.clone();
    });
}

#[test]
fn tsa_committed_faults_preserve_image_and_signature_math() {
    fn math(si: der::Node<'_>, cert: &Certificate) {
        let f = si.children().unwrap();
        let mut signed = f[3].full.to_vec();
        signed[0] = 0x31;
        crypto::verify_spki(
            &cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            crypto::Hash::Sha256,
            f[4].children().unwrap()[0].body,
            &signed,
            f[5].body,
        )
        .unwrap();
    }
    for fault in FAULTS {
        let bytes = std::fs::read(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
                .join("tests/fixtures")
                .join(format!("tsa-{fault}.exe")),
        )
        .unwrap();
        let pe = pe::Pe::parse(&bytes).unwrap();
        let cms_bytes = pe.certificates().unwrap();
        let sd = cms::SignedData::parse(cms_bytes[0]).unwrap();
        let (hash, expected) = sd.image_digest().unwrap();
        assert_eq!(pe.digest(hash).unwrap(), expected, "{fault}");
        math(sd.signers[0], &sd.certs[0]);
        let fields = sd.signers[0].children().unwrap();
        for attr in fields[6].children().unwrap() {
            let attr = attr.children().unwrap();
            for value in attr[1].children().unwrap() {
                if attr[0].body == cms::COUNTERSIGN {
                    math(value, &sd.certs[2]);
                } else {
                    let token = cms::SignedData::parse(value.full).unwrap();
                    // Includes the TSTInfo messageDigest binding; malformed fields
                    // are deliberately signed, rather than signature corruptions.
                    token.verify(token.signers[0], false).unwrap();
                }
            }
        }
        for cert in &sd.certs {
            crypto::verify_spki(
                &identity()
                    .root
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .unwrap(),
                crypto::Hash::Sha256,
                cert.signature_algorithm.oid.as_bytes(),
                &cert.tbs_certificate.to_der().unwrap(),
                cert.signature.as_bytes().unwrap(),
            )
            .unwrap();
        }
    }
}
