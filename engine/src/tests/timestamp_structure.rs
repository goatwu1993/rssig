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
    // PATH-014: a TSA certificate that repeats its subjectKeyIdentifier.
    "repeated-ski",
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
    if policy_fault.starts_with("eku-")
        || policy_fault == "key-usage"
        || policy_fault == "malformed-ski"
        || policy_fault == "repeated-ski"
    {
        let exts = tsa.cert.tbs_certificate.extensions.as_mut().unwrap();
        if policy_fault == "repeated-ski" {
            let ski = exts
                .iter()
                .find(|e| e.extn_id.to_string() == "2.5.29.14")
                .unwrap()
                .clone();
            exts.push(ski);
        } else if policy_fault == "malformed-ski" {
            exts.retain(|e| e.extn_id.to_string() != "2.5.29.14");
            exts.push(x509_cert::ext::Extension {
                extn_id: "2.5.29.14".parse().unwrap(),
                critical: false,
                extn_value: ::der::asn1::OctetString::new(vec![0x30, 0x02, 0x05, 0x00]).unwrap(),
            });
        } else if policy_fault == "eku-missing" {
            exts.retain(|e| e.extn_id.to_string() != "2.5.29.37");
        } else if policy_fault == "key-usage" {
            let ext = exts
                .iter_mut()
                .find(|e| e.extn_id.to_string() == "2.5.29.15")
                .unwrap();
            ext.extn_value = ::der::asn1::OctetString::new(
                x509_cert::ext::pkix::KeyUsage(
                    x509_cert::ext::pkix::KeyUsages::KeyEncipherment.into(),
                )
                .to_der()
                .unwrap(),
            )
            .unwrap();
        } else {
            let ext = exts
                .iter_mut()
                .find(|e| e.extn_id.to_string() == "2.5.29.37")
                .unwrap();
            if policy_fault == "eku-noncritical" {
                ext.critical = false;
            } else {
                ext.extn_value = ::der::asn1::OctetString::new(seq(&[
                    oid(trust::TIME_STAMPING),
                    oid(trust::CODE_SIGNING),
                ]))
                .unwrap();
            }
        }
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
        "signing-time"
        | "counter-substitution"
        | "good-counter"
        | "counter-eku-noncritical"
        | "counter-eku-mixed"
        | "counter-eku-missing"
        | "counter-key-usage" => vec![counter],
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

pub(super) fn write(dir: &std::path::Path) {
    for fault in FAULTS
        .iter()
        .copied()
        .chain(["good", "good-optional", "good-counter"])
    {
        std::fs::write(dir.join(format!("tsa-{fault}.exe")), artifact(fault)).unwrap();
    }
}

#[test]
#[ignore = "explicit fixture maintenance"]
fn regenerate_tsa_fixtures() {
    write(&std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/fixtures"));
}

/// PATH-014's TSA case rests on the TSA certificate of `tsa-repeated-ski.exe`
/// being that of `tsa-good.exe` with one copy of its subjectKeyIdentifier
/// appended, wherever it is embedded (in the signature and in the timestamp
/// token), and every other certificate unchanged.
#[test]
fn the_repeated_ski_tsa_certificate_differs_only_by_the_appended_copy() {
    let certs = |name: &str| {
        let bytes = std::fs::read(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap();
        let pe = pe::Pe::parse(&bytes).unwrap();
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
    };
    let (good, bad) = (certs("tsa-good.exe"), certs("tsa-repeated-ski.exe"));
    assert_eq!(bad.len(), good.len());
    let mut changed = Vec::new();
    for (good, bad) in good.iter().zip(&bad) {
        assert_eq!(bad.len(), good.len());
        for (good, bad) in good.iter().zip(bad).filter(|(good, bad)| good != bad) {
            let mut bad = bad.tbs_certificate.clone();
            let extensions = bad.extensions.as_mut().unwrap();
            let copy = extensions.pop().unwrap();
            assert_eq!(copy.extn_id.to_string(), "2.5.29.14");
            assert!(extensions.contains(&copy));
            assert_eq!(bad, good.tbs_certificate);
            changed.push(good.tbs_certificate.subject.to_string());
        }
    }
    assert!(!changed.is_empty());
    assert!(
        changed.iter().all(|subject| subject == "CN=rssig test TSA"),
        "{changed:?}"
    );
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
