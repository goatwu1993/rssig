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
    // PATH-013: a TSA certificate whose basicConstraints, keyUsage or
    // extKeyUsage does not decode, the last also in a countersignature.
    "malformed-bc",
    "malformed-ku",
    "malformed-eku",
    "counter-malformed-eku",
    // PATH-014: a TSA certificate that repeats its subjectKeyIdentifier.
    "repeated-ski",
    // PATH-006: a TSA certificate with a critical SCT list, which rssig does
    // not process, in a token and in a countersignature.
    "critical-sct",
    "counter-critical-sct",
    // PATH-006 before TSA-003: the same, without an extKeyUsage.
    "critical-sct-eku-missing",
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

/// SEQUENCE { NULL }: decodes as none of basicConstraints, keyUsage,
/// extKeyUsage or subjectKeyIdentifier (an OCTET STRING), so each
/// `malformed-` fault, `malformed-ski` included, relies on it.
const MALFORMED_VALUE: [u8; 4] = [0x30, 0x02, 0x05, 0x00];

/// Replaces only the value of the one extension with `oid`, keeping its place
/// and critical flag.
fn malform(exts: &mut [x509_cert::ext::Extension], oid: &str) {
    extension(exts, oid).extn_value =
        ::der::asn1::OctetString::new(MALFORMED_VALUE.to_vec()).unwrap();
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
                extn_value: ::der::asn1::OctetString::new(MALFORMED_VALUE.to_vec()).unwrap(),
            });
        }),
        // Only the value changes: the extension keeps its place and its
        // critical flag, and SEQUENCE { NULL } does not decode as one.
        "malformed-bc" => Some(|exts| malform(exts, "2.5.29.19")),
        "malformed-ku" => Some(|exts| malform(exts, "2.5.29.15")),
        "malformed-eku" => Some(|exts| malform(exts, "2.5.29.37")),
        "critical-sct" => Some(|exts| {
            exts.push(x509_cert::ext::Extension {
                extn_id: certificate_paths::SCT_LIST_OID.parse().unwrap(),
                critical: true,
                extn_value: ::der::asn1::OctetString::new(certificate_paths::sct_list()).unwrap(),
            });
        }),
        "critical-sct-eku-missing" => Some(|exts| {
            exts.retain(|e| e.extn_id.to_string() != "2.5.29.37");
            exts.push(x509_cert::ext::Extension {
                extn_id: certificate_paths::SCT_LIST_OID.parse().unwrap(),
                critical: true,
                extn_value: ::der::asn1::OctetString::new(certificate_paths::sct_list()).unwrap(),
            });
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

/// The good fixture a committed TSA fixture pairs with: its `paired_good` in
/// `tests/fixtures/manifest.json`, so the manifest is the one record of it.
fn good_pair(name: &str) -> String {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
                .join("tests/fixtures/manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut found = manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["file"] == name);
    let artifact = found
        .next()
        .unwrap_or_else(|| panic!("{name} not in the manifest"));
    assert!(found.next().is_none(), "{name} listed twice");
    artifact["paired_good"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has no paired_good"))
        .to_owned()
}

/// Asserts that `name` embeds the certificates of its good pair
/// (`good_pair`) in each of its certificate sets, except that in every set the
/// TSA certificate's TBSCertificate is the one `undo` turns back into the
/// pair's.
fn only_the_tsa_certificate_differs(name: &str, undo: impl Fn(&mut x509_cert::TbsCertificate)) {
    let pair = good_pair(name);
    let (good, bad) = (tsa_certificate_sets(&pair), tsa_certificate_sets(name));
    // The good RFC 3161 fixture has the signature's set and its token's; the
    // good countersignature has the signature's only. The fixture has the
    // same sets as its pair, so for an RFC 3161 pair the comparison covers the
    // token's set too.
    let sets = match pair.as_str() {
        "tsa-good.exe" => 2,
        "tsa-good-counter.exe" => 1,
        other => panic!("{name}: unexpected pair {other}"),
    };
    assert_eq!(good.len(), sets, "{pair}");
    assert_eq!(bad.len(), good.len(), "{name} against {pair}");
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

/// PATH-013's TSA cases for an extension the report decodes rest on the TSA
/// certificate of each fixture being that of its good pair with only that
/// extension's value replaced by SEQUENCE { NULL } (critical flag and place
/// kept), a value that does not decode as that extension, and every other
/// certificate unchanged.
#[test]
fn each_malformed_tsa_certificate_differs_only_by_the_extension_value() {
    use ::der::Decode;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
    // Whether a value decodes as the extension.
    type Decodes = fn(&[u8]) -> bool;
    // The extension each `malformed-` suffix edits in place.
    let edited: [(&str, &str, Decodes); 3] = [
        ("bc", "2.5.29.19", |v| BasicConstraints::from_der(v).is_ok()),
        ("ku", "2.5.29.15", |v| KeyUsage::from_der(v).is_ok()),
        ("eku", "2.5.29.37", |v| {
            ExtendedKeyUsage::from_der(v).is_ok()
        }),
    ];
    // Every `malformed-` fault but `malformed-ski`, which replaces its
    // extension instead (PATH-013's case rests on it not decoding, below), in
    // either form, so a new one is checked without being listed here.
    let decodes: Vec<(String, &str, Decodes)> = FAULTS
        .iter()
        .filter_map(|fault| {
            let suffix = fault
                .strip_prefix("counter-")
                .unwrap_or(fault)
                .strip_prefix("malformed-")?;
            if suffix == "ski" {
                return None;
            }
            let (_, oid, decodes) = edited
                .iter()
                .find(|(s, _, _)| *s == suffix)
                .unwrap_or_else(|| panic!("no extension for {fault}"));
            Some((format!("tsa-{fault}.exe"), *oid, *decodes))
        })
        .collect();
    // The filter finds at least the faults PATH-013's TSA cases pin.
    for pinned in [
        "tsa-malformed-bc.exe",
        "tsa-malformed-ku.exe",
        "tsa-malformed-eku.exe",
        "tsa-counter-malformed-eku.exe",
    ] {
        assert!(
            decodes.iter().any(|(name, _, _)| name == pinned),
            "{pinned}"
        );
    }
    // `malformed-ski` rests on the same value, which is no OCTET STRING.
    assert!(x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(&MALFORMED_VALUE).is_err());
    for (name, oid, decodes) in decodes {
        let name = name.as_str();
        // The value to restore comes from the pair
        // `only_the_tsa_certificate_differs` compares with.
        let good_ext = tsa_certificate_sets(&good_pair(name))[0]
            .iter()
            .find(|c| c.tbs_certificate.subject.to_string() == "CN=rssig test TSA")
            .unwrap()
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id.to_string() == oid)
            .unwrap()
            .clone();
        // The good value decodes, so the check below is not vacuous.
        assert!(decodes(good_ext.extn_value.as_bytes()), "{name}");
        assert!(good_ext.critical, "{name}");
        only_the_tsa_certificate_differs(name, |tbs| {
            let extensions = tbs.extensions.as_mut().unwrap();
            let mut found = extensions
                .iter_mut()
                .filter(|e| e.extn_id.to_string() == oid);
            let ext = found.next().unwrap();
            assert!(found.next().is_none(), "{name}");
            assert!(ext.critical, "{name}");
            assert_eq!(ext.extn_value.as_bytes(), MALFORMED_VALUE, "{name}");
            assert!(!decodes(ext.extn_value.as_bytes()), "{name}");
            ext.extn_value = good_ext.extn_value.clone();
        });
    }
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
