//! Deterministic, isolated negative fixtures. Only the ignored maintenance
//! command writes artifacts; ordinary tests inspect the committed bytes.
use super::*;
use ::der::{Decode, asn1::OctetString};
use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

#[derive(Clone, Copy)]
enum CmsFault {
    ContentDigest,
    ContentType,
    SignerIssuer,
    SignerSerial,
    DigestSet,
    AlgorithmDigest,
    AlgorithmKey,
    Signature,
}

fn parts(bytes: &[u8]) -> Vec<Vec<u8>> {
    der::one(bytes, 0x30)
        .unwrap()
        .children()
        .unwrap()
        .iter()
        .map(|n| n.full.to_vec())
        .collect()
}

fn edit_cms(bytes: &[u8], edit: impl FnOnce(&mut Vec<Vec<u8>>)) -> Vec<u8> {
    let mut outer = parts(bytes);
    let mut sd = parts(der::one(&outer[1], 0xa0).unwrap().body);
    edit(&mut sd);
    outer[1] = tlv(0xa0, &seq(&sd));
    seq(&outer)
}

fn corrupt_signature(si: &[u8]) -> Vec<u8> {
    let mut fields = parts(si);
    let mut signature = der::one(&fields[5], 4).unwrap().body.to_vec();
    // Change the last scalar byte, retaining a well-formed ECDSA DER encoding.
    *signature.last_mut().unwrap() ^= 1;
    fields[5] = tlv(4, &signature);
    seq(&fields)
}

fn faulty_cms(fault: CmsFault) -> Vec<u8> {
    let id = identity();
    let content = image_content(&base_pe(true), true, None);
    let body = der::one(&content, 0x30).unwrap().body;
    let wrong_content = [body, &[0]].concat();
    // For attribute faults, sign the deliberately wrong attributes correctly.
    // This isolates the binding check from mathematical signature validity.
    let si = signer_info(
        id,
        if matches!(fault, CmsFault::ContentDigest) {
            &wrong_content
        } else {
            body
        },
        Some(if matches!(fault, CmsFault::ContentType) {
            cms::TST_INFO
        } else {
            cms::INDIRECT
        }),
        vec![],
        vec![],
    );
    let mut fields = parts(&si);
    match fault {
        CmsFault::SignerIssuer | CmsFault::SignerSerial => {
            let mut sid = parts(&fields[1]);
            if matches!(fault, CmsFault::SignerIssuer) {
                sid[0] = Name::from_str("CN=missing test issuer")
                    .unwrap()
                    .to_der()
                    .unwrap();
            } else {
                sid[1] = SerialNumber::from(99u32).to_der().unwrap();
            }
            fields[1] = seq(&sid);
        }
        CmsFault::AlgorithmDigest => {
            // ECDSA-with-SHA384 conflicts with SignerInfo's SHA256 digest.
            fields[4] = seq(&[oid(&[42, 134, 72, 206, 61, 4, 3, 3])]);
        }
        CmsFault::AlgorithmKey => {
            // rsaEncryption cannot be verified using the signer's EC key.
            fields[4] = seq(&[oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]), vec![5, 0]]);
        }
        CmsFault::Signature => {
            return signed_data(id, content, cms::INDIRECT, corrupt_signature(&si));
        }
        _ => {}
    }
    let cms = signed_data(id, content, cms::INDIRECT, seq(&fields));
    if matches!(fault, CmsFault::DigestSet) {
        edit_cms(&cms, |sd| {
            sd[1] = tlv(
                0x31,
                &seq(&[oid(&[96, 134, 72, 1, 101, 3, 4, 2, 2]), vec![5, 0]]),
            );
        })
    } else {
        cms
    }
}

fn pe_with_identity(id: &Identity) -> Vec<u8> {
    let base = base_pe(true);
    let content = image_content(&base, true, None);
    let si = signer_info(
        id,
        der::one(&content, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    attach(base, &signed_data(id, content, cms::INDIRECT, si), true)
}

fn changed_certificate(change: impl FnOnce(&mut Certificate), resign: bool) -> Vec<u8> {
    let original = identity();
    let mut id = Identity {
        key: original.key.clone(),
        cert: original.cert.clone(),
        root: original.root.clone(),
        root_key: original.root_key.clone(),
    };
    change(&mut id.cert);
    if resign {
        let signature: Signature = id.root_key.sign(&id.cert.tbs_certificate.to_der().unwrap());
        id.cert.signature = BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    }
    pe_with_identity(&id)
}

fn set_extension(cert: &mut Certificate, oid: &str, value: Vec<u8>) {
    cert.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|ext| ext.extn_id.to_string() == oid)
        .unwrap()
        .extn_value = OctetString::new(value).unwrap();
}

fn bad_timestamp_signature(legacy: bool) -> Vec<u8> {
    let good = timestamped_pe(legacy, false, false, NOW);
    let pe = pe::Pe::parse(&good).unwrap();
    let cms = pe.certificates().unwrap()[0];
    let cms = edit_cms(cms, |sd| {
        let index = sd.len() - 1;
        let si = der::one(&sd[index], 0x31).unwrap().body;
        let mut fields = parts(si);
        let unsigned = der::one(&fields[6], 0xa1).unwrap().children().unwrap();
        let values = parts(unsigned[0].full);
        let token = der::one(&values[1], 0x31).unwrap().body;
        let token = if legacy {
            corrupt_signature(token)
        } else {
            edit_cms(token, |token_sd| {
                let index = token_sd.len() - 1;
                token_sd[index] = tlv(
                    0x31,
                    &corrupt_signature(der::one(&token_sd[index], 0x31).unwrap().body),
                );
            })
        };
        fields[6] = tlv(
            0xa1,
            &attr(
                if legacy {
                    cms::COUNTERSIGN
                } else {
                    cms::RFC3161
                },
                token,
            ),
        );
        sd[index] = tlv(0x31, &seq(&fields));
    });
    attach(base_pe(true), &cms, true)
}

fn bad_nested_signature() -> Vec<u8> {
    let id = identity();
    let base = base_pe(true);
    let content = image_content(&base, true, None);
    let si = signer_info(
        id,
        der::one(&content, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![attr(cms::NESTED, faulty_cms(CmsFault::Signature))],
    );
    attach(base, &signed_data(id, content, cms::INDIRECT, si), true)
}

pub(super) fn write(directory: &std::path::Path) {
    let write = |name: &str, bytes: &[u8]| std::fs::write(directory.join(name), bytes).unwrap();
    for (name, fault) in [
        ("bad-cms-content-digest.exe", CmsFault::ContentDigest),
        ("bad-cms-content-type.exe", CmsFault::ContentType),
        ("bad-signer-issuer.exe", CmsFault::SignerIssuer),
        ("bad-signer-serial.exe", CmsFault::SignerSerial),
        ("bad-cms-digest-set.exe", CmsFault::DigestSet),
        (
            "bad-signature-digest-algorithm.exe",
            CmsFault::AlgorithmDigest,
        ),
        ("bad-signature-key-algorithm.exe", CmsFault::AlgorithmKey),
    ] {
        write(name, &attach(base_pe(true), &faulty_cms(fault), true));
    }
    write(
        "bad-countersignature-digest.exe",
        &timestamped_pe(true, true, false, NOW),
    );
    write(
        "bad-timestamp-signature.exe",
        &bad_timestamp_signature(false),
    );
    write(
        "bad-countersignature-signature.exe",
        &bad_timestamp_signature(true),
    );
    write("bad-nested-signature.exe", &bad_nested_signature());
    write(
        "bad-certificate-not-yet-valid.exe",
        &changed_certificate(
            |cert| {
                cert.tbs_certificate.validity.not_before = tm(NOW + 1);
            },
            true,
        ),
    );
    write(
        "bad-certificate-expired.exe",
        &changed_certificate(
            |cert| {
                cert.tbs_certificate.validity.not_after = tm(NOW - 1);
            },
            true,
        ),
    );
    write(
        "bad-signer-eku.exe",
        &changed_certificate(
            |cert| {
                set_extension(
                    cert,
                    "2.5.29.37",
                    ExtendedKeyUsage(vec![::der::asn1::ObjectIdentifier::new_unwrap(
                        "1.3.6.1.5.5.7.3.1",
                    )])
                    .to_der()
                    .unwrap(),
                );
            },
            true,
        ),
    );
    write(
        "bad-signer-key-usage.exe",
        &changed_certificate(
            |cert| {
                set_extension(
                    cert,
                    "2.5.29.15",
                    KeyUsage(KeyUsages::KeyEncipherment.into())
                        .to_der()
                        .unwrap(),
                );
            },
            true,
        ),
    );
    write(
        "bad-certificate-signature.exe",
        &changed_certificate(
            |cert| {
                let mut sig = cert.signature.as_bytes().unwrap().to_vec();
                *sig.last_mut().unwrap() ^= 1;
                cert.signature = BitString::from_bytes(&sig).unwrap();
            },
            false,
        ),
    );
    write(
        "bad-signer-public-key.exe",
        &changed_certificate(
            |cert| {
                let wrong_key = SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
                cert.tbs_certificate.subject_public_key_info =
                    SubjectPublicKeyInfoOwned::from_key(*wrong_key.verifying_key()).unwrap();
            },
            true,
        ),
    );
    let good = intermediate_pe(false);
    let pe = pe::Pe::parse(&good).unwrap();
    let good_cms = cms::SignedData::parse(pe.certificates().unwrap()[0]).unwrap();
    let mut intermediate_crl =
        x509_cert::crl::CertificateList::from_der(&crl(false, false)).unwrap();
    intermediate_crl.tbs_cert_list.issuer = good_cms.certs[1].tbs_certificate.subject.clone();
    let ca_key = SigningKey::from_bytes((&[15u8; 32]).into()).unwrap();
    let sig: Signature = ca_key.sign(&intermediate_crl.tbs_cert_list.to_der().unwrap());
    intermediate_crl.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    write("good-intermediate.crl", &intermediate_crl.to_der().unwrap());
    let cms = edit_cms(pe.certificates().unwrap()[0], |sd| {
        let mut certs = der::one(&sd[3], 0xa0)
            .unwrap()
            .children()
            .unwrap()
            .iter()
            .map(|n| Certificate::from_der(n.full).unwrap())
            .collect::<Vec<_>>();
        let mut sig = certs[1].signature.as_bytes().unwrap().to_vec();
        *sig.last_mut().unwrap() ^= 1;
        certs[1].signature = BitString::from_bytes(&sig).unwrap();
        sd[3] = tlv(
            0xa0,
            &certs
                .iter()
                .flat_map(|c| c.to_der().unwrap())
                .collect::<Vec<_>>(),
        );
    });
    write(
        "bad-intermediate-signature.exe",
        &attach(base_pe(true), &cms, true),
    );
    let mut future = x509_cert::crl::CertificateList::from_der(&crl(false, false)).unwrap();
    future.tbs_cert_list.this_update = tm(NOW + 1);
    let sig: Signature = identity()
        .root_key
        .sign(&future.tbs_cert_list.to_der().unwrap());
    future.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    write("bad-crl-not-yet-valid.crl", &future.to_der().unwrap());
}

fn committed(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

#[test]
fn committed_binding_and_trust_faults_preserve_pe_image_hashes() {
    let manifest: serde_json::Value = serde_json::from_slice(&committed("manifest.json")).unwrap();
    for artifact in manifest["artifacts"].as_array().unwrap() {
        if !artifact["paired_good"]
            .as_str()
            .is_some_and(|s| s.ends_with(".exe"))
        {
            continue;
        }
        let name = artifact["file"].as_str().unwrap();
        let bytes = committed(name);
        let pe = pe::Pe::parse(&bytes).unwrap();
        for certificate in pe.certificates().unwrap() {
            let sd = cms::SignedData::parse(certificate).unwrap();
            let (hash, expected) = sd.image_digest().unwrap();
            assert_eq!(
                pe.digest(hash).unwrap(),
                expected,
                "{name}: earlier PE hash check must pass"
            );
        }
    }
}

#[test]
fn committed_attribute_faults_have_mathematically_valid_signatures() {
    for name in [
        "bad-cms-content-digest.exe",
        "bad-cms-content-type.exe",
        "bad-signer-issuer.exe",
        "bad-signer-serial.exe",
        "bad-cms-digest-set.exe",
    ] {
        let bytes = committed(name);
        let pe = pe::Pe::parse(&bytes).unwrap();
        let sd = cms::SignedData::parse(pe.certificates().unwrap()[0]).unwrap();
        let fields = sd.signers[0].children().unwrap();
        let mut attrs = fields[3].full.to_vec();
        attrs[0] = 0x31;
        let algorithm = fields[4].children().unwrap()[0].body;
        // Verify the math independently of the deliberately broken binding.
        crypto::verify_spki(
            &sd.certs[0]
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            cms::algorithm(fields[2]).unwrap(),
            algorithm,
            &attrs,
            fields[5].body,
        )
        .unwrap_or_else(|error| panic!("{name}: signature math must pass: {error}"));
        assert!(
            sd.verify(sd.signers[0], false).is_err(),
            "{name}: binding must fail"
        );
    }
}

#[test]
fn committed_signature_faults_change_only_one_byte() {
    for (bad, good) in [
        ("bad-timestamp-signature.exe", "good-rfc3161.exe"),
        (
            "bad-countersignature-signature.exe",
            "good-countersignature.exe",
        ),
        ("bad-nested-signature.exe", "good-nested.exe"),
        ("bad-certificate-signature.exe", "good-pe64.exe"),
        ("bad-intermediate-signature.exe", "good-intermediate.exe"),
    ] {
        let original = committed(good);
        let changed = committed(bad);
        assert_eq!(original.len(), changed.len(), "{bad}");
        let differences: Vec<_> = original
            .iter()
            .zip(&changed)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .collect();
        assert_eq!(differences.len(), 1, "{bad}");
        let (offset, (before, after)) = differences[0];
        assert!(offset >= 1032, "{bad}: only CMS bytes may change");
        assert_eq!(before ^ after, 1, "{bad}");
        let pe = pe::Pe::parse(&changed).unwrap();
        let sd = cms::SignedData::parse(pe.certificates().unwrap()[0]).unwrap();
        sd.verify(sd.signers[0], false).unwrap_or_else(|error| {
            panic!("{bad}: outer CMS signature must remain valid: {error}")
        });
    }
}

#[test]
fn committed_certificate_policy_faults_are_correctly_signed() {
    for name in [
        "bad-certificate-not-yet-valid.exe",
        "bad-certificate-expired.exe",
        "bad-signer-eku.exe",
        "bad-signer-key-usage.exe",
        "bad-signer-public-key.exe",
    ] {
        let bytes = committed(name);
        let pe = pe::Pe::parse(&bytes).unwrap();
        let sd = cms::SignedData::parse(pe.certificates().unwrap()[0]).unwrap();
        let cert = &sd.certs[0];
        crypto::verify_spki(
            &sd.certs[1]
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            crypto::Hash::Sha256,
            cert.signature_algorithm.oid.as_bytes(),
            &cert.tbs_certificate.to_der().unwrap(),
            cert.signature.as_bytes().unwrap(),
        )
        .unwrap_or_else(|error| panic!("{name}: issuer signature must pass: {error}"));
        if name != "bad-signer-public-key.exe" {
            sd.verify(sd.signers[0], false)
                .unwrap_or_else(|error| panic!("{name}: CMS signature must pass: {error}"));
        }
    }
    let future =
        x509_cert::crl::CertificateList::from_der(&committed("bad-crl-not-yet-valid.crl")).unwrap();
    let root = Certificate::from_der(&committed("root.der")).unwrap();
    crypto::verify_spki(
        &root
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap(),
        crypto::Hash::Sha256,
        future.signature_algorithm.oid.as_bytes(),
        &future.tbs_cert_list.to_der().unwrap(),
        future.signature.as_bytes().unwrap(),
    )
    .unwrap();
}
