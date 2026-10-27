//! Fixture-only MSI recipes, independent of the production package hasher.
use super::*;
use std::io::{Cursor, Read, Write};

const SIG: &str = "\u{5}DigitalSignature";
const EX: &str = "\u{5}MsiDigitalSignatureEx";
const ROOT: [u8; 16] = [
    0x84, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
];
const CHILD: [u8; 16] = [
    0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0,
];
const PORTED: &[&str] = &[
    "good-pe64",
    "good-nested",
    "good-rfc3161",
    "good-countersignature",
    "good-intermediate",
    "bad-cms-signature",
    "bad-cms-content-digest",
    "bad-cms-content-type",
    "bad-signer-issuer",
    "bad-signer-serial",
    "bad-cms-digest-set",
    "bad-signature-digest-algorithm",
    "bad-signature-key-algorithm",
    "bad-signer-public-key",
    "bad-countersignature-digest",
    "bad-timestamp-signature",
    "bad-countersignature-signature",
    "bad-nested-signature",
    "bad-certificate-not-yet-valid",
    "bad-certificate-expired",
    "bad-signer-eku",
    "bad-signer-key-usage",
    "bad-certificate-signature",
    "bad-intermediate-signature",
    "bad-timestamp-imprint",
    "bad-timestamp-eku",
    "bad-future-timestamp",
    "bad-ca-key-usage",
    "unsupported-digest-algorithm",
    "unsupported-signature-algorithm",
];

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn payloads() -> Vec<(&'static str, Vec<u8>)> {
    // Explicit UTF-16LE byte order, deliberately different from CFB tree order.
    vec![
        ("Ā", b"unicode".to_vec()),
        ("\u{4840}\u{380a}", b"encoded table".to_vec()),
        ("A", b"prefix".to_vec()),
        ("AB", b"longer prefix".to_vec()),
        ("Data", vec![0xab; 6000]),
        ("Nested/Empty", vec![]),
        ("Nested/X", vec![0x78; 130]),
    ]
}
fn recipe(extended: bool, hash: crypto::Hash) -> (Vec<u8>, Vec<u8>) {
    let mut metadata = ROOT.to_vec();
    metadata.extend(0u32.to_le_bytes());
    let mut content = Vec::new();
    let mut entered_nested = false;
    for (path, data) in payloads() {
        let nested = path.starts_with("Nested/");
        if nested && !entered_nested {
            metadata.extend(utf16("Nested"));
            metadata.extend(CHILD);
            metadata.extend([0; 4]);
            metadata.extend(116444736000000000u64.to_le_bytes());
            metadata.extend(116444736000000000u64.to_le_bytes());
            entered_nested = true;
        }
        metadata.extend(utf16(path.rsplit('/').next().unwrap()));
        metadata.extend((data.len() as u32).to_le_bytes());
        metadata.extend([0; 4]);
        metadata.extend([0; 16]);
        content.extend(data);
    }
    content.extend(CHILD);
    content.extend(ROOT);
    let prehash = hash.digest(&metadata);
    let digest = hash.digest(&[if extended { prehash.as_slice() } else { &[] }, &content].concat());
    (digest, prehash)
}
fn content(digest: &[u8], hash: crypto::Hash) -> Vec<u8> {
    let suffix = match hash {
        crypto::Hash::Sha1 => 0,
        crypto::Hash::Sha256 => 1,
        crypto::Hash::Sha384 => 2,
        crypto::Hash::Sha512 => 3,
    };
    let algorithm = if suffix == 0 {
        seq(&[oid(&[43, 14, 3, 2, 26]), vec![5, 0]])
    } else {
        seq(&[oid(&[96, 134, 72, 1, 101, 3, 4, 2, suffix]), vec![5, 0]])
    };
    seq(&[
        seq(&[
            oid(&[43, 6, 1, 4, 1, 130, 55, 2, 1, 30]),
            seq(&[
                vec![2, 1, 1],
                tlv(
                    4,
                    &[
                        0xf1, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
                    ],
                ),
                vec![2, 1, 0],
                vec![2, 1, 0],
                vec![2, 1, 0],
                vec![2, 1, 0],
                vec![2, 1, 0],
            ]),
        ]),
        seq(&[algorithm, tlv(4, digest)]),
    ])
}
fn fields(bytes: &[u8]) -> Vec<Vec<u8>> {
    der::one(bytes, 0x30)
        .unwrap()
        .children()
        .unwrap()
        .iter()
        .map(|n| n.full.to_vec())
        .collect()
}
fn rewrite_attrs(si: &[u8], old: &[u8], new: &[u8], package: &[u8]) -> Vec<u8> {
    let mut si = fields(si);
    let old_sig = der::one(&si[5], 4).unwrap().body.to_vec();
    let mut old_attrs = si[3].clone();
    old_attrs[0] = 0x31;
    let sid = fields(&si[1]);
    let key = if sid[1] == SerialNumber::from(3u32).to_der().unwrap() {
        tsa_identity().key
    } else {
        identity().key.clone()
    };
    let expected: Signature = key.sign(&old_attrs);
    let corrupt = old_sig != expected.to_der().as_bytes();
    let mut attrs = der::one(&si[3], 0xa0)
        .unwrap()
        .children()
        .unwrap()
        .iter()
        .map(|n| n.full.to_vec())
        .collect::<Vec<_>>();
    for attribute in &mut attrs {
        let parts = fields(attribute);
        if der::one(&parts[0], 6).unwrap().body == [42, 134, 72, 134, 247, 13, 1, 9, 4] {
            let digest = der::one(der::one(&parts[1], 0x31).unwrap().body, 4)
                .unwrap()
                .body;
            if digest == crypto::Hash::Sha256.digest(old) {
                *attribute = attr(
                    &[42, 134, 72, 134, 247, 13, 1, 9, 4],
                    tlv(4, &crypto::Hash::Sha256.digest(new)),
                );
            }
        }
    }
    attrs.sort();
    si[3] = tlv(0xa0, &attrs.concat());
    let mut to_sign = si[3].clone();
    to_sign[0] = 0x31;
    let sig: Signature = key.sign(&to_sign);
    let mut signature = sig.to_der().as_bytes().to_vec();
    if corrupt {
        *signature.last_mut().unwrap() ^= 1;
    }
    si[5] = tlv(4, &signature);
    if si.len() == 7 {
        let unsigned = der::one(&si[6], 0xa1).unwrap().children().unwrap();
        let mut updated = vec![];
        for attribute in unsigned {
            let parts = fields(attribute.full);
            let id = der::one(&parts[0], 6).unwrap().body;
            let values = der::one(&parts[1], 0x31).unwrap().children().unwrap();
            let changed = if id == cms::NESTED {
                convert_cms(values[0].full, package)
            } else if id == cms::COUNTERSIGN {
                rewrite_attrs(values[0].full, &old_sig, &signature, package)
            } else if id == cms::RFC3161 {
                let mut token = fields(values[0].full);
                let mut sd = fields(der::one(&token[1], 0xa0).unwrap().body);
                let mut ci = fields(&sd[2]);
                let old_info = der::one(der::one(&ci[1], 0xa0).unwrap().body, 4)
                    .unwrap()
                    .body
                    .to_vec();
                let mut info = fields(&old_info);
                let mut imprint = fields(&info[2]);
                if der::one(&imprint[1], 4).unwrap().body == crypto::Hash::Sha256.digest(&old_sig) {
                    imprint[1] = tlv(4, &crypto::Hash::Sha256.digest(&signature));
                }
                info[2] = seq(&imprint);
                let new_info = seq(&info);
                let i = sd.len() - 1;
                sd[i] = tlv(
                    0x31,
                    &rewrite_attrs(
                        der::one(&sd[i], 0x31).unwrap().body,
                        &old_info,
                        &new_info,
                        package,
                    ),
                );
                ci[1] = tlv(0xa0, &tlv(4, &new_info));
                sd[2] = seq(&ci);
                token[1] = tlv(0xa0, &seq(&sd));
                seq(&token)
            } else {
                values[0].full.to_vec()
            };
            updated.push(attr(id, changed));
        }
        si[6] = tlv(0xa1, &updated.concat());
    }

    seq(&si)
}
pub(super) fn convert_cms(bytes: &[u8], package: &[u8]) -> Vec<u8> {
    let mut outer = fields(bytes);
    let mut sd = fields(der::one(&outer[1], 0xa0).unwrap().body);
    let mut ci = fields(&sd[2]);
    let old = der::one(der::one(&ci[1], 0xa0).unwrap().body, 0x30)
        .unwrap()
        .body
        .to_vec();
    let new = der::one(package, 0x30).unwrap().body;
    let i = sd.len() - 1;
    sd[i] = tlv(
        0x31,
        &rewrite_attrs(der::one(&sd[i], 0x31).unwrap().body, &old, new, package),
    );
    ci[1] = tlv(0xa0, package);
    sd[2] = seq(&ci);
    outer[1] = tlv(0xa0, &seq(&sd));
    seq(&outer)
}
fn container(signature: Option<&[u8]>, extended: Option<&[u8]>, version: cfb::Version) -> Vec<u8> {
    let mut cf = cfb::CompoundFile::create_with_version(version, Cursor::new(vec![])).unwrap();
    cf.set_storage_clsid("/", "000c1084-0000-0000-c000-000000000046".parse().unwrap())
        .unwrap();
    cf.create_storage("Nested").unwrap();
    cf.set_storage_clsid(
        "Nested",
        "11223344-5566-7788-99aa-bbccddeeff00".parse().unwrap(),
    )
    .unwrap();
    for (path, data) in payloads() {
        cf.create_stream(path).unwrap().write_all(&data).unwrap();
    }
    if let Some(sig) = signature {
        cf.create_stream(SIG).unwrap().write_all(sig).unwrap();
    }
    if let Some(ex) = extended {
        cf.create_stream(EX).unwrap().write_all(ex).unwrap();
    }
    let paths: Vec<_> = cf.walk().map(|e| e.path().to_owned()).collect();
    for path in paths {
        cf.set_created_time(&path, std::time::UNIX_EPOCH).unwrap();
        cf.set_modified_time(&path, std::time::UNIX_EPOCH).unwrap();
    }
    cf.into_inner().into_inner()
}
fn edit(bytes: &[u8], f: impl FnOnce(&mut cfb::CompoundFile<Cursor<Vec<u8>>>)) -> Vec<u8> {
    let mut cf = cfb::CompoundFile::open(Cursor::new(bytes.to_vec())).unwrap();
    let original: std::collections::HashMap<_, _> = cf
        .walk()
        .map(|e| (e.path().to_owned(), e.is_storage()))
        .collect();
    f(&mut cf);
    let added: Vec<_> = cf
        .walk()
        .filter(|e| original.get(e.path()) != Some(&e.is_storage()))
        .map(|e| e.path().to_owned())
        .collect();
    for path in added {
        cf.set_created_time(&path, std::time::UNIX_EPOCH).unwrap();
        cf.set_modified_time(&path, std::time::UNIX_EPOCH).unwrap();
    }
    cf.into_inner().into_inner()
}
fn patch_directory(bytes: &[u8], name: &str, offset: usize, data: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let mut needle = utf16(name);
    needle.extend([0, 0]);
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    bytes[at + offset..at + offset + data.len()].copy_from_slice(data);
    bytes
}

pub(super) fn write(dir: &std::path::Path) {
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    let (digest, prehash) = recipe(true, crypto::Hash::Sha256);
    let package = content(&digest, crypto::Hash::Sha256);
    // Port each committed PE CMS/trust fault while preserving its specific fault.
    for name in PORTED {
        let pe_bytes = std::fs::read(dir.join(format!("{name}.exe"))).unwrap();
        let pe = pe::Pe::parse(&pe_bytes).unwrap();
        let sig = convert_cms(pe.certificates().unwrap()[0], &package);
        write(
            &format!("msi-{name}.msi"),
            &container(Some(&sig), Some(&prehash), cfb::Version::V3),
        );
    }
    let good = std::fs::read(dir.join("msi-good-pe64.msi")).unwrap();
    write(
        "msi-bad-stream-content.msi",
        &edit(&good, |cf| {
            cf.create_stream("Data")
                .unwrap()
                .write_all(&vec![0xac; 6000])
                .unwrap();
        }),
    );
    write(
        "msi-bad-extended-digest.msi",
        &edit(&good, |cf| {
            cf.create_stream(EX).unwrap().write_all(&[0; 32]).unwrap();
        }),
    );
    write(
        "msi-bad-extended-size.msi",
        &edit(&good, |cf| {
            cf.create_stream(EX).unwrap().write_all(&[0; 31]).unwrap();
        }),
    );
    write(
        "msi-bad-metadata-flags.msi",
        &edit(&good, |cf| {
            cf.set_state_bits("A", 1).unwrap();
        }),
    );
    write(
        "msi-bad-metadata-time.msi",
        &edit(&good, |cf| {
            cf.set_modified_time("Nested", std::time::UNIX_EPOCH + Duration::from_secs(1))
                .unwrap();
        }),
    );
    write(
        "msi-bad-metadata-name.msi",
        &patch_directory(&good, "AB", 0, &utf16("AC")),
    );
    write(
        "msi-bad-stream-size.msi",
        &patch_directory(&good, "Data", 120, &5999u64.to_le_bytes()),
    );
    write(
        "msi-bad-storage-clsid.msi",
        &edit(&good, |cf| {
            cf.set_storage_clsid(
                "Nested",
                "00000000-0000-0000-0000-000000000000".parse().unwrap(),
            )
            .unwrap();
        }),
    );
    let noex = content(&recipe(false, crypto::Hash::Sha256).0, crypto::Hash::Sha256);
    let sig = signer_info(
        identity(),
        der::one(&noex, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    let cms = signed_data(identity(), noex, cms::INDIRECT, sig);
    let legacy = container(Some(&cms), None, cfb::Version::V3);
    write("msi-good-legacy.msi", &legacy);
    write(
        "msi-bad-legacy-stream.msi",
        &edit(&legacy, |cf| {
            cf.create_stream("A").unwrap().write_all(b"tamper").unwrap();
        }),
    );
    write(
        "msi-bad-legacy-clsid.msi",
        &edit(&legacy, |cf| {
            cf.set_storage_clsid("/", "00000000-0000-0000-0000-000000000000".parse().unwrap())
                .unwrap();
        }),
    );
    let sig = cfb::CompoundFile::open(Cursor::new(good.clone()))
        .unwrap()
        .open_stream(SIG)
        .unwrap()
        .bytes()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    write(
        "msi-good-v4.msi",
        &container(Some(&sig), Some(&prehash), cfb::Version::V4),
    );
    write("msi-unsigned.msi", &container(None, None, cfb::Version::V3));
    write(
        "msi-bad-empty-signature.msi",
        &container(Some(&[]), None, cfb::Version::V3),
    );
    write(
        "msi-bad-malformed-cms.msi",
        &container(Some(&[0x30, 0]), None, cfb::Version::V3),
    );
    let mut payload = sig.clone();
    payload.push(1);
    write(
        "msi-bad-cms-trailer.msi",
        &container(Some(&payload), Some(&prehash), cfb::Version::V3),
    );
    write(
        "msi-bad-signature-storage.msi",
        &edit(&good, |cf| {
            cf.remove_stream(SIG).unwrap();
            cf.create_storage(SIG).unwrap();
        }),
    );
    write(
        "msi-bad-extended-storage.msi",
        &edit(&good, |cf| {
            cf.remove_stream(EX).unwrap();
            cf.create_storage(EX).unwrap();
        }),
    );
    write("msi-bad-truncated.msi", &good[..300]);
    let mut bad = good.clone();
    bad[30..32].copy_from_slice(&8u16.to_le_bytes());
    write("msi-bad-sector-size.msi", &bad);
    write(
        "msi-bad-directory-cycle.msi",
        &patch_directory(&good, "Root Entry", 76, &0u32.to_le_bytes()),
    );
    write(
        "msi-bad-stream-chain.msi",
        &patch_directory(&good, "Data", 116, &0xfffffff0u32.to_le_bytes()),
    );
    write(
        "msi-bad-stream-overflow.msi",
        &patch_directory(&good, "Data", 120, &u64::MAX.to_le_bytes()),
    );
    write(
        "msi-bad-name-length.msi",
        &patch_directory(&good, "Data", 64, &65u16.to_le_bytes()),
    );
    let wrong = image_content(&base_pe(true), true, None);
    let si = signer_info(
        identity(),
        der::one(&wrong, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    write(
        "msi-bad-sip-type.msi",
        &container(
            Some(&signed_data(identity(), wrong, cms::INDIRECT, si)),
            Some(&prehash),
            cfb::Version::V3,
        ),
    );
    write(
        "msi-bad-empty-extended.msi",
        &edit(&good, |cf| {
            cf.create_stream(EX).unwrap();
        }),
    );
    write(
        "msi-bad-nested-signature-stream.msi",
        &edit(&good, |cf| {
            cf.create_stream(format!("Nested/{SIG}"))
                .unwrap()
                .write_all(b"reserved")
                .unwrap();
        }),
    );
    write(
        "msi-bad-signature-name-case.msi",
        &patch_directory(&good, SIG, 2, &utf16("d")),
    );
    for (name, field, value) in [
        ("uuid", 1, tlv(4, &[0; 16])),
        ("version", 0, vec![2, 1, 3]),
        ("reserved", 2, vec![2, 1, 1]),
    ] {
        let mut body = fields(&package);
        let mut data = fields(&body[0]);
        let mut sip = fields(&data[1]);
        sip[field] = value;
        data[1] = seq(&sip);
        body[0] = seq(&data);
        let content = seq(&body);
        let si = signer_info(
            identity(),
            der::one(&content, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![],
            vec![],
        );
        write(
            &format!("msi-bad-sip-{name}.msi"),
            &container(
                Some(&signed_data(identity(), content, cms::INDIRECT, si)),
                Some(&prehash),
                cfb::Version::V3,
            ),
        );
    }
    let mut trailing = good.clone();
    trailing.push(1);
    write("msi-bad-trailing-data.msi", &trailing);
    write(
        "msi-bad-oversized-extended.msi",
        &edit(&good, |cf| {
            cf.create_stream(EX).unwrap().write_all(&[0; 65]).unwrap();
        }),
    );
    write(
        "msi-bad-storage-depth.msi",
        &edit(&good, |cf| {
            cf.create_storage_all(std::iter::repeat_n("N", 66).collect::<Vec<_>>().join("/"))
                .unwrap();
        }),
    );
    write(
        "msi-bad-total-stream-size.msi",
        &patch_directory(&good, "A", 120, &9000u64.to_le_bytes()),
    );
    let alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
    let mut alias = String::from("\u{5}");
    let chars: Vec<_> = "DigitalSignature".chars().collect();
    for pair in chars.chunks(2) {
        let a = alphabet.find(pair[0]).unwrap() as u32;
        alias.push(
            char::from_u32(if pair.len() == 2 {
                0x3800 + a + 64 * alphabet.find(pair[1]).unwrap() as u32
            } else {
                0x4800 + a
            })
            .unwrap(),
        );
    }
    write(
        "msi-bad-encoded-signature.msi",
        &edit(&good, |cf| {
            cf.create_stream(alias)
                .unwrap()
                .write_all(b"reserved")
                .unwrap();
        }),
    );
    let basic = signer_info(
        identity(),
        der::one(&package, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    let mut oversized = fields(&signed_data(
        identity(),
        package.clone(),
        cms::INDIRECT,
        basic.clone(),
    ));
    let mut sd = fields(der::one(&oversized[1], 0xa0).unwrap().body);
    let i = sd.len() - 1;
    for (name, count) in [("empty-signer-set", 0), ("signer-count", 65)] {
        sd[i] = tlv(0x31, &basic.repeat(count));
        oversized[1] = tlv(0xa0, &seq(&sd));
        write(
            &format!("msi-bad-{name}.msi"),
            &container(Some(&seq(&oversized)), Some(&prehash), cfb::Version::V3),
        );
    }
    let mut nested = signed_data(identity(), package.clone(), cms::INDIRECT, basic);
    for _ in 0..9 {
        let si = signer_info(
            identity(),
            der::one(&package, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![],
            vec![attr(cms::NESTED, nested)],
        );
        nested = signed_data(identity(), package.clone(), cms::INDIRECT, si);
    }
    write(
        "msi-bad-nested-depth.msi",
        &container(Some(&nested), Some(&prehash), cfb::Version::V3),
    );
    for (name, hash) in [
        ("sha384", crypto::Hash::Sha384),
        ("sha512", crypto::Hash::Sha512),
        ("sha1", crypto::Hash::Sha1),
    ] {
        let (digest, ex) = recipe(true, hash);
        let content = content(&digest, hash);
        let si = signer_info(
            identity(),
            der::one(&content, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![],
            vec![],
        );
        write(
            &format!("msi-good-{name}.msi"),
            &container(
                Some(&signed_data(identity(), content, cms::INDIRECT, si)),
                Some(&ex),
                cfb::Version::V3,
            ),
        );
    }
}

/// Optional interoperability maintenance helper. These public test constants
/// are never used outside fixtures; no private key is committed.
#[test]
#[ignore = "exports public test-only identity for an external fixture signer"]
fn export_msi_test_identity() {
    use ::der::EncodePem;
    use rand::SeedableRng;
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigner};
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use signature::Keypair;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let key = RsaSigner::<sha2::Sha256>::new(private.clone());
    let certificate = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(55u32),
        Validity {
            not_before: tm(NOW - 10000),
            not_after: tm(NOW + 10000),
        },
        Name::from_str("CN=rssig independent MSI test signer").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap(),
        &key,
    )
    .unwrap()
    .build::<RsaSignature>()
    .unwrap();
    let directory = std::env::temp_dir().join("rssig-msi-test-signing");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("key.pem"),
        private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    std::fs::write(
        directory.join("certificate.pem"),
        certificate.to_pem(LineEnding::LF).unwrap(),
    )
    .unwrap();
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
fn committed_msi_cms_and_trust_faults_have_valid_package_digests() {
    for source in PORTED {
        let name = format!("msi-{source}.msi");
        let bytes = committed(&name);
        let mut msi = crate::msi::Msi::parse(&bytes).unwrap();
        let sd = cms::SignedData::parse(msi.signature()).unwrap();
        let (hash, expected) = sd.package_digest().unwrap();
        let expected = expected.to_vec();
        assert_eq!(
            msi.digests(hash).unwrap().0,
            expected,
            "{name}: package checks must pass before the intended CMS/trust fault"
        );
    }
}

#[test]
fn committed_msi_attribute_faults_preserve_signature_math() {
    for name in [
        "bad-cms-content-digest",
        "bad-cms-content-type",
        "bad-signer-issuer",
        "bad-signer-serial",
        "bad-cms-digest-set",
    ] {
        let bytes = committed(&format!("msi-{name}.msi"));
        let msi = crate::msi::Msi::parse(&bytes).unwrap();
        let sd = cms::SignedData::parse(msi.signature()).unwrap();
        let si = sd.signers[0].children().unwrap();
        let mut attrs = si[3].full.to_vec();
        attrs[0] = 0x31;
        crypto::verify_spki(
            &sd.certs[0]
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            cms::algorithm(si[2]).unwrap(),
            si[4].children().unwrap()[0].body,
            &attrs,
            si[5].body,
        )
        .unwrap();
        assert!(sd.verify(sd.signers[0], false).is_err());
    }
}

#[test]
fn msi_library_dispatch_and_digest_reports_are_format_specific() {
    for name in [
        "msi-good-pe64.msi",
        "msi-good-legacy.msi",
        "msi-good-v4.msi",
        "msi-independent-jsign.msi",
    ] {
        let bytes = committed(name);
        let options = opts(None, false);
        let result = verify(&bytes, &options).unwrap();
        assert_eq!(result.format, "msi_authenticode");
        assert_eq!(result.signatures.len(), 1);
        assert!(result[0].image_digest.is_none());
        assert!(result[0].page_hashes.is_none());
        let digest = result[0].package_digest.as_ref().unwrap();
        assert_eq!(digest.expected, digest.computed);
        assert!(verify_msi(&bytes, &options).is_ok());
        assert!(verify_pe(&bytes, &options).is_err());
    }
    let pe = committed("good-pe64.exe");
    let options = opts(None, false);
    let result = verify(&pe, &options).unwrap();
    assert!(result[0].image_digest.is_some());
    assert!(result[0].package_digest.is_none());
    assert!(verify_msi(&pe, &options).is_err());
}

#[test]
fn signtool_fixture_digest_and_sign_padded_serial_are_verified() {
    let bytes = committed("msi-independent-signtool.msi");
    let mut msi = crate::msi::Msi::parse(&bytes).unwrap();
    let sd = cms::SignedData::parse(msi.signature()).unwrap();
    let (hash, expected) = sd.package_digest().unwrap();
    let expected = expected.to_vec();
    assert_eq!(
        domain::hex(&expected),
        "f38258e497510ffaa00a55c46751fdafbdea13fb"
    );
    let error = sd.verify(sd.signers[0], true).err().unwrap();
    let error = domain::VerificationError::from_internal(
        error,
        domain::ErrorCode::InternalError,
        domain::Stage::Cms,
    );
    assert_eq!(error.code, domain::ErrorCode::WeakAlgorithm);
    assert_eq!(error.details["key_bits"], 1024);
    assert_eq!(msi.digests(hash).unwrap().0, expected);
}

#[test]
fn truncated_msi_containers_fail_without_panicking() {
    let bytes = committed("msi-good-pe64.msi");
    for n in [0, 7, 8, 31, 32, 511, 512, 513, bytes.len() - 1] {
        let result = std::panic::catch_unwind(|| verify_msi(&bytes[..n], &opts(None, false)));
        assert!(result.is_ok(), "panic at {n}");
        assert!(result.unwrap().is_err(), "accepted truncation at {n}");
    }
}
