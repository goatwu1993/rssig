mod cab_fixtures;
mod fixture_faults;
mod msi_fixtures;
mod powershell_fixtures;

use super::*;
use ::der::{Encode, asn1::BitString};
use p256::ecdsa::{Signature, SigningKey};
use signature::Signer;
use std::{str::FromStr, sync::OnceLock, time::Duration};
use x509_cert::{
    Certificate,
    builder::{Builder, CertificateBuilder, Profile},
    ext::pkix::ExtendedKeyUsage,
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::{Time, Validity},
};

const NOW: u64 = 1_800_000_000;
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let len = (body.len() as u32).to_be_bytes();
        let first = len.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 | (4 - first) as u8);
        out.extend(&len[first..]);
    }
    out.extend(body);
    out
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn oid(value: &[u8]) -> Vec<u8> {
    tlv(6, value)
}
fn sha256_alg() -> Vec<u8> {
    seq(&[oid(&[96, 134, 72, 1, 101, 3, 4, 2, 1]), vec![5, 0]])
}
fn attr(id: &[u8], value: Vec<u8>) -> Vec<u8> {
    seq(&[oid(id), tlv(0x31, &value)])
}
fn tm(seconds: u64) -> Time {
    Time::GeneralTime(
        ::der::asn1::GeneralizedTime::from_unix_duration(Duration::from_secs(seconds)).unwrap(),
    )
}

struct Identity {
    key: SigningKey,
    cert: Certificate,
    root_key: SigningKey,
    root: Certificate,
}
fn identity() -> &'static Identity {
    static ID: OnceLock<Identity> = OnceLock::new();
    ID.get_or_init(|| {
        let root_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let key = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let validity = Validity {
            not_before: tm(NOW - 10000),
            not_after: tm(NOW + 10000),
        };
        let name = Name::from_str("CN=rssig test root").unwrap();
        let root = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            validity,
            name.clone(),
            SubjectPublicKeyInfoOwned::from_key(*root_key.verifying_key()).unwrap(),
            &root_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: name,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(2u32),
            validity,
            Name::from_str("CN=rssig test publisher").unwrap(),
            SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap(),
            &root_key,
        )
        .unwrap();
        builder
            .add_extension(&ExtendedKeyUsage(vec![
                ::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3"),
            ]))
            .unwrap();
        let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
        Identity {
            key,
            cert,
            root_key,
            root,
        }
    })
}

fn signer_info(
    id: &Identity,
    content: &[u8],
    content_type: Option<&[u8]>,
    extra_attrs: Vec<Vec<u8>>,
    unsigned: Vec<Vec<u8>>,
) -> Vec<u8> {
    let mut attrs = extra_attrs;
    if let Some(ct) = content_type {
        attrs.push(attr(&[42, 134, 72, 134, 247, 13, 1, 9, 3], oid(ct)));
    }
    attrs.push(attr(
        &[42, 134, 72, 134, 247, 13, 1, 9, 4],
        tlv(4, &crypto::Hash::Sha256.digest(content)),
    ));
    attrs.sort();
    let encoded = tlv(0x31, &attrs.concat());
    let signature: Signature = id.key.sign(&encoded);
    let sid = seq(&[
        id.cert.tbs_certificate.issuer.to_der().unwrap(),
        id.cert.tbs_certificate.serial_number.to_der().unwrap(),
    ]);
    let mut parts = vec![
        vec![2, 1, 1],
        sid,
        sha256_alg(),
        tlv(0xa0, &attrs.concat()),
        seq(&[oid(&[42, 134, 72, 206, 61, 4, 3, 2])]),
        tlv(4, signature.to_der().as_bytes()),
    ];
    if !unsigned.is_empty() {
        parts.push(tlv(0xa1, &unsigned.concat()));
    }
    seq(&parts)
}
fn signed_data(id: &Identity, content: Vec<u8>, content_type: &[u8], signer: Vec<u8>) -> Vec<u8> {
    signed_data_extra(id, content, content_type, signer, vec![])
}
fn signed_data_extra(
    id: &Identity,
    content: Vec<u8>,
    content_type: &[u8],
    signer: Vec<u8>,
    extra: Vec<Vec<u8>>,
) -> Vec<u8> {
    let ci = seq(&[oid(content_type), tlv(0xa0, &content)]);
    let certificates = [
        vec![id.cert.to_der().unwrap(), id.root.to_der().unwrap()],
        extra,
    ]
    .concat()
    .concat();
    seq(&[
        oid(cms::SIGNED_DATA),
        tlv(
            0xa0,
            &seq(&[
                vec![2, 1, 1],
                tlv(0x31, &sha256_alg()),
                ci,
                tlv(0xa0, &certificates),
                tlv(0x31, &signer),
            ]),
        ),
    ])
}
fn base_pe(plus: bool) -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
    bytes[128..132].copy_from_slice(b"PE\0\0");
    bytes[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[134..136].copy_from_slice(&1u16.to_le_bytes());
    let opt = 152;
    let opt_len = if plus { 240 } else { 224 };
    bytes[148..150].copy_from_slice(&(opt_len as u16).to_le_bytes());
    bytes[opt..opt + 2].copy_from_slice(&(if plus { 0x20bu16 } else { 0x10bu16 }).to_le_bytes());
    bytes[opt + 36..opt + 40].copy_from_slice(&512u32.to_le_bytes());
    bytes[opt + 60..opt + 64].copy_from_slice(&512u32.to_le_bytes());
    let num = opt + if plus { 108 } else { 92 };
    bytes[num..num + 4].copy_from_slice(&16u32.to_le_bytes());
    let section = opt + opt_len;
    bytes[section + 16..section + 20].copy_from_slice(&512u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
    bytes[512..].fill(0xab);
    bytes
}
fn attach(mut bytes: Vec<u8>, signature: &[u8], plus: bool) -> Vec<u8> {
    let directory = 152 + if plus { 144 } else { 128 };
    let start = bytes.len();
    let len = 8 + signature.len();
    let size = (len + 7) & !7;
    bytes[directory..directory + 4].copy_from_slice(&(start as u32).to_le_bytes());
    bytes[directory + 4..directory + 8].copy_from_slice(&(size as u32).to_le_bytes());
    bytes.extend((len as u32).to_le_bytes());
    bytes.extend([0, 2, 2, 0]);
    bytes.extend(signature);
    bytes.resize(start + size, 0);
    bytes
}
fn image_content(bytes: &[u8], plus: bool, pages: Option<Vec<u8>>) -> Vec<u8> {
    let d = 152 + if plus { 144 } else { 128 };
    let digest =
        crypto::Hash::Sha256.digest(&[&bytes[..216], &bytes[220..d], &bytes[d + 8..1024]].concat());
    let link = match pages {
        None => tlv(0xa2, &tlv(0x80, &[])),
        Some(pages) => {
            let hashes = tlv(
                0x31,
                &seq(&[
                    oid(&[43, 6, 1, 4, 1, 130, 55, 2, 3, 2]),
                    tlv(0x31, &tlv(4, &pages)),
                ]),
            );
            tlv(
                0xa1,
                &[
                    tlv(
                        4,
                        &[
                            0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 5, 0xa2, 0x17,
                            0xda, 0x8e, 0x60, 0xd6,
                        ],
                    ),
                    tlv(4, &hashes),
                ]
                .concat(),
            )
        }
    };
    seq(&[
        seq(&[
            oid(&[43, 6, 1, 4, 1, 130, 55, 2, 1, 15]),
            seq(&[vec![3, 1, 0], tlv(0xa0, &link)]),
        ]),
        seq(&[sha256_alg(), tlv(4, &digest)]),
    ])
}
fn make_pe(plus: bool, pages: bool, nested: bool) -> Vec<u8> {
    let id = identity();
    let base = base_pe(plus);
    let page_hashes = if pages {
        Some(
            pe::Pe::parse(&attach(base.clone(), &[0x30, 0], plus))
                .unwrap()
                .page_hashes(crypto::Hash::Sha256)
                .unwrap(),
        )
    } else {
        None
    };
    let content = image_content(&base, plus, page_hashes);
    let content_body = der::one(&content, 0x30).unwrap().body;
    let unsigned = if nested {
        let inner = signer_info(id, content_body, Some(cms::INDIRECT), vec![], vec![]);
        vec![attr(
            cms::NESTED,
            signed_data(id, content.clone(), cms::INDIRECT, inner),
        )]
    } else {
        vec![]
    };
    let si = signer_info(id, content_body, Some(cms::INDIRECT), vec![], unsigned);
    attach(base, &signed_data(id, content, cms::INDIRECT, si), plus)
}
fn opts(trust: Option<&TrustStore>, revocation: bool) -> VerifyOptions<'_> {
    VerifyOptions {
        trust,
        check_revocation: revocation,
        allow_sha1: false,
        now: NOW,
    }
}
fn trust() -> TrustStore {
    let mut trust = TrustStore::default();
    trust.add_roots(&identity().root.to_der().unwrap()).unwrap();
    trust
}

#[test]
fn verifies_pe32_and_pe32plus_and_nested_signatures() {
    for plus in [false, true] {
        let reports = verify_pe(&make_pe(plus, false, true), &opts(Some(&trust()), false)).unwrap();
        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|r| r.chain_trusted));
        assert_eq!(reports[1].nested_depth, 1);
    }
}
#[test]
fn validates_page_hashes_and_image_integrity() {
    let mut bytes = make_pe(true, true, false);
    verify_pe(&bytes, &opts(Some(&trust()), false)).unwrap();
    bytes[700] ^= 1;
    assert!(
        verify_pe(&bytes, &opts(None, false))
            .unwrap_err()
            .to_string()
            .contains("image digest mismatch")
    );
}
#[test]
fn checksum_is_excluded_but_section_data_is_not() {
    let mut bytes = make_pe(false, false, false);
    bytes[216..220].copy_from_slice(&[1, 2, 3, 4]);
    verify_pe(&bytes, &opts(None, false)).unwrap();
    bytes[900] ^= 1;
    assert!(verify_pe(&bytes, &opts(None, false)).is_err());
}
#[test]
fn rejects_signature_tampering_untrusted_and_expired_certificates() {
    let bytes = make_pe(true, false, false);
    assert!(verify_pe(&bytes, &opts(Some(&TrustStore::default()), false)).is_err());
    let store = trust();
    let mut options = opts(Some(&store), false);
    options.now += 20000;
    assert!(verify_pe(&bytes, &options).is_err());
    let mut bytes = bytes;
    let last = bytes.iter().rposition(|b| *b != 0).unwrap();
    bytes[last] ^= 1;
    assert!(verify_pe(&bytes, &opts(None, false)).is_err());
}
fn crl(revoked: bool, expired: bool) -> Vec<u8> {
    use x509_cert::{
        Version,
        crl::{CertificateList, RevokedCert, TbsCertList},
    };
    let id = identity();
    let algorithm = id.root.signature_algorithm.clone();
    let tbs = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer: id.root.tbs_certificate.subject.clone(),
        this_update: tm(NOW - 100),
        next_update: Some(tm(if expired { NOW - 1 } else { NOW + 1000 })),
        revoked_certificates: if revoked {
            Some(vec![RevokedCert {
                serial_number: id.cert.tbs_certificate.serial_number.clone(),
                revocation_date: tm(NOW - 50),
                crl_entry_extensions: None,
            }])
        } else {
            None
        },
        crl_extensions: Some(vec![x509_cert::ext::Extension {
            extn_id: ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20"),
            critical: false,
            extn_value: ::der::asn1::OctetString::new([2, 1, 1]).unwrap(),
        }]),
    };
    let sig: Signature = id.root_key.sign(&tbs.to_der().unwrap());
    CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
    }
    .to_der()
    .unwrap()
}
#[test]
fn crls_are_required_authenticated_fresh_and_enforced() {
    let bytes = make_pe(true, false, false);
    assert!(verify_pe(&bytes, &opts(Some(&trust()), true)).is_err());
    for (revoked, expired, valid) in [
        (false, false, true),
        (true, false, false),
        (false, true, false),
    ] {
        let mut trust = trust();
        trust.add_crl(&crl(revoked, expired)).unwrap();
        let result = verify_pe(&bytes, &opts(Some(&trust), true));
        assert_eq!(result.is_ok(), valid, "{result:?}");
    }
    let mut forged = crl(false, false);
    *forged.last_mut().unwrap() ^= 1;
    let mut trust = trust();
    trust.add_crl(&forged).unwrap();
    assert!(verify_pe(&bytes, &opts(Some(&trust), true)).is_err());
}
#[test]
fn truncated_and_malformed_files_never_panic() {
    let bytes = make_pe(true, false, false);
    for n in 0..bytes.len() {
        assert!(verify_pe(&bytes[..n], &opts(None, false)).is_err());
    }
    let mut overlap = bytes.clone();
    overlap[392 + 20..392 + 24].copy_from_slice(&4u32.to_le_bytes());
    assert!(verify_pe(&overlap, &opts(None, false)).is_err());
    let mut trailer = bytes;
    trailer.push(0);
    assert!(verify_pe(&trailer, &opts(None, false)).is_err());
}
#[test]
fn strict_der_rejects_indefinite_and_nonminimal_lengths() {
    for input in [
        &[0x30, 0x80][..],
        &[4, 0x81, 0][..],
        &[4, 0x82, 0, 0x80][..],
        &[4, 0xff][..],
    ] {
        assert!(der::take(&mut &input[..]).is_err());
    }
}

fn tsa_identity() -> Identity {
    let root = identity();
    let key = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: root.root.tbs_certificate.subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(3u32),
        Validity {
            not_before: tm(NOW - 10000),
            not_after: tm(NOW + 10000),
        },
        Name::from_str("CN=rssig test TSA").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap(),
        &root.root_key,
    )
    .unwrap();
    builder
        .add_extension(&ExtendedKeyUsage(vec![
            ::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8"),
        ]))
        .unwrap();
    let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
    Identity {
        key,
        cert,
        root: root.root.clone(),
        root_key: root.root_key.clone(),
    }
}
fn timestamped_pe(legacy: bool, bad_imprint: bool, wrong_eku: bool, time: u64) -> Vec<u8> {
    let id = identity();
    let tsa = tsa_identity();
    let tsa = if wrong_eku { id } else { &tsa };
    let base = base_pe(true);
    let content = image_content(&base, true, None);
    let content_body = der::one(&content, 0x30).unwrap().body;
    let si = signer_info(id, content_body, Some(cms::INDIRECT), vec![], vec![]);
    let parent = der::one(&si, 0x30).unwrap().children().unwrap()[5].body;
    let mut digest = crypto::Hash::Sha256.digest(parent);
    if bad_imprint {
        digest[0] ^= 1;
    }
    let timestamp = if legacy {
        attr(
            cms::COUNTERSIGN,
            signer_info(
                tsa,
                if bad_imprint { &digest } else { parent },
                None,
                vec![attr(
                    &[42, 134, 72, 134, 247, 13, 1, 9, 5],
                    tm(time).to_der().unwrap(),
                )],
                vec![],
            ),
        )
    } else {
        let info = seq(&[
            vec![2, 1, 1],
            oid(&[42, 3, 4]),
            seq(&[sha256_alg(), tlv(4, &digest)]),
            vec![2, 1, 1],
            tm(time).to_der().unwrap(),
        ]);
        let ts = signer_info(tsa, &info, Some(cms::TST_INFO), vec![], vec![]);
        attr(
            cms::RFC3161,
            signed_data(tsa, tlv(4, &info), cms::TST_INFO, ts),
        )
    };
    let si = signer_info(
        id,
        content_body,
        Some(cms::INDIRECT),
        vec![],
        vec![timestamp],
    );
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
#[test]
fn rfc3161_and_legacy_timestamps_authenticate_time_and_extend_validity() {
    let store = trust();
    for legacy in [false, true] {
        let bytes = timestamped_pe(legacy, false, false, NOW);
        let mut options = opts(Some(&store), false);
        options.now += 20000; // Both leaf and TSA certificates have expired now.
        let report = verify_pe(&bytes, &options).unwrap();
        assert_eq!(report[0].timestamp, Some(NOW));
        for bytes in [
            timestamped_pe(legacy, true, false, NOW),
            timestamped_pe(legacy, false, true, NOW),
            timestamped_pe(legacy, false, false, NOW + 50000),
        ] {
            assert!(verify_pe(&bytes, &options).is_err());
        }
    }
}

#[test]
fn rsa_pkcs1_signature_and_chain_use_rustcrypto() {
    use rand::SeedableRng;
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigner};
    use signature::{Keypair, SignatureEncoding};
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let key = RsaSigner::<sha2::Sha256>::new(rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap());
    let public = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap();
    let valid = Validity {
        not_before: tm(NOW - 100),
        not_after: tm(NOW + 100),
    };
    let root = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        valid,
        Name::from_str("CN=RSA test root").unwrap(),
        public.clone(),
        &key,
    )
    .unwrap()
    .build::<RsaSignature>()
    .unwrap();
    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: root.tbs_certificate.subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(2u32),
        valid,
        Name::from_str("CN=RSA test signer").unwrap(),
        public,
        &key,
    )
    .unwrap();
    builder
        .add_extension(&ExtendedKeyUsage(vec![
            ::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3"),
        ]))
        .unwrap();
    let cert = builder.build::<RsaSignature>().unwrap();
    let base = base_pe(true);
    let content = image_content(&base, true, None);
    let mut attrs = [
        attr(&[42, 134, 72, 134, 247, 13, 1, 9, 3], oid(cms::INDIRECT)),
        attr(
            &[42, 134, 72, 134, 247, 13, 1, 9, 4],
            tlv(
                4,
                &crypto::Hash::Sha256.digest(der::one(&content, 0x30).unwrap().body),
            ),
        ),
    ];
    attrs.sort();
    let signature: RsaSignature = key.sign(&tlv(0x31, &attrs.concat()));
    let sid = seq(&[
        cert.tbs_certificate.issuer.to_der().unwrap(),
        cert.tbs_certificate.serial_number.to_der().unwrap(),
    ]);
    let si = seq(&[
        vec![2, 1, 1],
        sid,
        sha256_alg(),
        tlv(0xa0, &attrs.concat()),
        seq(&[oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]), vec![5, 0]]),
        tlv(4, &signature.to_vec()),
    ]);
    let ci = seq(&[oid(cms::INDIRECT), tlv(0xa0, &content)]);
    let sd = seq(&[
        oid(cms::SIGNED_DATA),
        tlv(
            0xa0,
            &seq(&[
                vec![2, 1, 1],
                tlv(0x31, &sha256_alg()),
                ci,
                tlv(
                    0xa0,
                    &[cert.to_der().unwrap(), root.to_der().unwrap()].concat(),
                ),
                tlv(0x31, &si),
            ]),
        ),
    ]);
    let bytes = attach(base, &sd, true);
    let mut store = TrustStore::default();
    store.add_roots(&root.to_der().unwrap()).unwrap();
    assert!(verify_pe(&bytes, &opts(Some(&store), false)).is_ok());
    // Exercise the other advertised RSA digest algorithms directly.
    for (hash, alg, sig) in [
        (crypto::Hash::Sha384, 12, {
            let k = RsaSigner::<sha2::Sha384>::new(key.as_ref().clone());
            let s: RsaSignature = k.sign(b"message");
            s.to_vec()
        }),
        (crypto::Hash::Sha512, 13, {
            let k = RsaSigner::<sha2::Sha512>::new(key.as_ref().clone());
            let s: RsaSignature = k.sign(b"message");
            s.to_vec()
        }),
    ] {
        crypto::verify_spki(
            &cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            hash,
            &[42, 134, 72, 134, 247, 13, 1, 1, alg],
            b"message",
            &sig,
        )
        .unwrap();
    }
}

/// Explicit maintenance command; never runs during ordinary tests.
#[test]
#[ignore = "regenerates committed binary fixtures; run explicitly and review the diff"]
fn regenerate_cli_fixtures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    fixture_faults::write(&dir);
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    let good = make_pe(true, false, false);
    let mutate_oid = |needle: &[u8]| {
        let mut bytes = good.clone();
        let at = bytes
            .windows(needle.len())
            .rposition(|w| w == needle)
            .unwrap();
        bytes[at + needle.len() - 1] = 127;
        bytes
    };
    write(
        "unsupported-signature-algorithm.exe",
        &mutate_oid(&[6, 8, 42, 134, 72, 206, 61, 4, 3, 2]),
    );
    write(
        "unsupported-digest-algorithm.exe",
        &mutate_oid(&[6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1]),
    );
    let length = u32::from_le_bytes(good[1024..1028].try_into().unwrap()) as usize;
    let mut payload = good[1032..1024 + length].to_vec();
    payload.push(1);
    write(
        "bad-certificate-payload.exe",
        &attach(base_pe(true), &payload, true),
    );
    write("good-pe32.exe", &make_pe(false, false, false));
    write("good-pe64.exe", &good);
    write("good-intermediate.exe", &intermediate_pe(false));
    write("bad-ca-key-usage.exe", &intermediate_pe(true));
    write("good-page-hashes.exe", &make_pe(true, true, false));
    write("good-nested.exe", &make_pe(true, false, true));
    write(
        "good-rfc3161.exe",
        &timestamped_pe(false, false, false, NOW),
    );
    write(
        "good-countersignature.exe",
        &timestamped_pe(true, false, false, NOW),
    );
    write(
        "bad-timestamp-imprint.exe",
        &timestamped_pe(false, true, false, NOW),
    );
    write(
        "bad-timestamp-eku.exe",
        &timestamped_pe(false, false, true, NOW),
    );
    write(
        "bad-future-timestamp.exe",
        &timestamped_pe(false, false, false, NOW + 50000),
    );
    let mut modified = good.clone();
    modified[700] ^= 1;
    write("bad-image-digest.exe", &modified);
    let mut modified = good.clone();
    let end = modified.iter().rposition(|b| *b != 0).unwrap();
    modified[end] ^= 1;
    write("bad-cms-signature.exe", &modified);
    let mut modified = good.clone();
    modified[216..220].copy_from_slice(&[1, 2, 3, 4]);
    write("good-modified-checksum.exe", &modified);
    let mut modified = good.clone();
    modified.push(0);
    write("bad-trailing-data.exe", &modified);
    write("bad-truncated.exe", &good[..200]);
    write("unsigned.exe", &base_pe(true));
    write("not-pe.bin", b"not a Windows executable\n");
    write("root.der", &identity().root.to_der().unwrap());
    write("good.crl", &crl(false, false));
    write("revoked.crl", &crl(true, false));
    write("expired.crl", &crl(false, true));
    let mut forged = crl(false, false);
    *forged.last_mut().unwrap() ^= 1;
    write("forged.crl", &forged);
    let key = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
    let root = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity {
            not_before: tm(NOW - 10000),
            not_after: tm(NOW + 10000),
        },
        Name::from_str("CN=unrelated test root").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap(),
        &key,
    )
    .unwrap()
    .build::<p256::ecdsa::DerSignature>()
    .unwrap();
    write("unrelated-root.der", &root.to_der().unwrap());
    // A valid CMS signature containing deliberately wrong page hashes.
    let base = base_pe(true);
    let content = image_content(&base, true, Some(vec![0; 72]));
    let si = signer_info(
        identity(),
        der::one(&content, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    write(
        "bad-page-hashes.exe",
        &attach(
            base,
            &signed_data(identity(), content, cms::INDIRECT, si),
            true,
        ),
    );
    msi_fixtures::write(&dir);
    cab_fixtures::write(&dir);
    powershell_fixtures::write(&dir);
}

fn intermediate_pe(bad_key_usage: bool) -> Vec<u8> {
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
    let id = identity();
    let ca_key = SigningKey::from_bytes((&[15u8; 32]).into()).unwrap();
    let name = Name::from_str("CN=rssig intermediate").unwrap();
    let validity = Validity {
        not_before: tm(NOW - 10000),
        not_after: tm(NOW + 10000),
    };
    let mut ca = CertificateBuilder::new(
        Profile::SubCA {
            issuer: id.root.tbs_certificate.subject.clone(),
            path_len_constraint: Some(0),
        },
        SerialNumber::from(4u32),
        validity,
        name.clone(),
        SubjectPublicKeyInfoOwned::from_key(*ca_key.verifying_key()).unwrap(),
        &id.root_key,
    )
    .unwrap()
    .build::<p256::ecdsa::DerSignature>()
    .unwrap();
    if bad_key_usage {
        let ku = ca
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|ext| ext.extn_id.to_string() == "2.5.29.15")
            .unwrap();
        ku.extn_value = ::der::asn1::OctetString::new(
            KeyUsage(KeyUsages::DigitalSignature.into())
                .to_der()
                .unwrap(),
        )
        .unwrap();
        let sig: Signature = id.root_key.sign(&ca.tbs_certificate.to_der().unwrap());
        ca.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    }
    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: name,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(5u32),
        validity,
        id.cert.tbs_certificate.subject.clone(),
        id.cert.tbs_certificate.subject_public_key_info.clone(),
        &ca_key,
    )
    .unwrap();
    builder
        .add_extension(&ExtendedKeyUsage(vec![
            ::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3"),
        ]))
        .unwrap();
    let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
    let publisher = Identity {
        key: id.key.clone(),
        cert,
        root: ca,
        root_key: ca_key,
    };
    let base = base_pe(true);
    let content = image_content(&base, true, None);
    let si = signer_info(
        &publisher,
        der::one(&content, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    attach(
        base,
        &signed_data(&publisher, content, cms::INDIRECT, si),
        true,
    )
}
