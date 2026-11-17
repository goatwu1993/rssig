//! SEC-09 deterministic lifetime-signing and time-boundary fixtures.
use super::*;
use ::der::asn1::ObjectIdentifier;

const LIFETIME_SIGNING: &str = "1.3.6.1.4.1.311.10.3.13";
const SIGNING_TIME: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 5];
const LEAF_SERIAL: u32 = 902;
/// Serial of the second rolled-over intermediate (901 + 10 * index).
const VALID_ROLLOVER_SERIAL: u32 = 911;

enum Stamp {
    None,
    Rfc(i64, Option<&'static str>),
    Counter(i64),
}

/// One embedded intermediate CA.
struct Ca {
    window: (i64, i64),
    key_cert_sign: bool,
}

fn ca(not_before: i64, not_after: i64) -> Ca {
    Ca {
        window: (not_before, not_after),
        key_cert_sign: true,
    }
}

fn no_cert_sign(not_before: i64, not_after: i64) -> Ca {
    Ca {
        key_cert_sign: false,
        ..ca(not_before, not_after)
    }
}

/// Who issues the leaf, in embedded order.
enum Issuers {
    /// The configured root.
    Root,
    /// Intermediates sharing one subject and key, each issued by the root.
    /// The first embedded one is tried first.
    Rollover(Vec<Ca>),
    /// One path of distinct intermediates: the first issues the leaf and the
    /// last is issued by the root.
    Chain(Vec<Ca>),
}

impl Issuers {
    fn cas(&self) -> &[Ca] {
        match self {
            Self::Root => &[],
            Self::Rollover(cas) | Self::Chain(cas) => cas,
        }
    }
}

/// What carries the SEC-09 signer.
#[derive(Clone, Copy, PartialEq)]
enum Container {
    /// The only signature of a PE.
    Pe,
    /// The nested signature of a PE whose primary signer is the ordinary
    /// test publisher.
    NestedPe,
    /// A direct RDP signature over the canonical settings.
    Rdp,
}

struct Spec {
    label: &'static str,
    container: Container,
    leaf: (i64, i64),
    lifetime: bool,
    issuers: Issuers,
    stamp: Stamp,
}

pub(super) const LABELS: &[&str] = &[
    "expired-timestamped",
    "lifetime-expired",
    "lifetime-counter-expired",
    "lifetime-valid",
    "lifetime-before-not-before",
    "timestamp-before-not-before",
    "lifetime-untimestamped",
    "leaf-not-after-exact",
    "leaf-not-after-fraction",
    "leaf-not-before-fraction-inside",
    "leaf-not-before-fraction-early",
    "intermediate-not-after-exact",
    "intermediate-not-after-fraction",
    "intermediate-expired",
    "intermediate-not-before-fraction-inside",
    "intermediate-not-before-fraction-early",
    "untimestamped",
    "counter-expired-timestamped",
    "lifetime-intermediate-late",
    "lifetime-intermediate-rollover",
    "lifetime-intermediate-late-ca-usage",
    "lifetime-intermediate-ca-usage-late",
    "lifetime-chain-ca-usage-late",
    "lifetime-chain-late-ca-usage",
    "nested-expired-timestamped",
    "lifetime-nested-expired",
    "rdp-expired-timestamped",
    "lifetime-rdp-expired",
    "lifetime-leaf-not-before-exact",
    "lifetime-leaf-not-before-early",
    "lifetime-intermediate-not-before-exact",
    "lifetime-intermediate-not-before-early",
];

fn spec(label: &'static str) -> Spec {
    use Issuers::{Chain, Rollover, Root};
    let (leaf, lifetime, issuers, stamp) = match label {
        // The same pair in a nested PE signature and in an RDP signature.
        "expired-timestamped" | "nested-expired-timestamped" | "rdp-expired-timestamped" => {
            ((-9000, -1000), false, Root, Stamp::Rfc(-5000, None))
        }
        "lifetime-expired" | "lifetime-nested-expired" | "lifetime-rdp-expired" => {
            ((-9000, -1000), true, Root, Stamp::Rfc(-5000, None))
        }
        "lifetime-counter-expired" => ((-9000, -1000), true, Root, Stamp::Counter(-5000)),
        "lifetime-valid" => ((-9000, 0), true, Root, Stamp::Rfc(-5000, None)),
        "lifetime-before-not-before" => ((-4000, 9000), true, Root, Stamp::Rfc(-5000, None)),
        "timestamp-before-not-before" => ((-4000, 9000), false, Root, Stamp::Rfc(-5000, None)),
        "lifetime-untimestamped" => ((-9000, 9000), true, Root, Stamp::None),
        "leaf-not-after-exact" => ((-9000, -2000), false, Root, Stamp::Rfc(-2000, None)),
        "leaf-not-after-fraction" => ((-9000, -2000), false, Root, Stamp::Rfc(-2000, Some("5"))),
        "leaf-not-before-fraction-inside" => {
            ((-3000, 9000), false, Root, Stamp::Rfc(-3000, Some("5")))
        }
        "leaf-not-before-fraction-early" => {
            ((-3000, 9000), false, Root, Stamp::Rfc(-3001, Some("5")))
        }
        "intermediate-not-after-exact" => (
            (-9000, 9000),
            false,
            Rollover(vec![ca(-9000, -2000)]),
            Stamp::Rfc(-2000, None),
        ),
        "intermediate-not-after-fraction" => (
            (-9000, 9000),
            false,
            Rollover(vec![ca(-9000, -2000)]),
            Stamp::Rfc(-2000, Some("5")),
        ),
        "intermediate-expired" => (
            (-9000, 9000),
            false,
            Rollover(vec![ca(-9000, -2000)]),
            Stamp::Rfc(-1999, None),
        ),
        "intermediate-not-before-fraction-inside" => (
            (-9000, 9000),
            false,
            Rollover(vec![ca(-3000, 9000)]),
            Stamp::Rfc(-3000, Some("5")),
        ),
        "intermediate-not-before-fraction-early" => (
            (-9000, 9000),
            false,
            Rollover(vec![ca(-3000, 9000)]),
            Stamp::Rfc(-3001, Some("5")),
        ),
        "untimestamped" => ((-100, 100), false, Root, Stamp::None),
        "counter-expired-timestamped" => ((-9000, -1000), false, Root, Stamp::Counter(-5000)),
        "lifetime-intermediate-late" => (
            (-9000, 9000),
            true,
            Rollover(vec![ca(-4000, 9000)]),
            Stamp::Rfc(-5000, None),
        ),
        // The issuer valid at signing lacks keyCertSign, in either order.
        "lifetime-intermediate-late-ca-usage" => (
            (-9000, 9000),
            true,
            Rollover(vec![ca(-4000, 9000), no_cert_sign(-9000, 9000)]),
            Stamp::Rfc(-5000, None),
        ),
        "lifetime-intermediate-ca-usage-late" => (
            (-9000, 9000),
            true,
            Rollover(vec![no_cert_sign(-9000, 9000), ca(-4000, 9000)]),
            Stamp::Rfc(-5000, None),
        ),
        // Both defects on one path: leaf <- first <- second <- root.
        "lifetime-chain-ca-usage-late" => (
            (-9000, 9000),
            true,
            Chain(vec![no_cert_sign(-9000, 9000), ca(-4000, 9000)]),
            Stamp::Rfc(-5000, None),
        ),
        "lifetime-chain-late-ca-usage" => (
            (-9000, 9000),
            true,
            Chain(vec![ca(-4000, 9000), no_cert_sign(-9000, 9000)]),
            Stamp::Rfc(-5000, None),
        ),
        // A rollover issuer valid now but issued after signing is tried first.
        "lifetime-intermediate-rollover" => (
            (-9000, 9000),
            true,
            Rollover(vec![ca(-4000, 9000), ca(-9000, 9000)]),
            Stamp::Rfc(-5000, None),
        ),
        // The signing-time check is inclusive: notBefore equal to the
        // timestamp is valid, one second later is not.
        "lifetime-leaf-not-before-exact" => ((-5000, 9000), true, Root, Stamp::Rfc(-5000, None)),
        "lifetime-leaf-not-before-early" => ((-4999, 9000), true, Root, Stamp::Rfc(-5000, None)),
        "lifetime-intermediate-not-before-exact" => (
            (-9000, 9000),
            true,
            Rollover(vec![ca(-5000, 9000)]),
            Stamp::Rfc(-5000, None),
        ),
        "lifetime-intermediate-not-before-early" => (
            (-9000, 9000),
            true,
            Rollover(vec![ca(-4999, 9000)]),
            Stamp::Rfc(-5000, None),
        ),
        _ => unreachable!("{label}"),
    };
    let container = match label {
        "nested-expired-timestamped" | "lifetime-nested-expired" => Container::NestedPe,
        "rdp-expired-timestamped" | "lifetime-rdp-expired" => Container::Rdp,
        _ => Container::Pe,
    };
    Spec {
        label,
        container,
        leaf,
        lifetime,
        issuers,
        stamp,
    }
}

fn at(offset: i64) -> u64 {
    NOW.checked_add_signed(offset).unwrap()
}

fn validity((not_before, not_after): (i64, i64)) -> Validity {
    Validity {
        not_before: tm(at(not_before)),
        not_after: tm(at(not_after)),
    }
}

fn file_name(spec: &Spec) -> String {
    let extension = match spec.container {
        Container::Rdp => "rdp",
        Container::Pe | Container::NestedPe => "exe",
    };
    format!("sec09-{}.{extension}", spec.label)
}

fn intermediate_key(spec: &Spec, index: usize) -> SigningKey {
    let chained = matches!(spec.issuers, Issuers::Chain(_));
    let byte = if chained && index > 0 { 63 } else { 61 };
    SigningKey::from_bytes((&[byte; 32]).into()).unwrap()
}

fn leaf_key() -> SigningKey {
    SigningKey::from_bytes((&[62u8; 32]).into()).unwrap()
}

/// The SEC-09 signer identity and its embedded intermediates.
fn signer(spec: &Spec) -> (Identity, Vec<Certificate>) {
    let root = identity();
    let root_name = root.root.tbs_certificate.subject.clone();
    let cas = spec.issuers.cas();
    let chained = matches!(spec.issuers, Issuers::Chain(_));
    let keys: Vec<_> = (0..cas.len())
        .map(|index| intermediate_key(spec, index))
        .collect();
    let name = |index: usize| {
        if chained {
            Name::from_str(&format!("CN=SEC-09 intermediate {index}")).unwrap()
        } else {
            Name::from_str("CN=SEC-09 intermediate").unwrap()
        }
    };
    let intermediates: Vec<Certificate> = (0..cas.len())
        .map(|index| {
            let (issuer_name, issuer_key) = if chained && index + 1 < cas.len() {
                (name(index + 1), &keys[index + 1])
            } else {
                (root_name.clone(), &root.root_key)
            };
            let mut cert = CertificateBuilder::new(
                Profile::SubCA {
                    issuer: issuer_name,
                    path_len_constraint: None,
                },
                SerialNumber::from(901 + 10 * index as u32),
                validity(cas[index].window),
                name(index),
                SubjectPublicKeyInfoOwned::from_key(*keys[index].verifying_key()).unwrap(),
                issuer_key,
            )
            .unwrap()
            .build::<p256::ecdsa::DerSignature>()
            .unwrap();
            if !cas[index].key_cert_sign {
                let ku = cert
                    .tbs_certificate
                    .extensions
                    .as_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|e| e.extn_id.to_string() == "2.5.29.15")
                    .unwrap();
                ku.extn_value = ::der::asn1::OctetString::new(
                    x509_cert::ext::pkix::KeyUsage(
                        x509_cert::ext::pkix::KeyUsages::DigitalSignature.into(),
                    )
                    .to_der()
                    .unwrap(),
                )
                .unwrap();
                let sig: Signature = issuer_key.sign(&cert.tbs_certificate.to_der().unwrap());
                cert.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
            }
            cert
        })
        .collect();
    let (issuer, issuer_key) = match intermediates.first() {
        Some(cert) => (cert.tbs_certificate.subject.clone(), &keys[0]),
        None => (root_name, &root.root_key),
    };
    let key = leaf_key();
    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(LEAF_SERIAL),
        validity(spec.leaf),
        Name::from_str(&format!("CN=SEC-09 {}", spec.label)).unwrap(),
        SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap(),
        issuer_key,
    )
    .unwrap();
    let mut usages = vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3")];
    if spec.lifetime {
        usages.push(ObjectIdentifier::new_unwrap(LIFETIME_SIGNING));
    }
    builder.add_extension(&ExtendedKeyUsage(usages)).unwrap();
    let id = Identity {
        key,
        cert: builder.build::<p256::ecdsa::DerSignature>().unwrap(),
        root_key: root.root_key.clone(),
        root: root.root.clone(),
    };
    (id, intermediates)
}

/// Unsigned timestamp attributes over the parent signature value.
fn timestamp(stamp: &Stamp, parent: &[u8]) -> Vec<Vec<u8>> {
    let tsa = tsa_identity();
    match *stamp {
        Stamp::None => vec![],
        Stamp::Rfc(offset, fraction) => {
            let encoded = tm(at(offset)).to_der().unwrap();
            let mut text = der::one(&encoded, 0x18).unwrap().body[..14].to_vec();
            if let Some(fraction) = fraction {
                text.push(b'.');
                text.extend(fraction.as_bytes());
            }
            text.push(b'Z');
            let info = seq(&[
                tlv(2, &[1]),
                oid(&[42, 3, 4]),
                seq(&[sha256_alg(), tlv(4, &crypto::Hash::Sha256.digest(parent))]),
                tlv(2, &[9]),
                tlv(0x18, &text),
            ]);
            let token = signed_data(
                &tsa,
                tlv(4, &info),
                cms::TST_INFO,
                signer_info(&tsa, &info, Some(cms::TST_INFO), vec![], vec![]),
            );
            vec![attr(cms::RFC3161, token)]
        }
        Stamp::Counter(offset) => vec![attr(
            cms::COUNTERSIGN,
            signer_info(
                &tsa,
                parent,
                None,
                vec![attr(SIGNING_TIME, tm(at(offset)).to_der().unwrap())],
                vec![],
            ),
        )],
    }
}

fn artifact(spec: &Spec) -> Vec<u8> {
    let (id, intermediates) = signer(spec);
    let mut extra: Vec<Vec<u8>> = intermediates.iter().map(|c| c.to_der().unwrap()).collect();
    if !matches!(spec.stamp, Stamp::None) {
        extra.push(tsa_identity().cert.to_der().unwrap());
    }
    if spec.container == Container::Rdp {
        let hash = crypto::Hash::Sha256;
        let direct = rdp_fixtures::signer(
            &id.cert,
            hash,
            false,
            |bytes| {
                let signature: Signature = id.key.sign(bytes);
                signature.to_der().as_bytes().to_vec()
            },
            false,
        );
        let mut parts = rdp_fixtures::fields(&direct);
        let parent = der::one(parts.last().unwrap(), 4).unwrap().body.to_vec();
        let unsigned = timestamp(&spec.stamp, &parent);
        if !unsigned.is_empty() {
            parts.push(tlv(0xa1, &unsigned.concat()));
        }
        let cms = rdp_fixtures::envelope(&id.cert, hash, &seq(&parts), &extra);
        return rdp_fixtures::frame(&cms).into_bytes();
    }
    let base = base_pe(true);
    let content = image_content(&base, true, None);
    let body = der::one(&content, 0x30).unwrap().body;
    let parent_si = signer_info(&id, body, Some(cms::INDIRECT), vec![], vec![]);
    let parent = der::one(&parent_si, 0x30).unwrap().children().unwrap()[5].body;
    let si = signer_info(
        &id,
        body,
        Some(cms::INDIRECT),
        vec![],
        timestamp(&spec.stamp, parent),
    );
    let signature = signed_data_extra(&id, content.clone(), cms::INDIRECT, si, extra);
    let signature = match spec.container {
        Container::NestedPe => {
            let outer = identity();
            let nested = vec![attr(cms::NESTED, signature)];
            let si = signer_info(outer, body, Some(cms::INDIRECT), vec![], nested);
            signed_data(outer, content, cms::INDIRECT, si)
        }
        Container::Pe | Container::Rdp => signature,
    };
    attach(base, &signature, true)
}

/// CRLs for the rolled-over SEC-09 intermediate (and one root CRL), so
/// lifetime cases can run with revocation checked.
fn crls() -> Vec<(&'static str, Vec<u8>)> {
    use x509_cert::{
        Version,
        crl::{CertificateList, RevokedCert, TbsCertList},
    };
    let rollover = spec("lifetime-intermediate-rollover");
    let (_, intermediates) = signer(&rollover);
    let root = identity();
    let crl = |issuer: &Certificate, key: &SigningKey, revoked: Option<u32>| {
        let algorithm = issuer.signature_algorithm.clone();
        let tbs = TbsCertList {
            version: Version::V2,
            signature: algorithm.clone(),
            issuer: issuer.tbs_certificate.subject.clone(),
            this_update: tm(NOW - 100),
            next_update: Some(tm(NOW + 1000)),
            revoked_certificates: revoked.map(|serial| {
                vec![RevokedCert {
                    serial_number: SerialNumber::from(serial),
                    revocation_date: tm(NOW - 50),
                    crl_entry_extensions: None,
                }]
            }),
            crl_extensions: Some(vec![x509_cert::ext::Extension {
                extn_id: ObjectIdentifier::new_unwrap("2.5.29.20"),
                critical: false,
                extn_value: ::der::asn1::OctetString::new([2, 1, 1]).unwrap(),
            }]),
        };
        let sig: Signature = key.sign(&tbs.to_der().unwrap());
        CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
        }
        .to_der()
        .unwrap()
    };
    let intermediate = &intermediates[0];
    let key = intermediate_key(&rollover, 0);
    vec![
        ("sec09-intermediate.crl", crl(intermediate, &key, None)),
        (
            "sec09-intermediate-revoked-leaf.crl",
            crl(intermediate, &key, Some(LEAF_SERIAL)),
        ),
        // Revokes only the rolled-over intermediate that is valid at signing.
        (
            "sec09-root-revoked-intermediate.crl",
            crl(&root.root, &root.root_key, Some(VALID_ROLLOVER_SERIAL)),
        ),
    ]
}

pub(super) fn write(dir: &std::path::Path) {
    for label in LABELS {
        let spec = spec(label);
        std::fs::write(dir.join(file_name(&spec)), artifact(&spec)).unwrap();
    }
    for (name, bytes) in crls() {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

#[test]
#[ignore = "explicit fixture maintenance"]
fn regenerate_sec09_fixtures() {
    write(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"));
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn verify_certificate(cert: &Certificate, issuer: &Certificate) {
    crypto::verify_spki(
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
    .unwrap();
}

/// Verify one SignerInfo. `direct` is the signed content when there are no
/// signed attributes (RDP); otherwise the signed attributes are the message.
fn math(si: der::Node<'_>, cert: &Certificate, direct: Option<&[u8]>) {
    let f = si.children().unwrap();
    let (message, algorithm) = match direct {
        Some(content) => (content.to_vec(), 3),
        None => {
            let mut signed = f[3].full.to_vec();
            signed[0] = 0x31;
            (signed, 4)
        }
    };
    crypto::verify_spki(
        &cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap(),
        crypto::Hash::Sha256,
        f[algorithm].children().unwrap()[0].body,
        &message,
        f[algorithm + 1].body,
    )
    .unwrap();
}

/// Check the SEC-09 signer, its embedded certificates and its timestamp
/// against the specification. Embedded order is leaf, root, intermediates,
/// then the TSA.
fn check_signer(spec: &Spec, certs: &[Certificate], si: der::Node<'_>, direct: Option<&[u8]>) {
    let label = spec.label;
    let lifetime = ObjectIdentifier::new_unwrap(LIFETIME_SIGNING);
    let leaf = &certs[0];
    math(si, leaf, direct);
    let window = &leaf.tbs_certificate.validity;
    assert_eq!(
        (
            window.not_before.to_unix_duration().as_secs(),
            window.not_after.to_unix_duration().as_secs()
        ),
        (at(spec.leaf.0), at(spec.leaf.1)),
        "{label}"
    );
    let (_, usage) = leaf
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .unwrap()
        .unwrap();
    assert_eq!(usage.0.contains(&lifetime), spec.lifetime, "{label}");
    let cas = spec.issuers.cas();
    let root = &certs[1].tbs_certificate.subject;
    let chained = matches!(spec.issuers, Issuers::Chain(_));
    let issuer_of_leaf = cas
        .first()
        .map_or(root, |_| &certs[2].tbs_certificate.subject);
    assert_eq!(&leaf.tbs_certificate.issuer, issuer_of_leaf, "{label}");
    for (index, ca) in cas.iter().enumerate() {
        let cert = &certs[2 + index].tbs_certificate;
        let window = &cert.validity;
        assert_eq!(
            (
                window.not_before.to_unix_duration().as_secs(),
                window.not_after.to_unix_duration().as_secs()
            ),
            (at(ca.window.0), at(ca.window.1)),
            "{label} intermediate {index}"
        );
        let (_, usage) = cert
            .get::<x509_cert::ext::pkix::KeyUsage>()
            .unwrap()
            .unwrap();
        assert_eq!(usage.key_cert_sign(), ca.key_cert_sign, "{label}");
        let issuer = if chained && index + 1 < cas.len() {
            &certs[3 + index].tbs_certificate.subject
        } else {
            root
        };
        assert_eq!(&cert.issuer, issuer, "{label} intermediate {index}");
        // Rolled-over intermediates share the first one's subject and key.
        if !chained {
            let first = &certs[2].tbs_certificate;
            assert_eq!(cert.subject, first.subject, "{label}");
            assert_eq!(
                cert.subject_public_key_info, first.subject_public_key_info,
                "{label}"
            );
        }
    }
    // Every certificate signature is genuine under its named issuer.
    for cert in certs {
        let issuer = certs
            .iter()
            .find(|c| c.tbs_certificate.subject == cert.tbs_certificate.issuer)
            .unwrap();
        verify_certificate(cert, issuer);
    }
    let fields = si.children().unwrap();
    let unsigned = if direct.is_some() { 5 } else { 6 };
    if matches!(spec.stamp, Stamp::None) {
        assert_eq!(fields.len(), unsigned, "{label}");
        return;
    }
    let parent = fields[unsigned - 1].body;
    let tsa = tsa_identity().cert;
    for attr in fields[unsigned].children().unwrap() {
        let attr = attr.children().unwrap();
        for value in attr[1].children().unwrap() {
            if attr[0].body == cms::COUNTERSIGN {
                math(value, &tsa, None);
                let Stamp::Counter(offset) = spec.stamp else {
                    unreachable!()
                };
                let signed = value.children().unwrap()[3].children().unwrap();
                let time = signed
                    .iter()
                    .map(|attr| attr.children().unwrap())
                    .find(|attr| attr[0].body == SIGNING_TIME)
                    .unwrap()[1]
                    .children()
                    .unwrap()[0];
                let time = crate::parse::ParsedTime::parse(time.full).unwrap();
                assert_eq!(time.unix_seconds(), at(offset), "{label}");
                assert_eq!(time.fractional_seconds(), None, "{label}");
            } else {
                let token = cms::SignedData::parse(value.full).unwrap();
                token.verify(token.signers[0], false).unwrap();
                let info = crate::parse::TstInfo::parse(token.content.full).unwrap();
                let Stamp::Rfc(offset, fraction) = spec.stamp else {
                    unreachable!()
                };
                assert_eq!(info.parsed_time.unix_seconds(), at(offset), "{label}");
                assert_eq!(info.parsed_time.fractional_seconds(), fraction, "{label}");
                // The token is bound to this signer's signature value.
                let imprint = token.content.children().unwrap()[2].children().unwrap()[1].body;
                assert_eq!(imprint, crypto::Hash::Sha256.digest(parent), "{label}");
            }
        }
    }
}

#[test]
fn sec09_committed_fixtures_preserve_image_signatures_and_times() {
    for label in LABELS {
        let spec = spec(label);
        let bytes = fixture(&file_name(&spec));
        if spec.container == Container::Rdp {
            let rdp = crate::parse::Rdp::parse(&bytes).unwrap();
            let sd = cms::DetachedData::parse(rdp.signature()).unwrap();
            check_signer(&spec, &sd.certs, sd.signers[0], Some(rdp.canonical_bytes()));
            continue;
        }
        let pe = pe::Pe::parse(&bytes).unwrap();
        let sd = cms::SignedData::parse(pe.certificates().unwrap()[0]).unwrap();
        let (hash, expected) = sd.image_digest().unwrap();
        assert_eq!(pe.digest(hash).unwrap(), expected, "{label}");
        if spec.container == Container::Pe {
            check_signer(&spec, &sd.certs, sd.signers[0], None);
            continue;
        }
        // The primary signer is the ordinary publisher; the SEC-09 signer is
        // its single nested signature over the same image digest.
        math(sd.signers[0], &identity().cert, None);
        let outer = sd.signers[0].children().unwrap();
        let attributes = outer[6].children().unwrap();
        assert_eq!(attributes.len(), 1, "{label}");
        let nested = attributes[0].children().unwrap();
        assert_eq!(nested[0].body, cms::NESTED, "{label}");
        let nested = cms::SignedData::parse(nested[1].children().unwrap()[0].full).unwrap();
        assert_eq!(nested.image_digest().unwrap(), (hash, expected), "{label}");
        check_signer(&spec, &nested.certs, nested.signers[0], None);
    }
}

#[test]
fn sec09_committed_crls_are_signed_and_scoped() {
    use ::der::Decode;
    use x509_cert::crl::CertificateList;
    let (_, intermediates) = signer(&spec("lifetime-intermediate-rollover"));
    let root = &identity().root;
    for (name, issuer, revoked) in [
        ("sec09-intermediate.crl", &intermediates[0], None),
        (
            "sec09-intermediate-revoked-leaf.crl",
            &intermediates[0],
            Some(LEAF_SERIAL),
        ),
        (
            "sec09-root-revoked-intermediate.crl",
            root,
            Some(VALID_ROLLOVER_SERIAL),
        ),
    ] {
        let crl = CertificateList::from_der(&fixture(name)).unwrap();
        let tbs = &crl.tbs_cert_list;
        assert_eq!(tbs.issuer, issuer.tbs_certificate.subject, "{name}");
        crypto::verify_spki(
            &issuer
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            crypto::Hash::Sha256,
            crl.signature_algorithm.oid.as_bytes(),
            &tbs.to_der().unwrap(),
            crl.signature.as_bytes().unwrap(),
        )
        .unwrap();
        let serials: Vec<_> = tbs
            .revoked_certificates
            .iter()
            .flatten()
            .map(|entry| entry.serial_number.clone())
            .collect();
        let expected: Vec<_> = revoked.into_iter().map(SerialNumber::from).collect();
        assert_eq!(serials, expected, "{name}");
    }
    // The revoked intermediate is the one valid at the rollover signing time.
    assert_eq!(
        intermediates[1].tbs_certificate.serial_number,
        SerialNumber::from(VALID_ROLLOVER_SERIAL)
    );
    assert_eq!(not_before_offset(&intermediates[1]), -9000);
}

fn not_before_offset(cert: &Certificate) -> i64 {
    let seconds = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    seconds as i64 - NOW as i64
}
