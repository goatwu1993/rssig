//! Deterministic, inert RDP fixtures. Never open these in an RDP client.
use super::*;
use base64ct::{Base64, Encoding};
use rand::SeedableRng;

const DATA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 1];
const BODY: &str = "desktopwidth:i:1024\r\nredirectclipboard:i:0\r\nfull address:s:example.invalid\r\nserver port:i:3389\r\n";
const SCOPE: &str = "Full Address,Server Port,RedirectClipboard";
fn canonical() -> Vec<u8> {
    format!("full address:s:example.invalid\r\nserver port:i:3389\r\nredirectclipboard:i:0\r\nsignscope:s:{SCOPE}\r\n\0")
        .encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn alg(hash: crypto::Hash) -> Vec<u8> {
    let value = match hash {
        crypto::Hash::Sha1 => vec![43, 14, 3, 2, 26],
        crypto::Hash::Sha256 => vec![96, 134, 72, 1, 101, 3, 4, 2, 1],
        crypto::Hash::Sha384 => vec![96, 134, 72, 1, 101, 3, 4, 2, 2],
        crypto::Hash::Sha512 => vec![96, 134, 72, 1, 101, 3, 4, 2, 3],
    };
    seq(&[oid(&value), vec![5, 0]])
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
fn envelope(
    certificate: &Certificate,
    hash: crypto::Hash,
    signer: &[u8],
    extra: &[Vec<u8>],
) -> Vec<u8> {
    let mut certs = certificate.to_der().unwrap();
    certs.extend(identity().root.to_der().unwrap());
    for cert in extra {
        certs.extend(cert);
    }
    seq(&[
        oid(cms::SIGNED_DATA),
        tlv(
            0xa0,
            &seq(&[
                vec![2, 1, 1],
                tlv(0x31, &alg(hash)),
                seq(&[oid(DATA)]),
                tlv(0xa0, &certs),
                tlv(0x31, signer),
            ]),
        ),
    ])
}
fn signer(
    cert: &Certificate,
    hash: crypto::Hash,
    attributes: bool,
    signature: impl Fn(&[u8]) -> Vec<u8>,
    rsa: bool,
) -> Vec<u8> {
    let mut si = vec![
        vec![2, 1, 1],
        seq(&[
            cert.tbs_certificate.issuer.to_der().unwrap(),
            cert.tbs_certificate.serial_number.to_der().unwrap(),
        ]),
        alg(hash),
    ];
    let mut to_sign = canonical();
    if attributes {
        let mut attrs = [
            attr(&[42, 134, 72, 134, 247, 13, 1, 9, 3], oid(DATA)),
            attr(
                &[42, 134, 72, 134, 247, 13, 1, 9, 4],
                tlv(4, &hash.digest(&to_sign)),
            ),
        ];
        attrs.sort();
        to_sign = tlv(0x31, &attrs.concat());
        si.push(tlv(0xa0, &attrs.concat()));
    }
    si.push(if rsa {
        seq(&[oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]), vec![5, 0]])
    } else {
        seq(&[oid(&[42, 134, 72, 206, 61, 4, 3, 2])])
    });
    si.push(tlv(4, &signature(&to_sign)));
    seq(&si)
}
fn ec_signer(cert: &Certificate, attributes: bool) -> Vec<u8> {
    signer(
        cert,
        crypto::Hash::Sha256,
        attributes,
        |b| {
            let s: Signature = identity().key.sign(b);
            s.to_der().as_bytes().to_vec()
        },
        false,
    )
}
fn frame(cms: &[u8]) -> String {
    let mut blob = vec![1, 0, 1, 0, 1, 0, 0, 0];
    blob.extend((cms.len() as u32).to_le_bytes());
    blob.extend(cms);
    format!(
        "{BODY}signscope:s:{SCOPE}\r\nsignature:s:{}\r\n",
        Base64::encode_string(&blob)
    )
}
fn timestamped(legacy: bool, bad: bool) -> Vec<u8> {
    let id = identity();
    let tsa = tsa_identity();
    let si = ec_signer(&id.cert, false);
    let mut parts = fields(&si);
    let signature = der::one(parts.last().unwrap(), 4).unwrap().body;
    let mut imprint = crypto::Hash::Sha256.digest(signature);
    if bad {
        imprint[0] ^= 1;
    }
    let unsigned = if legacy {
        attr(
            cms::COUNTERSIGN,
            signer_info(
                &tsa,
                signature,
                None,
                vec![attr(
                    &[42, 134, 72, 134, 247, 13, 1, 9, 5],
                    tm(NOW).to_der().unwrap(),
                )],
                vec![],
            ),
        )
    } else {
        let info = seq(&[
            vec![2, 1, 1],
            oid(&[42, 3, 4]),
            seq(&[sha256_alg(), tlv(4, &imprint)]),
            vec![2, 1, 1],
            tm(NOW).to_der().unwrap(),
        ]);
        let ts = signer_info(&tsa, &info, Some(cms::TST_INFO), vec![], vec![]);
        attr(
            cms::RFC3161,
            signed_data(&tsa, tlv(4, &info), cms::TST_INFO, ts),
        )
    };
    parts.push(tlv(0xa1, &unsigned));
    envelope(
        &id.cert,
        crypto::Hash::Sha256,
        &seq(&parts),
        &[tsa.cert.to_der().unwrap()],
    )
}
fn changed_cert(eku: Option<&str>, key_usage: bool) -> Certificate {
    let id = identity();
    let mut cert = id.cert.clone();
    let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
    extensions.retain(|e| e.extn_id.to_string() != "2.5.29.37");
    if let Some(eku) = eku {
        extensions.push(x509_cert::ext::Extension {
            extn_id: "2.5.29.37".parse().unwrap(),
            critical: false,
            extn_value: ::der::asn1::OctetString::new(seq(&[oid(
                ::der::asn1::ObjectIdentifier::new(eku).unwrap().as_bytes(),
            )]))
            .unwrap(),
        });
    }
    if !key_usage {
        let extension = extensions
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.15")
            .unwrap();
        extension.extn_value = ::der::asn1::OctetString::new([3, 2, 5, 0x20]).unwrap();
    }
    let signature: Signature = id.root_key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    cert
}
pub(super) fn write(dir: &std::path::Path) {
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    let id = identity();
    let hash = crypto::Hash::Sha256;
    let bare = envelope(&id.cert, hash, &ec_signer(&id.cert, false), &[]);
    let attrs = envelope(&id.cert, hash, &ec_signer(&id.cert, true), &[]);
    let good = frame(&bare);
    write("good.rdp", good.as_bytes());
    write("rdp-misnamed.bin", good.as_bytes());
    write("good-rdp-attributes.rdp", frame(&attrs).as_bytes());
    write(
        "good-rdp-utf8-bom.rdp",
        format!("\u{feff}{good}").as_bytes(),
    );
    write(
        "good-rdp-utf16le.rdp",
        &format!("\u{feff}{good}")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    write(
        "good-rdp-utf16be.rdp",
        &format!("\u{feff}{good}")
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>(),
    );
    write("good-rdp-lf.rdp", good.replace("\r\n", "\n").as_bytes());
    write(
        "good-rdp-no-final-newline.rdp",
        good.trim_end_matches("\r\n").as_bytes(),
    );
    write(
        "good-rdp-unsigned-change.rdp",
        good.replace("desktopwidth:i:1024", "desktopwidth:i:2048")
            .as_bytes(),
    );
    write(
        "good-rdp-unicode-unsigned.rdp",
        format!("username:s:café 😀\r\n{good}").as_bytes(),
    );
    write(
        "bad-rdp-setting.rdp",
        good.replace("example.invalid", "example.invalie")
            .as_bytes(),
    );
    write(
        "bad-rdp-attributes-setting.rdp",
        frame(&attrs)
            .replace("example.invalid", "example.invalie")
            .as_bytes(),
    );
    write(
        "bad-rdp-scope-order.rdp",
        good.replace(SCOPE, "Server Port,Full Address,RedirectClipboard")
            .as_bytes(),
    );
    let mut broken = bare.clone();
    *broken.last_mut().unwrap() ^= 1;
    write("bad-rdp-cms-signature.rdp", frame(&broken).as_bytes());
    for (name, legacy, bad) in [
        ("good-rdp-rfc3161.rdp", false, false),
        ("good-rdp-countersignature.rdp", true, false),
        ("bad-rdp-timestamp-imprint.rdp", false, true),
    ] {
        write(name, frame(&timestamped(legacy, bad)).as_bytes());
    }
    for (name, eku, ku) in [
        ("good-rdp-server-auth.rdp", Some("1.3.6.1.5.5.7.3.1"), true),
        (
            "good-rdp-remote-auth.rdp",
            Some("1.3.6.1.4.1.311.54.1.2"),
            true,
        ),
        ("bad-rdp-eku.rdp", Some("1.3.6.1.5.5.7.3.2"), true),
        ("bad-rdp-no-eku.rdp", None, true),
        ("bad-rdp-key-usage.rdp", Some("1.3.6.1.5.5.7.3.3"), false),
    ] {
        let cert = changed_cert(eku, ku);
        write(
            name,
            frame(&envelope(&cert, hash, &ec_signer(&cert, false), &[])).as_bytes(),
        );
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public = rsa::RsaPublicKey::from(&private);
    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: id.root.tbs_certificate.subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(4u32),
        Validity {
            not_before: tm(NOW - 10000),
            not_after: tm(NOW + 10000),
        },
        Name::from_str("CN=rssig RDP RSA publisher").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(public).unwrap(),
        &id.root_key,
    )
    .unwrap();
    builder
        .add_extension(&ExtendedKeyUsage(vec![
            "1.3.6.1.5.5.7.3.3".parse().unwrap(),
        ]))
        .unwrap();
    let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
    for (name, hash) in [
        ("good-rdp-rsa.rdp", crypto::Hash::Sha256),
        ("good-rdp-sha384.rdp", crypto::Hash::Sha384),
        ("good-rdp-sha512.rdp", crypto::Hash::Sha512),
        ("legacy-rdp-sha1.rdp", crypto::Hash::Sha1),
    ] {
        let si = signer(
            &cert,
            hash,
            false,
            |b| {
                use rsa::pkcs1v15::SigningKey as RsaSigner;
                use signature::SignatureEncoding;
                match hash {
                    crypto::Hash::Sha1 => RsaSigner::<sha1::Sha1>::new(private.clone())
                        .sign(b)
                        .to_vec(),
                    crypto::Hash::Sha256 => RsaSigner::<sha2::Sha256>::new(private.clone())
                        .sign(b)
                        .to_vec(),
                    crypto::Hash::Sha384 => RsaSigner::<sha2::Sha384>::new(private.clone())
                        .sign(b)
                        .to_vec(),
                    crypto::Hash::Sha512 => RsaSigner::<sha2::Sha512>::new(private.clone())
                        .sign(b)
                        .to_vec(),
                }
            },
            true,
        );
        write(name, frame(&envelope(&cert, hash, &si, &[])).as_bytes());
    }

    // Preserve mandatory signed attributes in the existing Authenticode path.
    let pe_bytes = std::fs::read(dir.join("good-pe64.exe")).unwrap();
    let pe = pe::Pe::parse(&pe_bytes).unwrap();
    let mut outer = fields(pe.certificates().unwrap()[0]);
    let mut sd = fields(der::one(&outer[1], 0xa0).unwrap().body);
    let ci = fields(&sd[2]);
    let content = der::one(der::one(&ci[1], 0xa0).unwrap().body, 0x30)
        .unwrap()
        .body;
    let mut si = fields(der::one(&sd[4], 0x31).unwrap().body);
    si.remove(3);
    let signature: Signature = id.key.sign(content);
    si[4] = tlv(4, signature.to_der().as_bytes());
    sd[4] = tlv(0x31, &seq(&si));
    outer[1] = tlv(0xa0, &seq(&sd));
    write(
        "bad-rdp-pe-no-attributes.exe",
        &attach(base_pe(true), &seq(&outer), true),
    );
    let mut nested_si = fields(&ec_signer(&id.cert, false));
    nested_si.push(tlv(0xa1, &attr(cms::NESTED, bare.clone())));
    write(
        "bad-rdp-nested.rdp",
        frame(&envelope(&id.cert, hash, &seq(&nested_si), &[])).as_bytes(),
    );
    let ps_body = "<#\r\nsignscope:s:not-rdp\r\nsignature:s:not-rdp\r\n#>\r\n";
    let ps_cms = powershell_fixtures::cms_for(ps_body, hash, None);
    write(
        "good-rdp-powershell-comment.bin",
        format!("{ps_body}{}", powershell_fixtures::block(&ps_cms)).as_bytes(),
    );
    write("unsigned.rdp", BODY.as_bytes());
    for (name, text) in [
        (
            "bad-rdp-duplicate.rdp",
            format!("full address:s:other.invalid\r\n{good}"),
        ),
        (
            "bad-rdp-case-duplicate.rdp",
            format!("Full Address:s:other.invalid\r\n{good}"),
        ),
        (
            "bad-rdp-duplicate-signature.rdp",
            format!("{good}{}", good.lines().last().unwrap()),
        ),
        (
            "bad-rdp-duplicate-scope.rdp",
            good.replace(
                SCOPE,
                "Full Address,Full Address,Server Port,RedirectClipboard",
            ),
        ),
        (
            "bad-rdp-unknown-scope.rdp",
            good.replace(SCOPE, "Full Address,Unsupported Scope"),
        ),
        (
            "bad-rdp-missing-setting.rdp",
            good.replace("server port:i:3389\r\n", ""),
        ),
        (
            "bad-rdp-wrong-type.rdp",
            good.replace("server port:i:3389", "server port:s:3389"),
        ),
        (
            "bad-rdp-invalid-integer.rdp",
            good.replace("server port:i:3389", "server port:i:abc"),
        ),
        (
            "bad-rdp-missing-scope.rdp",
            good.replace(&format!("signscope:s:{SCOPE}\r\n"), ""),
        ),
        ("bad-rdp-empty-scope.rdp", good.replace(SCOPE, "")),
        (
            "bad-rdp-scope-no-host.rdp",
            good.replace(SCOPE, "Server Port,RedirectClipboard"),
        ),
        ("bad-rdp-blank-line.rdp", format!("\r\n{good}")),
        ("bad-rdp-lone-cr.rdp", good.replacen("\r\n", "\r", 1)),
        (
            "bad-rdp-empty-host.rdp",
            good.replace("example.invalid", ""),
        ),
        ("bad-rdp-invalid-line.rdp", format!("nonsense\r\n{good}")),
    ] {
        write(name, text.as_bytes());
    }
    let sig_start = good.find("signature:s:").unwrap() + 12;
    let mut b = good.as_bytes().to_vec();
    b[sig_start] = b'!';
    write("bad-rdp-base64.rdp", &b);
    let raw = Base64::decode_vec(good[sig_start..].trim()).unwrap();
    for (name, at, value) in [
        ("bad-rdp-header.rdp", 0, 2),
        ("bad-rdp-version.rdp", 4, 2),
        ("bad-rdp-length.rdp", 8, 255),
    ] {
        let mut b = raw.clone();
        b[at] = value;
        write(
            name,
            format!("{}{}\r\n", &good[..sig_start], Base64::encode_string(&b)).as_bytes(),
        );
    }
    write(
        "bad-rdp-short-header.rdp",
        format!("{}AAAA\r\n", &good[..sig_start]).as_bytes(),
    );
    let mut trailer = bare.clone();
    trailer.push(0);
    write("bad-rdp-cms-trailing.rdp", frame(&trailer).as_bytes());
    write("bad-rdp-malformed-cms.rdp", frame(&[0, 0]).as_bytes());
    let pe = std::fs::read(dir.join("good-pe64.exe")).unwrap();
    let pe = pe::Pe::parse(&pe).unwrap();
    write(
        "bad-rdp-attached-cms.rdp",
        frame(pe.certificates().unwrap()[0]).as_bytes(),
    );
    let mut b = good.as_bytes().to_vec();
    b[0] = 255;
    write("bad-rdp-utf8.rdp", &b);
    let mut b: Vec<_> = format!("\u{feff}{good}")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    b.pop();
    write("bad-rdp-odd-utf16.rdp", &b);
}
