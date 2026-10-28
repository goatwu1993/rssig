//! Deterministic test-only NAVX recipes, independent of the production parser.
use super::*;

fn base() -> Vec<u8> {
    let mut b = vec![0; 40];
    b[..4].copy_from_slice(b"NAVX");
    b[28..32].copy_from_slice(&4u32.to_le_bytes());
    b[36..40].copy_from_slice(b"NAVX");
    b.extend(b"test");
    b
}
fn content(hash: crypto::Hash, fault: &str) -> Vec<u8> {
    let mut sip = vec![
        vec![2, 1, 1],
        tlv(
            4,
            &[
                0x12, 0x34, 0x12, 0x34, 0xf8, 0x04, 0, 0, 0x78, 0x1d, 0x12, 0x34, 0x12, 0x34, 0x12,
                0x34,
            ],
        ),
    ];
    sip.extend(vec![vec![2, 1, 0]; 5]);
    match fault {
        "sip-version" => sip[0] = vec![2, 1, 2],
        "sip-uuid" => sip[1] = tlv(4, &[0; 16]),
        "sip-reserved" => sip[2] = vec![2, 1, 1],
        _ => {}
    }
    let alg = match hash {
        crypto::Hash::Sha1 => seq(&[oid(&[43, 14, 3, 2, 26]), vec![5, 0]]),
        _ => {
            let suffix = match hash {
                crypto::Hash::Sha256 => 1,
                crypto::Hash::Sha384 => 2,
                crypto::Hash::Sha512 => 3,
                _ => unreachable!(),
            };
            seq(&[oid(&[96, 134, 72, 1, 101, 3, 4, 2, suffix]), vec![5, 0]])
        }
    };
    let ty = if fault == "sip-type" { 25 } else { 30 };
    seq(&[
        seq(&[oid(&[43, 6, 1, 4, 1, 130, 55, 2, 1, ty]), seq(&sip)]),
        seq(&[alg, tlv(4, &hash.digest(&base()))]),
    ])
}
fn attach(cms: &[u8]) -> Vec<u8> {
    let mut b = base();
    b.extend(b"NXSB");
    b.extend(cms);
    b.extend(44u32.to_le_bytes());
    b.extend(b"NXSB");
    b
}
pub(super) fn write(dir: &std::path::Path) {
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    write("unsigned.navx", &base());
    for (name, hash, fault) in [
        ("good.navx", crypto::Hash::Sha256, ""),
        ("good-navx-sha384.navx", crypto::Hash::Sha384, ""),
        ("good-navx-sha512.navx", crypto::Hash::Sha512, ""),
        ("legacy-navx-sha1.navx", crypto::Hash::Sha1, ""),
        ("bad-navx-sip-type.navx", crypto::Hash::Sha256, "sip-type"),
        (
            "bad-navx-sip-version.navx",
            crypto::Hash::Sha256,
            "sip-version",
        ),
        ("bad-navx-sip-uuid.navx", crypto::Hash::Sha256, "sip-uuid"),
        (
            "bad-navx-sip-reserved.navx",
            crypto::Hash::Sha256,
            "sip-reserved",
        ),
    ] {
        let data = content(hash, fault);
        let si = signer_info(
            identity(),
            der::one(&data, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![],
            vec![],
        );
        write(
            name,
            &attach(&signed_data(identity(), data, cms::INDIRECT, si)),
        );
    }
    let good = std::fs::read(dir.join("good.navx")).unwrap();
    for (name, at) in [
        ("digest", 40),
        ("header", 36),
        ("size", 28),
        ("block", 44),
        ("offset", good.len() - 8),
        ("trailer", good.len() - 1),
        ("cms-signature", good.len() - 9),
    ] {
        let mut b = good.clone();
        b[at] ^= 1;
        write(&format!("bad-navx-{name}.navx"), &b);
    }
    for (fault, source) in [
        ("nested", "good-nested.exe"),
        ("rfc3161", "good-rfc3161.exe"),
        ("countersignature", "good-countersignature.exe"),
        ("bad-nested", "bad-nested-signature.exe"),
        ("timestamp-imprint", "bad-timestamp-imprint.exe"),
    ] {
        let pe = std::fs::read(dir.join(source)).unwrap();
        let pe = pe::Pe::parse(&pe).unwrap();
        let sig = msi_fixtures::convert_cms(
            pe.certificates().unwrap()[0],
            &content(crypto::Hash::Sha256, ""),
        );
        let prefix = if fault.starts_with("bad") || fault == "timestamp-imprint" {
            "bad"
        } else {
            "good"
        };
        write(&format!("{prefix}-navx-{fault}.navx"), &attach(&sig));
    }
    let mut sig = good[48..good.len() - 8].to_vec();
    sig.push(0);
    write("bad-navx-cms-trailing.navx", &attach(&sig));
    write("bad-navx-malformed-cms.navx", &attach(&[0, 0]));
    let mut b = good.clone();
    b.push(0);
    write("bad-navx-trailing.navx", &b);
    write("bad-navx-truncated.navx", &good[..39]);
    write("navx-misnamed.ps1", &good);
}
