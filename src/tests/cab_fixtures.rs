//! Test-only CAB recipe. Hash input is assembled independently of production.
use super::*;

pub(super) fn base() -> Vec<u8> {
    let mut b = vec![0; 98];
    b[..4].copy_from_slice(b"MSCF");
    b[8..12].copy_from_slice(&98u32.to_le_bytes());
    b[16..20].copy_from_slice(&68u32.to_le_bytes());
    b[24..26].copy_from_slice(&[3, 1]);
    b[26..28].copy_from_slice(&1u16.to_le_bytes());
    b[28..30].copy_from_slice(&1u16.to_le_bytes());
    b[30..32].copy_from_slice(&4u16.to_le_bytes());
    b[36..40].copy_from_slice(&[20, 0, 0, 0]);
    b[40..44].copy_from_slice(&[0, 0, 16, 0]);
    b[44..48].copy_from_slice(&98u32.to_le_bytes());
    b[60..64].copy_from_slice(&86u32.to_le_bytes());
    b[64..66].copy_from_slice(&1u16.to_le_bytes());
    b[68..72].copy_from_slice(&4u32.to_le_bytes());
    b[84..86].copy_from_slice(b"x\0");
    b[90..94].copy_from_slice(&[4, 0, 4, 0]);
    b[94..98].copy_from_slice(b"test");
    b
}
fn content(hash: crypto::Hash) -> Vec<u8> {
    let b = base();
    let input = [&b[..4], &b[8..34], &[0; 4], &b[60..]].concat();
    let algorithm = match hash {
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
    seq(&[
        seq(&[oid(&[43, 6, 1, 4, 1, 130, 55, 2, 1, 25]), seq(&[])]),
        seq(&[algorithm, tlv(4, &hash.digest(&input))]),
    ])
}
fn attach(signature: &[u8]) -> Vec<u8> {
    let mut b = base();
    let len = (signature.len() + 7) & !7;
    b[48..52].copy_from_slice(&(len as u32).to_le_bytes());
    b.extend(signature);
    b.resize(98 + len, 0);
    b
}
pub(super) fn write(dir: &std::path::Path) {
    let write = |name: &str, b: &[u8]| std::fs::write(dir.join(name), b).unwrap();
    let data = content(crypto::Hash::Sha256);
    let signer = signer_info(
        identity(),
        der::one(&data, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    let good = attach(&signed_data(
        identity(),
        data.clone(),
        cms::INDIRECT,
        signer,
    ));
    write("good.cab", &good);
    for (name, at) in [
        ("bad-cab-digest.cab", 96),
        (
            "bad-cab-cms-signature.cab",
            good.iter().rposition(|b| *b != 0).unwrap(),
        ),
    ] {
        let mut b = good.clone();
        b[at] ^= 1;
        write(name, &b);
    }
    for (name, hash) in [
        ("good-cab-sha384.cab", crypto::Hash::Sha384),
        ("good-cab-sha512.cab", crypto::Hash::Sha512),
        ("legacy-cab-sha1.cab", crypto::Hash::Sha1),
    ] {
        let data = content(hash);
        let signer = signer_info(
            identity(),
            der::one(&data, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![],
            vec![],
        );
        write(
            name,
            &attach(&signed_data(identity(), data, cms::INDIRECT, signer)),
        );
    }
    for (name, source) in [
        ("good-cab-nested.cab", "good-nested.exe"),
        ("good-cab-rfc3161.cab", "good-rfc3161.exe"),
        ("good-cab-countersignature.cab", "good-countersignature.exe"),
        ("bad-cab-timestamp-imprint.cab", "bad-timestamp-imprint.exe"),
    ] {
        let pe = std::fs::read(dir.join(source)).unwrap();
        let pe = pe::Pe::parse(&pe).unwrap();
        write(
            name,
            &attach(&msi_fixtures::convert_cms(
                pe.certificates().unwrap()[0],
                &data,
            )),
        );
    }
    for (name, at, value) in [
        ("bad-cab-flags.cab", 30, 5),
        ("bad-cab-reserve.cab", 36, 19),
        ("bad-cab-offset.cab", 44, 97),
        ("bad-cab-folder-offset.cab", 60, 0),
    ] {
        let mut b = good.clone();
        b[at] = value;
        write(name, &b);
    }
    let mut b = good.clone();
    b.push(0);
    write("bad-cab-trailing.cab", &b);
    write("bad-cab-truncated.cab", &good[..50]);
    let mut b = base();
    b[48..52].fill(0);
    write("unsigned.cab", &b);
    let mut no_reserve = base();
    no_reserve.drain(36..60);
    no_reserve[8..12].copy_from_slice(&74u32.to_le_bytes());
    no_reserve[16..20].copy_from_slice(&44u32.to_le_bytes());
    no_reserve[30..32].fill(0);
    no_reserve[36..40].copy_from_slice(&62u32.to_le_bytes());
    write("unsigned-cab-no-reserve.cab", &no_reserve);
    no_reserve.push(0);
    write("bad-cab-no-reserve-trailing.cab", &no_reserve);
    let mut b = good.clone();
    b[98..].fill(0);
    write("bad-cab-malformed-cms.cab", &b);
    let pe = std::fs::read(dir.join("good-pe64.exe")).unwrap();
    let pe = pe::Pe::parse(&pe).unwrap();
    write("bad-cab-sip.cab", &attach(pe.certificates().unwrap()[0]));
}
