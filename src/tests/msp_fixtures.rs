//! Inert MSP-shaped CFB fixtures; not installable Windows Installer patches.
//! The explicit digest recipe is independent of the production CFB walker.
use super::*;
use std::io::{Cursor, Read, Write};

const SIG: &str = "\u{5}DigitalSignature";
const EX: &str = "\u{5}MsiDigitalSignatureEx";
const PATCH: &str = "000c1086-0000-0000-c000-000000000046";
const TRANSFORM: &str = "000c1082-0000-0000-c000-000000000046";
const SUMMARY: &[u8] = b"Synthetic patch summary; no product installation is possible.";
const UPDATE: &[u8] = b"Synthetic database transform";
const PATCHING: &[u8] = b"Synthetic patching transform";

fn clsid(kind: u8) -> [u8; 16] {
    [
        kind, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
    ]
}
fn stream_metadata(out: &mut Vec<u8>, name: &str, size: usize) {
    out.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
    out.extend(u32::try_from(size).unwrap().to_le_bytes());
    out.extend([0; 20]); // state bits and stream timestamps
}
fn recipe(cab: &[u8], extended: bool) -> (Vec<u8>, Vec<u8>) {
    let mut metadata = clsid(0x86).to_vec();
    metadata.extend([0; 4]);
    stream_metadata(&mut metadata, "\u{5}SummaryInformation", SUMMARY.len());
    stream_metadata(&mut metadata, "PatchCab", cab.len());
    let mut payload = [SUMMARY, cab].concat();
    for (name, data) in [("TransformA", UPDATE), ("TransformB", PATCHING)] {
        metadata.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
        metadata.extend(clsid(0x82));
        metadata.extend([0; 4]);
        metadata.extend(116444736000000000u64.to_le_bytes());
        metadata.extend(116444736000000000u64.to_le_bytes());
        stream_metadata(&mut metadata, "Data", data.len());
        payload.extend(data);
        payload.extend(clsid(0x82));
    }
    payload.extend(clsid(0x86));
    let prehash = crypto::Hash::Sha256.digest(&metadata);
    let mut input = if extended { prehash.clone() } else { vec![] };
    input.extend(payload);
    (crypto::Hash::Sha256.digest(&input), prehash)
}
fn container(cab: &[u8], version: cfb::Version) -> Vec<u8> {
    let mut cf = cfb::CompoundFile::create_with_version(version, Cursor::new(vec![])).unwrap();
    cf.set_storage_clsid("/", PATCH.parse().unwrap()).unwrap();
    cf.create_stream("\u{5}SummaryInformation")
        .unwrap()
        .write_all(SUMMARY)
        .unwrap();
    cf.create_stream("PatchCab")
        .unwrap()
        .write_all(cab)
        .unwrap();
    for (name, data) in [("TransformA", UPDATE), ("TransformB", PATCHING)] {
        cf.create_storage(name).unwrap();
        cf.set_storage_clsid(name, TRANSFORM.parse().unwrap())
            .unwrap();
        cf.create_stream(format!("{name}/Data"))
            .unwrap()
            .write_all(data)
            .unwrap();
    }
    let paths: Vec<_> = cf.walk().map(|e| e.path().to_owned()).collect();
    for path in paths {
        cf.set_created_time(&path, std::time::UNIX_EPOCH).unwrap();
        cf.set_modified_time(&path, std::time::UNIX_EPOCH).unwrap();
    }
    cf.into_inner().into_inner()
}
fn edit(bytes: &[u8], change: impl FnOnce(&mut cfb::CompoundFile<Cursor<Vec<u8>>>)) -> Vec<u8> {
    let mut cf = cfb::CompoundFile::open(Cursor::new(bytes.to_vec())).unwrap();
    change(&mut cf);
    cf.into_inner().into_inner()
}
pub(super) fn write(dir: &std::path::Path) {
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    let cab = std::fs::read(dir.join("unsigned.cab")).unwrap();
    let unsigned = container(&cab, cfb::Version::V3);
    write("msp-unsigned.msp", &unsigned);
    for (name, extended, version) in [
        ("msp-good.msp", true, cfb::Version::V3),
        ("msp-good-legacy.msp", false, cfb::Version::V3),
        ("msp-good-v4.msp", true, cfb::Version::V4),
    ] {
        let (digest, prehash) = recipe(&cab, extended);
        let content = msi_fixtures::content(&digest, crypto::Hash::Sha256);
        let si = signer_info(
            identity(),
            der::one(&content, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![],
            vec![],
        );
        let cms = signed_data(identity(), content, cms::INDIRECT, si);
        write(
            name,
            &edit(&container(&cab, version), |cf| {
                cf.create_stream(SIG).unwrap().write_all(&cms).unwrap();
                if extended {
                    cf.create_stream(EX).unwrap().write_all(&prehash).unwrap();
                }
            }),
        );
    }
    let good = std::fs::read(dir.join("msp-good.msp")).unwrap();
    let legacy = std::fs::read(dir.join("msp-good-legacy.msp")).unwrap();
    for (name, base, path) in [
        ("msp-bad-transform.msp", &good, "TransformA/Data"),
        ("msp-bad-cab.msp", &good, "PatchCab"),
    ] {
        write(
            name,
            &edit(base, |cf| {
                let mut bytes = vec![];
                cf.open_stream(path)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                bytes[0] ^= 1;
                cf.open_stream(path).unwrap().write_all(&bytes).unwrap();
            }),
        );
    }
    write(
        "msp-bad-clsid.msp",
        &edit(&legacy, |cf| {
            cf.set_storage_clsid("/", "000c1084-0000-0000-c000-000000000046".parse().unwrap())
                .unwrap();
        }),
    );
    write(
        "msp-bad-metadata.msp",
        &edit(&good, |cf| {
            cf.set_state_bits("TransformA", 1).unwrap();
        }),
    );
    write(
        "msp-bad-cms.msp",
        &edit(&good, |cf| {
            let mut bytes = vec![];
            cf.open_stream(SIG)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            cf.open_stream(SIG).unwrap().write_all(&bytes).unwrap();
        }),
    );
    let (digest, _) = recipe(&cab, true);
    let content = msi_fixtures::content(&digest, crypto::Hash::Sha256);
    for (name, source) in [
        ("msp-good-rfc3161.msp", "good-rfc3161.exe"),
        ("msp-good-nested.msp", "good-nested.exe"),
    ] {
        let bytes = std::fs::read(dir.join(source)).unwrap();
        let pe = pe::Pe::parse(&bytes).unwrap();
        let cms = msi_fixtures::convert_cms(pe.certificates().unwrap()[0], &content);
        write(
            name,
            &edit(&good, |cf| {
                cf.create_stream(SIG).unwrap().write_all(&cms).unwrap();
            }),
        );
    }
}

/// Explicit maintenance only, after signing a copy of msp-unsigned.msp with Jsign.
#[test]
#[ignore = "creates the isolated mutation of the independently signed MSP fixture"]
fn regenerate_msp_jsign_mutation() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let bytes = std::fs::read(dir.join("msp-independent-jsign.msp")).unwrap();
    let changed = edit(&bytes, |cf| {
        let mut stream = cf.open_stream("TransformA/Data").unwrap();
        stream.write_all(b"X").unwrap();
    });
    std::fs::write(dir.join("msp-independent-jsign-tampered.msp"), changed).unwrap();
}

#[test]
fn committed_msp_mutations_preserve_valid_cms_signatures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (good, bad) in [
        ("msp-good.msp", "msp-bad-transform.msp"),
        ("msp-good.msp", "msp-bad-cab.msp"),
        ("msp-good.msp", "msp-bad-metadata.msp"),
        ("msp-good-legacy.msp", "msp-bad-clsid.msp"),
        (
            "msp-independent-jsign.msp",
            "msp-independent-jsign-tampered.msp",
        ),
    ] {
        let original = std::fs::read(dir.join(good)).unwrap();
        let changed = std::fs::read(dir.join(bad)).unwrap();
        assert_eq!(original.len(), changed.len(), "{bad}");
        assert_eq!(
            original
                .iter()
                .zip(&changed)
                .filter(|(a, b)| a != b)
                .count(),
            1,
            "{bad}: isolate a single-byte mutation"
        );
        let original = crate::msi::Msi::parse(&original).unwrap();
        let changed = crate::msi::Msi::parse(&changed).unwrap();
        assert_eq!(original.signature(), changed.signature(), "{bad}");
        let sd = cms::SignedData::parse(changed.signature()).unwrap();
        for signer in &sd.signers {
            sd.verify(*signer, false).unwrap();
        }
    }
}

#[test]
fn committed_msp_has_patch_and_transform_class_ids() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/msp-good.msp"
    ))
    .unwrap();
    let cf = cfb::CompoundFile::open_strict(Cursor::new(bytes)).unwrap();
    assert_eq!(cf.root_entry().clsid().to_string(), PATCH);
    for name in ["TransformA", "TransformB"] {
        assert_eq!(cf.entry(name).unwrap().clsid().to_string(), TRANSFORM);
        assert!(cf.is_stream(format!("{name}/Data")));
    }
    assert!(cf.is_stream("PatchCab"));
}
