#[path = "common/crosscheck.rs"]
mod crosscheck;
use std::path::Path;

#[test]
fn mismatched_image_fixture_preserves_the_original_signature() {
    let directory = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/fixtures");
    let good = std::fs::read(directory.join("good-pe64.exe")).unwrap();
    let bad = std::fs::read(directory.join("bad-image-digest.exe")).unwrap();
    // The good image's signature covers hash(b). Only section data changes,
    // producing hash(a) while retaining the complete original certificate table.
    let mut expected = good;
    expected[700] ^= 1;
    assert_eq!(bad, expected);
}
