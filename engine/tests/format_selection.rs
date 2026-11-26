#![cfg(feature = "verify")]
#[path = "common/crosscheck.rs"]
mod crosscheck;
use rssig_engine::{
    VerifyOptions,
    format::{self, Format},
};
#[test]
fn public_selection_preserves_magic_hints_and_explicit_dispatch() {
    assert_eq!(
        format::detect(b"MZ", Some("wrong.rdp")).unwrap(),
        Format::Pe
    );
    assert_eq!(format::detect(b"unknown", None).unwrap(), Format::Pe);
    assert_eq!(
        format::detect(b"unknown", Some("file.PS1XML")).unwrap(),
        Format::PowershellXml
    );
    let bytes = include_bytes!("../../tests/fixtures/good-powershell.ps1");
    let options = VerifyOptions {
        trust: None,
        check_revocation: false,
        allow_sha1: false,
        now: 1800000000,
    };
    assert!(rssig_engine::verify::verify_as(bytes, Format::Powershell, &options).is_ok());
    assert!(rssig_engine::verify::verify_as(bytes, Format::Pe, &options).is_err());
    assert_eq!(
        rssig_engine::verify::verify_with_hint(bytes, Some("wrong.rdp"), &options)
            .unwrap_err()
            .stage,
        rssig_engine::domain::Stage::Rdp
    );
}

#[test]
fn library_dispatch_uses_the_msi_family_without_a_filename() {
    let bytes = include_bytes!("../../tests/fixtures/msp-good.msp");
    let options = VerifyOptions {
        trust: None,
        check_revocation: true,
        allow_sha1: false,
        now: 1800000000,
    };
    let auto = rssig_engine::verify(bytes, &options).unwrap();
    let explicit = rssig_engine::verify_msi(bytes, &options).unwrap();
    assert_eq!(
        serde_json::to_value(auto).unwrap(),
        serde_json::to_value(explicit).unwrap()
    );
}
