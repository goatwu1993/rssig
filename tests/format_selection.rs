#![cfg(feature = "verify")]
use rssig::{
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
    let bytes = include_bytes!("fixtures/good-powershell.ps1");
    let options = VerifyOptions {
        trust: None,
        check_revocation: false,
        allow_sha1: false,
        now: 1800000000,
    };
    assert!(rssig::verify::verify_as(bytes, Format::Powershell, &options).is_ok());
    assert!(rssig::verify::verify_as(bytes, Format::Pe, &options).is_err());
    assert_eq!(
        rssig::verify::verify_with_hint(bytes, Some("wrong.rdp"), &options)
            .unwrap_err()
            .stage,
        rssig::domain::Stage::Rdp
    );
}
