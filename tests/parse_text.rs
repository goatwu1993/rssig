use rssig::parse::{ErrorKind, Powershell, Rdp, TextEncoding, Wsh, WshKind};
use sha2::{Digest, Sha256};

#[test]
fn powershell_preserves_stored_bytes_encoding_and_canonical_utf16() {
    for (bytes, encoding) in [
        (
            include_bytes!("fixtures/good-powershell.ps1").as_slice(),
            TextEncoding::Utf8,
        ),
        (
            include_bytes!("fixtures/good-powershell-utf16le.ps1").as_slice(),
            TextEncoding::Utf16Le,
        ),
        (
            include_bytes!("fixtures/good-powershell-utf16be.ps1").as_slice(),
            TextEncoding::Utf16Be,
        ),
    ] {
        let script = Powershell::parse(bytes).unwrap();
        assert_eq!(script.as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(script.encoding(), encoding);
        let expected: Vec<_> = script
            .body()
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(script.authenticode_bytes(), expected);
        let mut hash = Sha256::new();
        script.update_digest(&mut hash);
        assert_eq!(hash.finalize(), Sha256::digest(expected));
        assert!(!script.signature().is_empty());
    }
    Powershell::parse_xml(include_bytes!("fixtures/good-psxml.ps1xml")).unwrap();
    assert_eq!(
        Powershell::parse(include_bytes!("fixtures/unsigned-powershell.ps1"))
            .unwrap_err()
            .kind(),
        ErrorKind::UnsignedPowershell
    );
}

#[test]
fn wsh_preserves_text_and_hashes_the_insertion_position() {
    for (bytes, kind) in [
        (
            include_bytes!("fixtures/good-wsh.vbs").as_slice(),
            WshKind::VbScript,
        ),
        (
            include_bytes!("fixtures/good-wsh.js").as_slice(),
            WshKind::JScript,
        ),
    ] {
        let script = Wsh::parse(bytes, kind).unwrap();
        assert_eq!(Wsh::detect(bytes).unwrap(), kind);
        assert_eq!(script.kind(), kind);
        assert_eq!(script.as_bytes(), bytes);
        let mut expected: Vec<_> = script
            .body()
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        expected.extend(script.insertion_position().to_le_bytes());
        assert_eq!(script.authenticode_bytes(), expected);
        let mut hash = Sha256::new();
        script.update_digest(&mut hash);
        assert_eq!(hash.finalize(), Sha256::digest(expected));
    }
}

#[test]
fn rdp_exposes_canonical_bytes_and_explicit_untrusted_setting_coverage() {
    let bytes = include_bytes!("fixtures/good.rdp");
    let good = Rdp::parse(bytes).unwrap();
    let changed = Rdp::parse(include_bytes!("fixtures/good-rdp-unsigned-change.rdp")).unwrap();
    let bad = Rdp::parse(include_bytes!("fixtures/bad-rdp-setting.rdp")).unwrap();
    assert_eq!(good.as_bytes(), bytes);
    assert!(good.decoded_text().contains("\r\n"));
    assert_eq!(good.canonical_bytes(), changed.canonical_bytes());
    assert_ne!(good.canonical_bytes(), bad.canonical_bytes());
    assert_eq!(good.signature(), bad.signature());
    assert_eq!(
        good.signscope(),
        ["Full Address", "Server Port", "RedirectClipboard"]
    );
    assert_eq!(good.signed_settings()[0].name, "full address");
    assert_eq!(good.unsigned_settings()[0].name, "desktopwidth");
    assert!(good.canonical_bytes().ends_with(&[13, 0, 10, 0, 0, 0]));
}

#[test]
fn wsf_requires_the_xml_adapter_and_never_falls_back_to_comment_only_framing() {
    let result = Wsh::parse(include_bytes!("fixtures/good-wsh.wsf"), WshKind::Wsf);
    #[cfg(feature = "xml")]
    assert!(result.is_ok());
    #[cfg(not(feature = "xml"))]
    assert_eq!(result.unwrap_err().kind(), ErrorKind::UnsupportedWsfXml);
}

#[test]
fn canonical_inputs_pin_bom_line_endings_unicode_offsets_and_rdp_scope_order() {
    let input = include_bytes!("fixtures/good-powershell-utf8-bom.ps1");
    let ps = Powershell::parse(input).unwrap();
    assert_eq!(ps.encoding(), TextEncoding::Utf8Bom);
    assert_eq!(ps.body(), "\u{feff}# rssig test-only\r\n# café 😀\r\n");
    let xml = Powershell::parse_xml(include_bytes!("fixtures/good-psxml.ps1xml")).unwrap();
    assert_eq!(xml.body(), "<Types />\r\n");
    let wsh = Wsh::parse(include_bytes!("fixtures/good-wsh.vbs"), WshKind::VbScript).unwrap();
    assert_eq!(wsh.body(), "' rssig test-only\r\n");
    assert_eq!(wsh.insertion_position(), 19);
    let rdp = Rdp::parse(include_bytes!("fixtures/good.rdp")).unwrap();
    let canonical: Vec<_> = "full address:s:example.invalid\r\nserver port:i:3389\r\nredirectclipboard:i:0\r\nsignscope:s:Full Address,Server Port,RedirectClipboard\r\n\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(rdp.canonical_bytes(), canonical);
}

#[test]
fn text_parser_errors_and_unsupported_scope_details_are_typed() {
    for (bytes, kind) in [
        (b"\xff".as_slice(), ErrorKind::InvalidPowershell),
        (
            include_bytes!("fixtures/unsigned-powershell.ps1").as_slice(),
            ErrorKind::UnsignedPowershell,
        ),
    ] {
        assert_eq!(Powershell::parse(bytes).unwrap_err().kind(), kind);
    }
    assert_eq!(
        Wsh::parse(b"' unsigned\r\n", WshKind::VbScript)
            .unwrap_err()
            .kind(),
        ErrorKind::UnsignedWsh
    );
    assert_eq!(
        Rdp::parse(include_bytes!("fixtures/unsigned.rdp"))
            .unwrap_err()
            .kind(),
        ErrorKind::UnsignedRdp
    );
    // Scope metadata is not normalized or silently ignored.
    let text = String::from_utf8(include_bytes!("fixtures/good.rdp").to_vec()).unwrap();
    let text = text.replace("Full Address,Server Port", "Unknown Scope,Server Port");
    let error = Rdp::parse(text.as_bytes()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedRdpScope);
    assert_eq!(error.rdp_scope_entry(), Some("Unknown Scope"));
}

#[test]
fn truncated_script_and_rdp_inputs_fail_without_panicking() {
    for bytes in [
        include_bytes!("fixtures/good-powershell.ps1").as_slice(),
        include_bytes!("fixtures/good-powershell-utf16be.ps1").as_slice(),
    ] {
        for end in 0..bytes.len() {
            assert!(Powershell::parse(&bytes[..end]).is_err());
        }
    }
    let bytes = include_bytes!("fixtures/good-wsh.js");
    for end in 0..bytes.len() {
        assert!(Wsh::parse(&bytes[..end], WshKind::JScript).is_err());
    }
    let bytes = include_bytes!("fixtures/good-psxml.ps1xml");
    for end in 0..bytes.len() {
        assert!(Powershell::parse_xml(&bytes[..end]).is_err());
    }
    let bytes = include_bytes!("fixtures/good-rdp-utf16be.rdp");
    for end in 0..bytes.len() {
        if end != bytes.len() - 4 {
            assert!(Rdp::parse(&bytes[..end]).is_err());
        }
    }
}

#[cfg(feature = "xml")]
#[test]
fn wsf_xml_adapter_rejects_malformed_placement_dtds_and_multiple_jobs() {
    for bytes in [
        include_bytes!("fixtures/bad-wsh-xml.wsf").as_slice(),
        include_bytes!("fixtures/bad-wsh-dtd.wsf").as_slice(),
        include_bytes!("fixtures/bad-wsh-multijob.wsf").as_slice(),
        include_bytes!("fixtures/bad-wsh-placement.wsf").as_slice(),
    ] {
        assert_eq!(
            Wsh::parse(bytes, WshKind::Wsf).unwrap_err().kind(),
            ErrorKind::InvalidWsh
        );
    }
    let bytes = include_bytes!("fixtures/good-wsh.wsf");
    let wsf = Wsh::parse(bytes, WshKind::Wsf).unwrap();
    assert_eq!(
        wsf.body(),
        "<job id=\"rssig\"><!-- rssig test-only --></job>\r\n"
    );
    assert_eq!(wsf.insertion_position(), 40);
}
