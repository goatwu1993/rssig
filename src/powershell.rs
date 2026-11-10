use crate::crypto::Hash;
#[cfg(test)]
use crate::domain::{ErrorCode, Stage};
pub(crate) use crate::parse::powershell::Powershell;
#[cfg(test)]
use crate::parse::powershell::{MAX_SIGNATURE_TEXT, PREFIX, SUFFIX};
use std::path::Path;
pub(crate) fn has_extension(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()).is_some_and(|s| {
        ["ps1", "psm1", "psd1"]
            .iter()
            .any(|ext| s.eq_ignore_ascii_case(ext))
    })
}

pub(crate) fn has_xml_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("ps1xml"))
}
pub(crate) fn looks_like_xml(bytes: &[u8]) -> bool {
    contains_marker(bytes, "<!-- SIG #")
}

pub(crate) fn looks_like(bytes: &[u8]) -> bool {
    contains_marker(bytes, "# SIG #")
}
fn contains_marker(bytes: &[u8], marker: &str) -> bool {
    let le: Vec<_> = marker.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let be: Vec<_> = marker.encode_utf16().flat_map(u16::to_be_bytes).collect();
    [marker.as_bytes(), &le, &be]
        .iter()
        .any(|needle| bytes.windows(needle.len()).any(|w| w == *needle))
}

impl Powershell<'_> {
    pub(crate) fn digest(&self, hash: Hash) -> Vec<u8> {
        let mut digest = hash.hasher();
        self.update_digest(&mut crate::crypto::DigestSink(digest.as_mut()));
        digest.finalize().to_vec()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn digest_faults_preserve_signature_math() {
        for (good, bad) in [
            ("good-powershell.ps1", "bad-powershell-digest.ps1"),
            ("good-powershell.ps1", "bad-powershell-line-endings.ps1"),
            (
                "good-powershell-utf8-bom.ps1",
                "bad-powershell-missing-bom.ps1",
            ),
            (
                "powershell-independent-jsign.ps1",
                "bad-powershell-independent-digest.ps1",
            ),
        ] {
            let good_bytes = fixture(good);
            let good = Powershell::parse(&good_bytes).unwrap();
            let bad_bytes = fixture(bad);
            let bad = Powershell::parse(&bad_bytes).unwrap();
            assert_eq!(good.signature(), bad.signature());
            let sd = crate::cms::SignedData::parse(bad.signature()).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            let (hash, expected) = sd.script_digest().unwrap();
            assert_eq!(good.digest(hash), expected);
            assert_ne!(bad.digest(hash), expected);
        }
        let bad_bytes = fixture("bad-powershell-cms-signature.ps1");
        let bad = Powershell::parse(&bad_bytes).unwrap();
        let sd = crate::cms::SignedData::parse(bad.signature()).unwrap();
        let (hash, expected) = sd.script_digest().unwrap();
        assert_eq!(bad.digest(hash), expected);
        assert!(sd.verify(sd.signers[0], false).is_err());
    }
    #[test]
    fn malformed_sip_fixtures_are_mathematically_signed() {
        for name in [
            "bad-powershell-sip-version.ps1",
            "bad-powershell-sip-uuid.ps1",
            "bad-powershell-sip-reserved.ps1",
            "bad-powershell-sip-type.ps1",
        ] {
            let script_bytes = fixture(name);
            let script = Powershell::parse(&script_bytes).unwrap();
            let sd = crate::cms::SignedData::parse(script.signature()).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            assert!(sd.script_digest().is_err());
        }
    }
    #[test]
    fn truncated_scripts_fail_without_panicking() {
        for name in [
            "good-powershell.ps1",
            "good-powershell-utf16le.ps1",
            "good-powershell-utf16be.ps1",
        ] {
            let bytes = fixture(name);
            for end in 0..bytes.len() {
                assert!(
                    Powershell::parse(&bytes[..end]).is_err(),
                    "accepted {name} prefix {end}"
                );
            }
        }
    }
    #[test]
    fn signature_text_bounds_and_base64_canonicalization_are_enforced() {
        for value in [
            "A",
            "AAAAA",
            "AB==",
            "AA=A",
            "!!!!",
            "AAA=AAAA",
            "",
            &"A".repeat(68),
        ] {
            let text = format!("{PREFIX}# {value}\r\n{SUFFIX}");
            assert!(
                Powershell::parse(text.as_bytes()).is_err(),
                "accepted {value:?}"
            );
        }
        let text = format!("{PREFIX}{}{SUFFIX}", "A".repeat(MAX_SIGNATURE_TEXT + 1));
        assert!(
            Powershell::parse(text.as_bytes())
                .err()
                .unwrap()
                .to_string()
                .contains("oversized")
        );
    }
    #[test]
    fn library_dispatch_and_domain_contract_are_format_specific() {
        let options = crate::VerifyOptions {
            trust: None,
            check_revocation: false,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        for name in [
            "good-powershell.ps1",
            "good-powershell-utf16le.ps1",
            "good-powershell-utf16be.ps1",
        ] {
            let b = fixture(name);
            for report in [
                crate::verify(&b, &options).unwrap(),
                crate::verify_powershell(&b, &options).unwrap(),
            ] {
                assert_eq!(report.format, "powershell_authenticode");
                let s = &report.signatures[0];
                let digest = s.script_digest.as_ref().unwrap();
                assert_eq!(digest.expected, digest.computed);
                assert!(
                    s.image_digest.is_none()
                        && s.package_digest.is_none()
                        && s.extended_digest.is_none()
                );
                let json = serde_json::to_value(report).unwrap();
                assert!(json["signatures"][0].get("script_digest").is_some());
                assert!(json["signatures"][0].get("image_digest").is_none());
            }
        }
        let error =
            crate::verify_powershell(&fixture("unsigned-powershell.ps1"), &options).unwrap_err();
        assert_eq!(error.code, ErrorCode::Unsigned);
        assert_eq!(error.stage, Stage::Powershell);
        let json = serde_json::to_value(error).unwrap();
        assert_eq!(json["code"], "unsigned");
        assert_eq!(json["stage"], "powershell");
        let json =
            serde_json::to_value(crate::verify_powershell(b"\xff", &options).unwrap_err()).unwrap();
        assert_eq!(json["code"], "invalid_powershell");
        assert_eq!(json["stage"], "powershell");
        assert!(has_extension(Path::new("X.PS1")));
        assert!(has_extension(Path::new("X.PsM1")));
        assert!(has_extension(Path::new("X.PsD1")));
        assert!(!has_extension(Path::new("X.ps1xml")));
        assert!(!has_extension(Path::new("X")));
        for (name, expected) in [
            ("good-pe64.exe", "pe_authenticode"),
            ("good.cab", "cab_authenticode"),
        ] {
            let b = fixture(name);
            assert!(crate::format::is_binary(&b));
            assert_eq!(crate::verify(&b, &options).unwrap().format, expected);
        }
        assert!(!crate::format::is_binary(&fixture("good-powershell.ps1")));
    }
}

#[cfg(test)]
mod xml_tests {
    use super::*;
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn xml_digest_faults_preserve_valid_cms_signatures() {
        for (good, bad) in [
            ("good-psxml.ps1xml", "bad-psxml-digest.ps1xml"),
            ("good-psxml.ps1xml", "bad-psxml-line-endings.ps1xml"),
            (
                "good-psxml-ascii-bom.ps1xml",
                "bad-psxml-missing-bom.ps1xml",
            ),
            (
                "psxml-independent-jsign-ascii.ps1xml",
                "bad-psxml-independent-digest.ps1xml",
            ),
        ] {
            let good_bytes = fixture(good);
            let good = Powershell::parse_xml(&good_bytes).unwrap();
            let bad_bytes = fixture(bad);
            let bad = Powershell::parse_xml(&bad_bytes).unwrap();
            assert_eq!(good.signature(), bad.signature());
            let sd = crate::cms::SignedData::parse(bad.signature()).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            let (hash, expected) = sd.script_digest().unwrap();
            assert_eq!(good.digest(hash), expected);
            assert_ne!(bad.digest(hash), expected);
        }
        let bad_bytes = fixture("bad-psxml-cms-signature.ps1xml");
        let bad = Powershell::parse_xml(&bad_bytes).unwrap();
        let sd = crate::cms::SignedData::parse(bad.signature()).unwrap();
        let (hash, expected) = sd.script_digest().unwrap();
        assert_eq!(bad.digest(hash), expected);
        assert!(sd.verify(sd.signers[0], false).is_err());
    }
    #[test]
    fn xml_prefixes_and_comment_delimiters_fail_closed() {
        for name in [
            "good-psxml.ps1xml",
            "good-psxml-utf16le.ps1xml",
            "good-psxml-utf16be.ps1xml",
        ] {
            let bytes = fixture(name);
            for end in 0..bytes.len() {
                assert!(
                    Powershell::parse_xml(&bytes[..end]).is_err(),
                    "accepted {name} prefix {end}"
                );
            }
        }
        let bad = fixture("bad-psxml-comment-end.ps1xml");
        let message = Powershell::parse_xml(&bad).err().unwrap().to_string();
        assert!(message.contains("invalid comment delimiters"), "{message}");
        assert!(has_xml_extension(Path::new("types.PS1XML")));
        assert!(!has_xml_extension(Path::new("types.ps1")));
        assert!(!has_xml_extension(Path::new("types.psc1")));
        assert!(Powershell::parse_xml(&fixture("good-powershell.ps1")).is_err());
        assert!(Powershell::parse(&fixture("good-psxml.ps1xml")).is_err());
    }
    #[test]
    fn xml_library_dispatch_and_json_use_the_existing_script_contract() {
        let options = crate::VerifyOptions {
            trust: None,
            check_revocation: false,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        for name in [
            "good-psxml.ps1xml",
            "good-psxml-utf8-bom.ps1xml",
            "good-psxml-utf16le.ps1xml",
            "good-psxml-utf16be.ps1xml",
        ] {
            let bytes = fixture(name);
            for report in [
                crate::verify(&bytes, &options).unwrap(),
                crate::verify_powershell_xml(&bytes, &options).unwrap(),
            ] {
                assert_eq!(report.format, "powershell_xml_authenticode");
                let value = serde_json::to_value(report).unwrap();
                let signature = &value["signatures"][0];
                assert!(signature.get("script_digest").is_some());
                for field in ["image_digest", "package_digest", "extended_digest"] {
                    assert!(signature.get(field).is_none());
                }
                assert!(value.get("rdp").is_none());
                let roundtrip: crate::VerificationBundle =
                    serde_json::from_value(value.clone()).unwrap();
                assert_eq!(serde_json::to_value(roundtrip).unwrap(), value);
            }
        }
        let error =
            crate::verify_powershell_xml(&fixture("unsigned.ps1xml"), &options).unwrap_err();
        assert_eq!(error.code, ErrorCode::Unsigned);
        assert_eq!(error.stage, Stage::Powershell);
        let value = serde_json::to_value(
            crate::verify_powershell_xml(&fixture("bad-psxml-ambiguous-utf8.ps1xml"), &options)
                .unwrap_err(),
        )
        .unwrap();
        assert_eq!(value["code"], "invalid_powershell");
        assert_eq!(value["stage"], "powershell");
    }
}
