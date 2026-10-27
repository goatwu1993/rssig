//! Hash-comment PowerShell Authenticode signatures; scripts are never executed.
use crate::{
    crypto::Hash,
    domain::{ErrorCode, Stage, VerificationError},
};
use anyhow::{Result, ensure};
use base64ct::{Base64, Encoding};
use std::path::Path;

const BEGIN: &str = "# SIG # Begin signature block";
const END: &str = "# SIG # End signature block";
const PREFIX: &str = "\r\n# SIG # Begin signature block\r\n";
const SUFFIX: &str = "# SIG # End signature block\r\n";
const MAX_SIGNATURE_TEXT: usize = 16 * 1024 * 1024;

pub(crate) struct Powershell {
    body: String,
    signature: Vec<u8>,
}

pub(crate) fn has_extension(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()).is_some_and(|s| {
        ["ps1", "psm1", "psd1"]
            .iter()
            .any(|ext| s.eq_ignore_ascii_case(ext))
    })
}

pub(crate) fn looks_like(bytes: &[u8]) -> bool {
    let marker = "# SIG #";
    let le: Vec<_> = marker.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let be: Vec<_> = marker.encode_utf16().flat_map(u16::to_be_bytes).collect();
    [marker.as_bytes(), &le, &be]
        .iter()
        .any(|needle| bytes.windows(needle.len()).any(|w| w == *needle))
}

fn decode(bytes: &[u8]) -> Result<String> {
    let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        ensure!(
            bytes.len().is_multiple_of(2),
            "odd-length UTF-16 PowerShell script"
        );
        let little = bytes[0] == 0xff;
        let units: Vec<_> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| {
                let pair = [b[0], b[1]];
                if little {
                    u16::from_le_bytes(pair)
                } else {
                    u16::from_be_bytes(pair)
                }
            })
            .collect();
        String::from_utf16(&units)?
    } else {
        std::str::from_utf8(bytes)?.to_owned()
    };
    ensure!(
        !text.contains('\0'),
        "NUL or unsupported script encoding (UTF-16 requires a BOM)"
    );
    Ok(text)
}

impl Powershell {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut text = decode(bytes)?;
        if !text.contains("# SIG #") {
            return Err(VerificationError::new(
                ErrorCode::Unsigned,
                Stage::Powershell,
                "PowerShell script has no signature block",
            )
            .into());
        }
        ensure!(
            text.matches(BEGIN).count() == 1 && text.matches(END).count() == 1,
            "missing or duplicate PowerShell signature markers"
        );
        let start = text.find(PREFIX).ok_or_else(|| {
            anyhow::anyhow!(
                "PowerShell signature block requires a preceding CRLF and CRLF marker lines"
            )
        })?;
        let encoded_start = start + PREFIX.len();
        let before_end = text.strip_suffix(SUFFIX).ok_or_else(|| {
            anyhow::anyhow!("PowerShell signature end marker must terminate the file with CRLF")
        })?;
        ensure!(
            encoded_start <= before_end.len(),
            "reversed PowerShell signature markers"
        );
        let encoded = &before_end[encoded_start..];
        ensure!(
            !encoded.is_empty() && encoded.len() <= MAX_SIGNATURE_TEXT,
            "empty or oversized PowerShell signature block"
        );
        let lines = encoded
            .strip_suffix("\r\n")
            .ok_or_else(|| anyhow::anyhow!("PowerShell signature payload requires CRLF lines"))?;
        let mut base64 = String::with_capacity(lines.len());
        for line in lines.split("\r\n") {
            let value = line.strip_prefix("# ").ok_or_else(|| {
                anyhow::anyhow!("PowerShell signature line requires '# ' comment prefix")
            })?;
            ensure!(
                !value.is_empty() && value.len() <= 64 && value.len().is_multiple_of(4),
                "invalid PowerShell base64 line length"
            );
            base64.push_str(value);
        }
        let signature = Base64::decode_vec(&base64)
            .map_err(|e| anyhow::anyhow!("invalid PowerShell signature base64: {e}"))?;
        ensure!(!signature.is_empty(), "empty PowerShell CMS signature");
        text.truncate(start);
        Ok(Self {
            body: text,
            signature,
        })
    }
    pub(crate) fn signature(&self) -> &[u8] {
        &self.signature
    }
    pub(crate) fn digest(&self, hash: Hash) -> Vec<u8> {
        // Include U+FEFF when present; preserve every original body line ending.
        // Exclude only the inserted CRLF and terminal signature block.
        let mut h = hash.hasher();
        for unit in self.body.encode_utf16() {
            h.update(&unit.to_le_bytes());
        }
        h.finalize().to_vec()
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
            let good = Powershell::parse(&fixture(good)).unwrap();
            let bad = Powershell::parse(&fixture(bad)).unwrap();
            assert_eq!(good.signature(), bad.signature());
            let sd = crate::cms::SignedData::parse(bad.signature()).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            let (hash, expected) = sd.script_digest().unwrap();
            assert_eq!(good.digest(hash), expected);
            assert_ne!(bad.digest(hash), expected);
        }
        let bad = Powershell::parse(&fixture("bad-powershell-cms-signature.ps1")).unwrap();
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
            let script = Powershell::parse(&fixture(name)).unwrap();
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
            assert!(crate::verify::is_binary(&b));
            assert_eq!(crate::verify(&b, &options).unwrap().format, expected);
        }
        assert!(!crate::verify::is_binary(&fixture("good-powershell.ps1")));
    }
}
