//! Windows Script Host text containers; stored scripts are never executed or decoded as code.
use crate::{
    crypto::Hash,
    domain::{ErrorCode, Stage, VerificationError},
};
use anyhow::{Context, Result, ensure};
use base64ct::{Base64, Encoding};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    VbScript,
    JScript,
    Wsf,
}
impl Kind {
    fn markers(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::VbScript => (
                "'' SIG '' Begin signature block",
                "'' SIG '' End signature block",
                "'' SIG '' ",
            ),
            Self::JScript => (
                "// SIG // Begin signature block",
                "// SIG // End signature block",
                "// SIG // ",
            ),
            Self::Wsf => ("<signature>", "</signature>", "** SIG ** "),
        }
    }
    pub(crate) fn format(self) -> &'static str {
        match self {
            Self::VbScript => "vbscript_authenticode",
            Self::JScript => "jscript_authenticode",
            Self::Wsf => "wsf_authenticode",
        }
    }
    pub(crate) fn uuid(self) -> [u8; 16] {
        match self {
            Self::VbScript => [
                0x4e, 0xf0, 0x29, 0x16, 0x99, 0x27, 0xb5, 0x4d, 0x8f, 0xe5, 0xac, 0xe1, 0x0f, 0x17,
                0xeb, 0xab,
            ],
            Self::JScript => [
                0x10, 0xe0, 0xc9, 0x06, 0xce, 0x38, 0xd4, 0x11, 0xa2, 0xa3, 0, 0x10, 0x4b, 0xd3,
                0x50, 0x90,
            ],
            Self::Wsf => [
                0x70, 0x05, 0x61, 0x1a, 0xce, 0x38, 0xd4, 0x11, 0xa2, 0xa3, 0, 0x10, 0x4b, 0xd3,
                0x50, 0x90,
            ],
        }
    }
}
const KINDS: [Kind; 3] = [Kind::VbScript, Kind::JScript, Kind::Wsf];
pub(crate) fn extension(path: &Path) -> Option<Kind> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "vbs" | "vbe" => Some(Kind::VbScript),
        "js" | "jse" => Some(Kind::JScript),
        "wsf" => Some(Kind::Wsf),
        _ => None,
    }
}
fn contains(bytes: &[u8], marker: &str) -> bool {
    let le: Vec<_> = marker.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let be: Vec<_> = marker.encode_utf16().flat_map(u16::to_be_bytes).collect();
    [marker.as_bytes(), &le, &be]
        .iter()
        .any(|needle| bytes.windows(needle.len()).any(|w| w == *needle))
}
pub(crate) fn looks_like(bytes: &[u8]) -> bool {
    KINDS
        .iter()
        .any(|k| contains(bytes, k.markers().2.trim_end()))
}
pub(crate) fn detect(bytes: &[u8]) -> Result<Kind> {
    let found: Vec<_> = KINDS
        .into_iter()
        .filter(|k| contains(bytes, k.markers().2.trim_end()))
        .collect();
    if found.is_empty() {
        return Err(VerificationError::new(
            ErrorCode::Unsigned,
            Stage::Wsh,
            "WSH script has no signature block",
        )
        .into());
    }
    ensure!(found.len() == 1, "mixed WSH signature styles");
    Ok(found[0])
}
fn decode(bytes: &[u8], kind: Kind) -> Result<String> {
    ensure!(bytes.len() <= 64 * 1024 * 1024, "WSH input exceeds 64 MiB");
    let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        ensure!(bytes.len().is_multiple_of(2), "odd-length UTF-16 WSH input");
        let units: Vec<_> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| {
                if bytes[0] == 0xff {
                    u16::from_le_bytes(*b)
                } else {
                    u16::from_be_bytes(*b)
                }
            })
            .collect();
        String::from_utf16(&units)?
    } else if let Some(body) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        std::str::from_utf8(body)?.to_owned()
    } else {
        ensure!(
            kind == Kind::Wsf || bytes.is_ascii(),
            "BOM-less VBScript/JScript must be ASCII; Unicode requires a BOM"
        );
        std::str::from_utf8(bytes)?.to_owned()
    };
    ensure!(!text.contains('\0'), "NUL or unsupported WSH encoding");
    Ok(text)
}
pub(crate) struct Wsh {
    pub(crate) kind: Kind,
    body: String,
    position: u32,
    signature: Vec<u8>,
}
impl Wsh {
    pub(crate) fn parse(bytes: &[u8], kind: Kind) -> Result<Self> {
        let text = decode(bytes, kind)?;
        for other in KINDS.into_iter().filter(|k| *k != kind) {
            ensure!(
                !text.contains(other.markers().2.trim_end()),
                "mixed or mismatched WSH signature styles"
            );
        }
        ensure!(
            !text.contains("# SIG #") && !text.contains("<!-- SIG #"),
            "mixed script signature styles"
        );
        let (begin, end, prefix) = kind.markers();
        if !text.contains(prefix.trim_end()) && !text.contains(begin) && !text.contains(end) {
            return Err(VerificationError::new(
                ErrorCode::Unsigned,
                Stage::Wsh,
                "WSH script has no signature block",
            )
            .into());
        }
        ensure!(
            text.matches(begin).count() == 1 && text.matches(end).count() == 1,
            "missing or duplicate WSH signature markers"
        );
        let start = text
            .find(&format!("\r\n{begin}\r\n"))
            .context("WSH signature requires preceding CRLF and CRLF marker lines")?;
        let payload_start = start + 2 + begin.len() + 2;
        let end_start = text.find(end).context("missing signature end")?;
        ensure!(payload_start <= end_start, "reversed signature markers");
        let after = end_start + end.len() + 2;
        ensure!(
            text.get(end_start + end.len()..after) == Some("\r\n"),
            "WSH end marker requires CRLF"
        );
        let encoded = &text[payload_start..end_start];
        ensure!(
            !encoded.is_empty() && encoded.len() <= 16 * 1024 * 1024,
            "empty or oversized WSH signature"
        );
        let lines = encoded
            .strip_suffix("\r\n")
            .context("WSH payload requires CRLF lines")?;
        let mut base64 = String::with_capacity(lines.len());
        for line in lines.split("\r\n") {
            let value = line
                .strip_prefix(prefix)
                .context("invalid WSH signature line prefix")?;
            ensure!(
                !value.is_empty() && value.len() <= 64 && value.len().is_multiple_of(4),
                "invalid WSH base64 line length"
            );
            base64.push_str(value);
        }
        let signature =
            Base64::decode_vec(&base64).map_err(|e| anyhow::anyhow!("invalid WSH base64: {e}"))?;
        ensure!(!signature.is_empty(), "empty WSH signature");
        if kind == Kind::Wsf {
            let doc = roxmltree::Document::parse_with_options(
                &text,
                roxmltree::ParsingOptions {
                    allow_dtd: false,
                    nodes_limit: 100_000,
                    ..Default::default()
                },
            )?;
            let root = doc.root_element();
            ensure!(
                root.has_tag_name("job") && root.tag_name().namespace().is_none(),
                "WSF requires a single unqualified job root"
            );
            ensure!(
                root.descendants()
                    .filter(|n| n.is_element() && n.tag_name().name() == "job")
                    .count()
                    == 1,
                "nested WSF jobs unsupported"
            );
            let signatures: Vec<_> = root
                .descendants()
                .filter(|n| n.is_element() && n.tag_name().name() == "signature")
                .collect();
            ensure!(
                signatures.len() == 1,
                "WSF requires exactly one signature element"
            );
            let node = signatures[0];
            ensure!(
                node.tag_name().namespace().is_none()
                    && node.attributes().len() == 0
                    && node.parent() == Some(root),
                "invalid WSF signature element"
            );
            ensure!(
                root.children().rfind(|n| n.is_element()) == Some(node),
                "WSF signature must be the last child element"
            );
            ensure!(
                node.range() == (start + 2..after - 2) && text[after..].starts_with("</job>"),
                "invalid WSF signature placement"
            );
        } else {
            ensure!(after == text.len(), "WSH signature must terminate the file");
        }
        let position = u32::try_from(text[..start].encode_utf16().count())?;
        let mut body = text[..start].to_owned();
        body.push_str(&text[after..]);
        if kind == Kind::Wsf {
            ensure!(
                body.rfind("</job>") == Some(start),
                "ambiguous WSF insertion position"
            );
        }
        Ok(Self {
            kind,
            body,
            position,
            signature,
        })
    }
    pub(crate) fn signature(&self) -> &[u8] {
        &self.signature
    }
    pub(crate) fn digest(&self, hash: Hash) -> Vec<u8> {
        let mut bytes: Vec<_> = self
            .body
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes.extend(self.position.to_le_bytes());
        hash.digest(&bytes)
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
    fn truncated_blocks_and_encodings_fail_closed() {
        for (kind, name) in [
            (Kind::VbScript, "good-wsh.vbs"),
            (Kind::JScript, "good-wsh.js"),
            (Kind::Wsf, "good-wsh.wsf"),
            (Kind::VbScript, "good-wsh-utf16le.vbs"),
            (Kind::JScript, "good-wsh-utf16be.js"),
        ] {
            let bytes = fixture(name);
            let complete = Wsh::parse(&bytes, kind).unwrap();
            for end in 0..bytes.len() {
                // WSF may omit trailing root whitespace, but it must change the signed digest.
                if let Ok(short) = Wsh::parse(&bytes[..end], kind) {
                    assert_eq!(kind, Kind::Wsf);
                    assert_ne!(short.digest(Hash::Sha256), complete.digest(Hash::Sha256));
                }
            }
        }
        assert_eq!(extension(Path::new("file.VBE")), Some(Kind::VbScript));
        assert_eq!(extension(Path::new("file.JSE")), Some(Kind::JScript));
        assert_eq!(extension(Path::new("file.WSF")), Some(Kind::Wsf));
        assert_eq!(extension(Path::new("file.txt")), None);
    }
    #[test]
    fn mutated_text_preserves_cms_and_wrong_sips_preserve_signature_math() {
        for (kind, ext) in [
            (Kind::VbScript, "vbs"),
            (Kind::JScript, "js"),
            (Kind::Wsf, "wsf"),
        ] {
            let good = Wsh::parse(&fixture(&format!("good-wsh.{ext}")), kind).unwrap();
            let bad = Wsh::parse(&fixture(&format!("bad-wsh-digest.{ext}")), kind).unwrap();
            assert_eq!(good.signature(), bad.signature());
            assert_ne!(good.digest(Hash::Sha256), bad.digest(Hash::Sha256));
            for fault in [
                "sip-type",
                "sip-version",
                "sip-uuid",
                "sip-cross",
                "sip-reserved",
                "offset",
                "no-offset",
            ] {
                let artifact =
                    Wsh::parse(&fixture(&format!("bad-wsh-{fault}.{ext}")), kind).unwrap();
                let cms = crate::cms::SignedData::parse(artifact.signature()).unwrap();
                for signer in &cms.signers {
                    cms.verify(*signer, false).unwrap();
                }
                if fault.starts_with("sip-") {
                    assert!(cms.wsh_digest(kind).is_err());
                } else {
                    let (hash, expected) = cms.wsh_digest(kind).unwrap();
                    assert_ne!(artifact.digest(hash), expected);
                }
            }
        }
    }
    #[test]
    fn independent_mutations_preserve_valid_cms_signatures() {
        for (kind, ext) in [
            (Kind::VbScript, "vbs"),
            (Kind::VbScript, "vbe"),
            (Kind::JScript, "js"),
            (Kind::JScript, "jse"),
            (Kind::Wsf, "wsf"),
        ] {
            let good = Wsh::parse(&fixture(&format!("wsh-independent-jsign.{ext}")), kind).unwrap();
            let bad =
                Wsh::parse(&fixture(&format!("bad-wsh-independent-digest.{ext}")), kind).unwrap();
            assert_eq!(good.signature(), bad.signature());
            let cms = crate::cms::SignedData::parse(bad.signature()).unwrap();
            for signer in &cms.signers {
                cms.verify(*signer, false).unwrap();
            }
            let (hash, expected) = cms.wsh_digest(kind).unwrap();
            assert_eq!(good.digest(hash), expected);
            assert_ne!(bad.digest(hash), expected);
        }
    }
    #[test]
    fn resource_limits_reject_before_base64_or_xml_allocation() {
        let too_large = vec![b' '; 64 * 1024 * 1024 + 1];
        assert!(
            Wsh::parse(&too_large, Kind::VbScript)
                .err()
                .unwrap()
                .to_string()
                .contains("64 MiB")
        );
        drop(too_large);
        let (begin, end, prefix) = Kind::JScript.markers();
        let mut block = format!("\r\n{begin}\r\n{prefix}");
        block.push_str(&"A".repeat(16 * 1024 * 1024));
        block.push_str(&format!("\r\n{end}\r\n"));
        assert!(
            Wsh::parse(block.as_bytes(), Kind::JScript)
                .err()
                .unwrap()
                .to_string()
                .contains("oversized")
        );
    }
    #[test]
    fn library_dispatch_and_serialized_domain_contract() {
        let options = crate::VerifyOptions {
            trust: None,
            check_revocation: false,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        for (name, format) in [
            ("good-wsh.vbs", "vbscript_authenticode"),
            ("good-wsh.jse", "jscript_authenticode"),
            ("good-wsh.wsf", "wsf_authenticode"),
        ] {
            let bytes = fixture(name);
            for report in [
                crate::verify(&bytes, &options).unwrap(),
                crate::verify_wsh(&bytes, &options).unwrap(),
            ] {
                assert_eq!(report.format, format);
                let value = serde_json::to_value(report).unwrap();
                assert!(value["signatures"][0].get("script_digest").is_some());
                assert!(value["signatures"][0].get("image_digest").is_none());
                let roundtrip: crate::VerificationBundle =
                    serde_json::from_value(value.clone()).unwrap();
                assert_eq!(serde_json::to_value(roundtrip).unwrap(), value);
            }
        }
        let error = crate::verify_wsh(&fixture("bad-wsh-mixed.vbs"), &options).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidWsh);
        assert_eq!(error.stage, Stage::Wsh);
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(value["code"], "invalid_wsh");
        assert_eq!(value["stage"], "wsh");
        let unsigned = crate::verify_wsh(&fixture("unsigned-wsh.vbs"), &options).unwrap_err();
        assert_eq!(unsigned.code, ErrorCode::Unsigned);
        assert_eq!(unsigned.stage, Stage::Wsh);
    }
}
