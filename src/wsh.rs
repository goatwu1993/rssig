use crate::crypto::Hash;
#[cfg(test)]
use crate::domain::{ErrorCode, Stage};
pub(crate) use crate::parse::wsh::{Kind, Wsh};
#[cfg(test)]
use std::path::Path;
const KINDS: [Kind; 3] = [Kind::VbScript, Kind::JScript, Kind::Wsf];
#[cfg(test)]
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
pub(crate) fn detect(bytes: &[u8]) -> anyhow::Result<Kind> {
    Wsh::detect(bytes).map_err(|e| crate::VerificationError::from(e).into())
}
impl Wsh<'_> {
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
            let good_bytes = fixture(&format!("good-wsh.{ext}"));
            let good = Wsh::parse(&good_bytes, kind).unwrap();
            let bad_bytes = fixture(&format!("bad-wsh-digest.{ext}"));
            let bad = Wsh::parse(&bad_bytes, kind).unwrap();
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
                let artifact_bytes = fixture(&format!("bad-wsh-{fault}.{ext}"));
                let artifact = Wsh::parse(&artifact_bytes, kind).unwrap();
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
            let good_bytes = fixture(&format!("wsh-independent-jsign.{ext}"));
            let good = Wsh::parse(&good_bytes, kind).unwrap();
            let bad_bytes = fixture(&format!("bad-wsh-independent-digest.{ext}"));
            let bad = Wsh::parse(&bad_bytes, kind).unwrap();
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
