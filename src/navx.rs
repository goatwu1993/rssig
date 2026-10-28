//! Bounded NAVX envelope reader. The signature covers the complete header and payload.
use crate::{
    crypto::Hash,
    domain::{ErrorCode, Stage, VerificationError},
};
use anyhow::{Result, ensure};

pub(crate) const MAGIC: &[u8] = b"NAVX";
pub(crate) struct Navx<'a> {
    bytes: &'a [u8],
    end: usize,
}
impl<'a> Navx<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(bytes.len() >= 40, "truncated NAVX header");
        ensure!(
            &bytes[..4] == MAGIC && &bytes[36..40] == MAGIC,
            "invalid NAVX header markers"
        );
        let size = u32::from_le_bytes(bytes[28..32].try_into()?) as usize;
        let end = 40usize
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("NAVX content size overflow"))?;
        ensure!(end <= bytes.len(), "NAVX content extends beyond file");
        if end == bytes.len() {
            return Err(VerificationError::new(
                ErrorCode::Unsigned,
                Stage::Navx,
                "NAVX has no embedded signature",
            )
            .into());
        }
        let block = &bytes[end..];
        ensure!(block.len() > 12, "truncated NAVX signature block");
        ensure!(
            &block[..4] == b"NXSB" && &block[block.len() - 4..] == b"NXSB",
            "invalid NAVX signature block markers"
        );
        let offset =
            u32::from_le_bytes(block[block.len() - 8..block.len() - 4].try_into()?) as usize;
        ensure!(offset == end, "NAVX signature block offset mismatch");
        Ok(Self { bytes, end })
    }
    pub(crate) fn signature(&self) -> &'a [u8] {
        &self.bytes[self.end + 4..self.bytes.len() - 8]
    }
    pub(crate) fn digest(&self, hash: Hash) -> Vec<u8> {
        hash.digest(&self.bytes[..self.end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn truncations_and_unbounded_content_sizes_fail_closed() {
        let good = fixture("good.navx");
        for end in 0..good.len() {
            assert!(Navx::parse(&good[..end]).is_err(), "accepted prefix {end}");
        }
        let mut b = good;
        b[28..32].fill(255);
        assert!(Navx::parse(&b).is_err());
    }
    #[test]
    fn tampered_payload_preserves_valid_cms_and_changes_only_package_digest() {
        for (good, bad) in [
            ("good.navx", "bad-navx-digest.navx"),
            (
                "navx-independent-jsign.navx",
                "bad-navx-independent-digest.navx",
            ),
        ] {
            let good = fixture(good);
            let bad = fixture(bad);
            let a = Navx::parse(&good).unwrap();
            let b = Navx::parse(&bad).unwrap();
            assert_eq!(a.signature(), b.signature());
            let sd = crate::cms::SignedData::parse(b.signature()).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            let (hash, expected) = sd.navx_digest().unwrap();
            assert_eq!(a.digest(hash), expected);
            assert_ne!(b.digest(hash), expected);
        }
    }
    #[test]
    fn signature_fault_preserves_valid_package_digest() {
        let bytes = fixture("bad-navx-cms-signature.navx");
        let navx = Navx::parse(&bytes).unwrap();
        let sd = crate::cms::SignedData::parse(navx.signature()).unwrap();
        let (hash, expected) = sd.navx_digest().unwrap();
        assert_eq!(navx.digest(hash), expected);
        assert!(sd.verify(sd.signers[0], false).is_err());
    }
    #[test]
    fn explicit_api_returns_serialized_domain_errors() {
        let options = crate::VerifyOptions {
            trust: None,
            check_revocation: false,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        assert_eq!(
            crate::verify_navx(&fixture("good.navx"), &options)
                .unwrap()
                .format,
            "navx_authenticode"
        );
        let error = crate::verify_navx(b"MZ", &options).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidNavx);
        assert_eq!(error.stage, Stage::Navx);
        let json = serde_json::to_value(error).unwrap();
        assert_eq!(json["code"], "invalid_navx");
        assert_eq!(json["stage"], "navx");
    }
}
