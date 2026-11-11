//! Verification hashing adapter for the public CAB parser.
use crate::crypto::Hash;
pub(crate) use crate::parse::Cab;
pub(crate) use crate::parse::cab::MAGIC;
use alloc::vec::Vec;

impl Cab<'_> {
    pub(crate) fn digest(&self, hash: Hash) -> Vec<u8> {
        let mut digest = hash.hasher();
        for chunk in self.authenticode_chunks() {
            digest.update(chunk);
        }
        digest.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ErrorCode, Stage};
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn every_truncated_prefix_is_rejected() {
        let b = fixture("good.cab");
        for end in 0..b.len() {
            assert!(Cab::parse(&b[..end]).is_err(), "accepted prefix {end}");
        }
    }
    #[test]
    fn malformed_counts_offsets_and_lengths_are_bounded() {
        let good = fixture("good.cab");
        for at in [8, 16, 44, 48, 60, 68, 72] {
            let mut b = good.clone();
            b[at..at + 4].fill(255);
            assert!(Cab::parse(&b).is_err(), "accepted u32 at {at}");
        }
        for at in [26, 28, 34, 36, 64, 76, 90, 92] {
            let mut b = good.clone();
            b[at..at + 2].fill(255);
            assert!(Cab::parse(&b).is_err(), "accepted u16 at {at}");
        }
        let mut b = good.clone();
        b[84..98].fill(255);
        assert!(Cab::parse(&b).is_err());
        for at in [24, 38, 39, 40, 52, 56] {
            let mut b = good.clone();
            b[at] ^= 1;
            assert!(
                Cab::parse(&b).is_err(),
                "accepted reserved/version byte {at}"
            );
        }
    }
    #[test]
    fn digest_faults_preserve_valid_cms_and_signature_faults_preserve_digest() {
        for (good, bad) in [
            ("good.cab", "bad-cab-digest.cab"),
            (
                "cab-independent-jsign.cab",
                "bad-cab-independent-digest.cab",
            ),
        ] {
            let good_bytes = fixture(good);
            let bad_bytes = fixture(bad);
            let good = Cab::parse(&good_bytes).unwrap();
            let bad = Cab::parse(&bad_bytes).unwrap();
            assert_eq!(good.signature(), bad.signature());
            let mut rest = bad.signature();
            let cms = crate::der::take(&mut rest).unwrap();
            let sd = crate::cms::SignedData::parse(cms.full).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            let (hash, expected) = sd.cab_digest().unwrap();
            assert_eq!(good.digest(hash), expected);
            assert_ne!(bad.digest(hash), expected);
        }
        let b = fixture("bad-cab-cms-signature.cab");
        let cab = Cab::parse(&b).unwrap();
        let mut rest = cab.signature();
        let cms = crate::der::take(&mut rest).unwrap();
        let sd = crate::cms::SignedData::parse(cms.full).unwrap();
        let (hash, expected) = sd.cab_digest().unwrap();
        assert_eq!(cab.digest(hash), expected);
        assert!(sd.verify(sd.signers[0], false).is_err());
    }
    #[test]
    fn explicit_cab_api_rejects_other_formats_and_returns_domain_errors() {
        let options = crate::VerifyOptions {
            trust: None,
            check_revocation: false,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        let b = fixture("good.cab");
        let result = crate::verify_cab(&b, &options).unwrap();
        assert_eq!(result.format, "cab_authenticode");
        let error = crate::verify_cab(b"MZ", &options).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidCab);
        assert_eq!(error.stage, Stage::Cab);
        let json = serde_json::to_value(error).unwrap();
        assert_eq!(json["code"], "invalid_cab");
        assert_eq!(json["stage"], "cab");
    }
}
