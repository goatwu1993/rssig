//! Single-volume CAB Authenticode parsing. No decompression or extraction.
use crate::crypto::Hash;
use crate::domain::{ErrorCode, Stage, VerificationError};
use anyhow::{Result, ensure};

pub(crate) const MAGIC: &[u8; 4] = b"MSCF";

pub(crate) struct Cab<'a> {
    bytes: &'a [u8],
    end: usize,
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    let b = bytes
        .get(at..at + 2)
        .ok_or_else(|| anyhow::anyhow!("truncated CAB field"))?;
    Ok(u16::from_le_bytes(b.try_into()?))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<usize> {
    let b = bytes
        .get(at..at + 4)
        .ok_or_else(|| anyhow::anyhow!("truncated CAB field"))?;
    Ok(u32::from_le_bytes(b.try_into()?) as usize)
}
impl<'a> Cab<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 36 && bytes.starts_with(MAGIC),
            "truncated or invalid CAB header"
        );
        ensure!(bytes[24..26] == [3, 1], "unsupported CAB version");
        ensure!(
            u32_at(bytes, 4)? == 0 && u32_at(bytes, 12)? == 0 && u32_at(bytes, 20)? == 0,
            "nonzero CAB reserved header fields"
        );
        let flags = u16_at(bytes, 30)?;
        ensure!(
            flags == 0 || flags == 4,
            "multipart or unsupported CAB flags"
        );
        ensure!(
            u16_at(bytes, 34)? == 0,
            "multipart CAB index is unsupported"
        );
        let end = u32_at(bytes, 8)?;
        ensure!(
            end >= 36 && end <= bytes.len(),
            "CAB size is outside the file"
        );
        if flags == 0 {
            ensure!(end == bytes.len(), "trailing data after unsigned CAB");
            return Err(VerificationError::new(
                ErrorCode::Unsigned,
                Stage::Cab,
                "CAB has no signature reserve",
            )
            .into());
        }
        ensure!(
            bytes.len() >= 60 && bytes[36..40] == [20, 0, 0, 0],
            "unsupported CAB reserve layout"
        );
        ensure!(
            bytes[40..44] == [0, 0, 16, 0] && bytes[52..60] == [0; 8],
            "unsupported CAB signature reserve"
        );
        ensure!(
            u32_at(bytes, 44)? == end,
            "CAB signature offset must equal cabinet size"
        );
        let size = u32_at(bytes, 48)?;
        ensure!(
            size == bytes.len() - end,
            "CAB signature size mismatch or trailing data"
        );
        let folders = usize::from(u16_at(bytes, 26)?);
        let files = usize::from(u16_at(bytes, 28)?);
        ensure!(
            folders > 0 && files > 0,
            "empty CAB containers are unsupported"
        );
        let file_start = 60 + folders * 8;
        ensure!(
            file_start <= end && u32_at(bytes, 16)? == file_start,
            "invalid CAB folder table or file offset"
        );
        let mut file_end = file_start;
        let mut file_ranges = Vec::with_capacity(files.min((end - file_start) / 17));
        for _ in 0..files {
            ensure!(end - file_end >= 17, "truncated CAB file entry");
            let length = u32_at(bytes, file_end)?;
            let offset = u32_at(bytes, file_end + 4)?;
            let folder = usize::from(u16_at(bytes, file_end + 8)?);
            ensure!(folder < folders, "invalid or split CAB file folder index");
            let name_start = file_end + 16;
            let name_len = bytes[name_start..end]
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| anyhow::anyhow!("unterminated CAB file name"))?;
            ensure!(name_len > 0, "empty CAB file name");
            file_end = name_start + name_len + 1;
            file_ranges.push((folder, offset, length));
        }
        let mut next = file_end;
        let mut unpacked = Vec::with_capacity(folders);
        for folder in 0..folders {
            let at = 60 + folder * 8;
            ensure!(
                u32_at(bytes, at)? == next,
                "noncontiguous or invalid CAB folder data offset"
            );
            let blocks = usize::from(u16_at(bytes, at + 4)?);
            let mut total = 0u64;
            for _ in 0..blocks {
                ensure!(end - next >= 8, "truncated CAB data header");
                let compressed = usize::from(u16_at(bytes, next + 4)?);
                let uncompressed = u64::from(u16_at(bytes, next + 6)?);
                ensure!(
                    uncompressed > 0 && uncompressed <= 32768,
                    "invalid or split CAB data block"
                );
                ensure!(
                    compressed > 0 && compressed <= end - next - 8,
                    "CAB data block exceeds cabinet bounds"
                );
                total += uncompressed;
                next += 8 + compressed;
            }
            unpacked.push(total);
        }
        ensure!(next == end, "unaccounted data inside CAB");
        for (folder, offset, length) in file_ranges {
            ensure!(
                offset as u64 + length as u64 <= unpacked[folder],
                "CAB file exceeds folder bounds"
            );
        }
        if size == 0 {
            return Err(VerificationError::new(
                ErrorCode::Unsigned,
                Stage::Cab,
                "CAB has no embedded signature",
            )
            .into());
        }
        Ok(Self { bytes, end })
    }
    pub(crate) fn signature(&self) -> &'a [u8] {
        &self.bytes[self.end..]
    }
    pub(crate) fn digest(&self, hash: Hash) -> Vec<u8> {
        // Standard reserve with empty structure1, 16-byte signature pointer,
        // cabinet index zero. Header checksum and signature metadata are omitted.
        // The final four zero bytes are iCabinet + structure1 length (jsign),
        // equivalently SignatureHeader.Unknown3 (relic) for this supported layout.
        let mut h = hash.hasher();
        h.update(&self.bytes[..4]);
        h.update(&self.bytes[8..34]);
        h.update(&[0; 4]);
        h.update(&self.bytes[60..self.end]);
        h.finalize().to_vec()
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
