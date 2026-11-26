//! Single-volume CAB Authenticode parsing. No decompression or extraction.
use super::{Error, ErrorKind};
use alloc::vec::Vec;
use anyhow::{Result, ensure};

pub(crate) const MAGIC: &[u8; 4] = b"MSCF";

/// An untrusted signed CAB container borrowing immutable input.
///
/// Parsing checks the supported container layout only; CMS interpretation,
/// integrity, timestamps, and certificate trust belong to verification.
#[derive(Debug)]
pub struct Cab<'a> {
    bytes: &'a [u8],
    end: usize,
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    let b = bytes
        .get(at..)
        .and_then(|bytes| bytes.get(..2))
        .ok_or_else(|| anyhow::anyhow!("truncated CAB field"))?;
    Ok(u16::from_le_bytes(b.try_into()?))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<usize> {
    let b = bytes
        .get(at..)
        .and_then(|bytes| bytes.get(..4))
        .ok_or_else(|| anyhow::anyhow!("truncated CAB field"))?;
    Ok(u32::from_le_bytes(b.try_into()?) as usize)
}
impl<'a> Cab<'a> {
    /// Parse the supported signed CAB layout without hashing or authenticating it.
    ///
    /// Missing signatures and malformed/unsupported layouts return typed errors.
    /// The embedded signature is opaque here, including any CMS padding.
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::parse_inner(bytes).map_err(|e| Error::new(ErrorKind::InvalidCab, e))
    }

    fn parse_inner(bytes: &'a [u8]) -> Result<Self> {
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
            return Err(Error::new(
                ErrorKind::UnsignedCab,
                anyhow::anyhow!("CAB has no signature reserve"),
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
            return Err(Error::new(
                ErrorKind::UnsignedCab,
                anyhow::anyhow!("CAB has no embedded signature"),
            )
            .into());
        }
        Ok(Self { bytes, end })
    }
    /// The original complete container bytes, borrowed without copying.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Borrow the opaque embedded signature bytes without parsing CMS.
    ///
    /// Includes any CAB signature padding; verification permits at most seven zero bytes after CMS.
    pub fn signature(&self) -> &'a [u8] {
        &self.bytes[self.end..]
    }
    /// Borrow the four Authenticode digest chunks in order, without hashing.
    ///
    /// The checksum and signature metadata are omitted. The four canonical
    /// zero bytes borrow the validated zero reserve at offsets 56..60; this is
    /// equivalent to the zero cabinet index plus empty structure1 length.
    /// Every slice borrows the original input. No trust verdict is produced.
    pub fn authenticode_chunks(&self) -> [&'a [u8]; 4] {
        [
            &self.bytes[..4],
            &self.bytes[8..34],
            &self.bytes[56..60],
            &self.bytes[60..self.end],
        ]
    }
}

#[cfg(test)]
mod offset_tests {
    #[test]
    fn field_offsets_never_overflow() {
        for at in [usize::MAX, usize::MAX - 1, usize::MAX - 3] {
            assert!(super::u16_at(&[], at).is_err());
            assert!(super::u32_at(&[], at).is_err());
        }
    }
}
