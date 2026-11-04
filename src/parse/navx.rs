//! Bounded NAVX envelope reader. The signature covers the complete header and payload.
use super::{Error, ErrorKind};
use anyhow::{Result, ensure};

pub(crate) const MAGIC: &[u8] = b"NAVX";
/// An untrusted signed NAVX container borrowing immutable input.
///
/// Parsing checks the supported container layout only; CMS interpretation,
/// integrity, timestamps, and certificate trust belong to verification.
#[derive(Debug)]
pub struct Navx<'a> {
    bytes: &'a [u8],
    end: usize,
}
impl<'a> Navx<'a> {
    /// Parse the supported signed NAVX layout without hashing or authenticating it.
    ///
    /// Missing signatures and malformed/unsupported layouts return typed errors.
    /// The embedded signature is opaque here, including any CMS padding.
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::parse_inner(bytes).map_err(|e| Error::new(ErrorKind::InvalidNavx, e))
    }

    fn parse_inner(bytes: &'a [u8]) -> Result<Self> {
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
            return Err(Error::new(
                ErrorKind::UnsignedNavx,
                anyhow::anyhow!("NAVX has no embedded signature"),
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
    /// The original complete container bytes, borrowed without copying.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Borrow the opaque embedded signature bytes without parsing CMS.
    ///
    /// Excludes the NXSB wrapper; verification requires exactly one CMS DER object with no padding.
    pub fn signature(&self) -> &'a [u8] {
        &self.bytes[self.end + 4..self.bytes.len() - 8]
    }
    /// Borrow the Authenticode digest input: the complete header and payload.
    ///
    /// The NXSB signature wrapper is excluded. No hashing or authentication is
    /// performed; the single chunk borrows the original input.
    pub fn authenticode_chunks(&self) -> [&'a [u8]; 1] {
        [&self.bytes[..self.end]]
    }
}
