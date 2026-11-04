use super::{Error, ErrorKind};
use alloc::vec::Vec;
use anyhow::{Result, ensure};
use core::ops::Range;

/// Offsets delimiting the portions included in an Authenticode PE image digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeOffsets {
    /// Start of the optional-header checksum field.
    pub check_sum: usize,
    /// First byte after the four-byte checksum.
    pub after_check_sum: usize,
    /// Start of the security data-directory entry.
    pub security_data_dir: usize,
    /// First byte after the security data-directory entry.
    pub after_security_data_dir: usize,
    /// End of the PE headers.
    pub after_header: usize,
}

/// A PE range or offset is outside the supplied byte slice or overflows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeOffsetError;

impl core::fmt::Display for PeOffsetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid PE offset or range")
    }
}

impl core::error::Error for PeOffsetError {}

/// Borrowed PE byte ranges needed to calculate an Authenticode image digest.
///
/// Implement this for another PE reader to reuse [`super::authenticode_digest`].
/// The caller is responsible for ensuring the ranges follow the desired PE
/// hashing policy; the trait does not validate or authenticate the input.
pub trait PeTrait {
    /// Complete immutable PE byte slice.
    fn data(&self) -> &[u8];
    /// Number of PE sections.
    fn num_sections(&self) -> usize;
    /// Section raw-data range for a one-based section index.
    fn section_data_range(&self, index: usize) -> Result<Range<usize>, PeOffsetError>;
    /// Certificate table file range, if present.
    fn certificate_table_range(&self) -> Result<Option<Range<usize>>, PeOffsetError>;
    /// Offsets for checksum, security directory, and header exclusions.
    fn offsets(&self) -> Result<PeOffsets, PeOffsetError>;
}

/// A borrowed signed PE layout. All extracted data is untrusted.
///
/// Accepts the same bounded, contiguous PE layouts as the verifier. This is
/// not a general PE loader and does not authenticate any bytes.
#[derive(Debug)]
pub struct Pe<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) checksum: usize,
    pub(crate) directory: usize,
    pub(crate) cert_start: usize,
    pub(crate) cert_end: usize,
    pub(crate) headers_end: usize,
    pub(crate) sections: Vec<(usize, usize)>,
    #[cfg(feature = "verify")]
    pub(crate) page_size: usize,
}

fn u16_at(data: &[u8], at: usize) -> Result<usize> {
    let b = data
        .get(at..)
        .and_then(|bytes| bytes.get(..2))
        .ok_or_else(|| anyhow::anyhow!("truncated PE header"))?;
    Ok(u16::from_le_bytes(b.try_into()?) as usize)
}
fn u32_at(data: &[u8], at: usize) -> Result<usize> {
    let b = data
        .get(at..)
        .and_then(|bytes| bytes.get(..4))
        .ok_or_else(|| anyhow::anyhow!("truncated PE header"))?;
    Ok(u32::from_le_bytes(b.try_into()?) as usize)
}

impl<'a> Pe<'a> {
    /// Parse PE headers and signed-image ranges without hashing or cryptography.
    pub fn parse(data: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::parse_inner(data).map_err(|e| Error::new(ErrorKind::InvalidPe, e))
    }

    /// Original immutable bytes, including the certificate table.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Borrow the image bytes in Authenticode digest order, without copying.
    ///
    /// Excludes the checksum, security directory entry, and certificate table.
    /// Feed each chunk to a digest implementation of your choice. Computing a
    /// digest does not authenticate it or establish certificate trust.
    ///
    /// Only the bounded, contiguous layouts accepted by [`Self::parse`] are
    /// supported; this does not implement arbitrary Windows PE hashing policy.
    pub fn authenticode_chunks(&self) -> [&'a [u8]; 3] {
        [
            &self.data[..self.checksum],
            &self.data[self.checksum + 4..self.directory],
            &self.data[self.directory + 8..self.cert_start],
        ]
    }

    /// Extract embedded CMS DER objects, permitting only zero WIN_CERTIFICATE padding.
    /// CMS contents and signatures remain unverified; use `SignedData::parse` to inspect them.
    pub fn signatures(&self) -> core::result::Result<Vec<&'a [u8]>, Error> {
        self.signatures_inner()
            .map_err(|e| Error::new(ErrorKind::InvalidCertificateTable, e))
    }

    fn signatures_inner(&self) -> Result<Vec<&'a [u8]>> {
        self.certificates()?
            .into_iter()
            .map(|certificate| {
                let mut rest = certificate;
                let node = crate::der::take(&mut rest)?;
                ensure!(
                    rest.iter().all(|b| *b == 0),
                    "nonzero trailing data in WIN_CERTIFICATE"
                );
                Ok(node.full)
            })
            .collect()
    }

    pub(crate) fn parse_inner(data: &'a [u8]) -> Result<Self> {
        ensure!(data.get(..2) == Some(b"MZ"), "not a PE file (missing MZ)");
        let pe = u32_at(data, 0x3c)?;
        ensure!(
            pe >= 64 && data.get(pe..).and_then(|bytes| bytes.get(..4)) == Some(b"PE\0\0"),
            "invalid PE signature"
        );
        // Bound the complete COFF header before doing offset arithmetic. In
        // particular, e_lfanew is an untrusted u32 even on a 32-bit target.
        ensure!(data.len() - pe >= 24, "truncated PE header");
        let section_count = u16_at(data, pe + 6)?;
        let opt_len = u16_at(data, pe + 20)?;
        let opt = pe + 24;
        ensure!(
            opt_len <= data.len() - opt && opt_len >= 2,
            "truncated optional header"
        );
        let (dirs_offset, num_dirs_offset) = match u16_at(data, opt)? {
            0x10b => (96, 92),
            0x20b => (112, 108),
            _ => anyhow::bail!("unsupported optional header magic"),
        };
        ensure!(dirs_offset + 40 <= opt_len, "truncated optional header");
        let directory = opt + dirs_offset + 32;
        let num_dirs = opt + num_dirs_offset;
        ensure!(u32_at(data, num_dirs)? >= 5, "PE has no security directory");
        let headers_end = u32_at(data, opt + 60)?;
        let section_table = opt + opt_len;
        ensure!(
            section_table <= headers_end
                && headers_end <= data.len()
                && section_count <= (headers_end - section_table) / 40,
            "invalid SizeOfHeaders"
        );
        let cert_start = u32_at(data, directory)?;
        let cert_size = u32_at(data, directory + 4)?;
        if cert_start == 0 || cert_size == 0 {
            return Err(Error::new(
                ErrorKind::Unsigned,
                anyhow::anyhow!("PE has no embedded signature"),
            )
            .into());
        }
        let cert_end = cert_start
            .checked_add(cert_size)
            .ok_or_else(|| anyhow::anyhow!("certificate size overflow"))?;
        ensure!(
            cert_start % 8 == 0 && cert_size % 8 == 0,
            "unaligned certificate table"
        );
        ensure!(
            cert_start >= headers_end && cert_end == data.len(),
            "certificate table must end at EOF and follow headers"
        );
        // Accept ordinary contiguous PE layouts, as relic does. Refuse ambiguous
        // gaps/overlaps rather than claim Windows-equivalent hashing for them.
        let mut sections = Vec::new();
        for i in 0..section_count {
            let at = section_table + i * 40;
            let size = u32_at(data, at + 16)?;
            let start = u32_at(data, at + 20)?;
            if size != 0 {
                sections.push((start, size));
            }
        }
        sections.sort_unstable();
        let mut end = headers_end;
        for (index, (start, size)) in sections.iter().enumerate() {
            ensure!(
                *start >= end && (index == 0 || *start == end),
                "unsupported overlapping or noncontiguous PE sections"
            );
            end = start
                .checked_add(*size)
                .ok_or_else(|| anyhow::anyhow!("section size overflow"))?;
            ensure!(
                end <= cert_start,
                "section overlaps certificate table or EOF"
            );
        }
        #[cfg(feature = "verify")]
        let page_size = {
            let machine = u16_at(data, pe + 4)?;
            if [0x200, 0x184, 0x284].contains(&machine) {
                8192
            } else {
                4096
            }
        };
        Ok(Self {
            data,
            checksum: opt + 64,
            directory,
            cert_start,
            cert_end,
            headers_end,
            sections,
            #[cfg(feature = "verify")]
            page_size,
        })
    }

    pub(crate) fn certificates(&self) -> Result<Vec<&'a [u8]>> {
        let mut result = Vec::new();
        let mut at = self.cert_start;
        while at < self.cert_end {
            ensure!(self.cert_end - at >= 8, "truncated WIN_CERTIFICATE");
            let len = u32_at(self.data, at)?;
            ensure!(
                len >= 8 && len <= self.cert_end - at,
                "invalid WIN_CERTIFICATE length"
            );
            ensure!(
                u16_at(self.data, at + 4)? == 0x200 && u16_at(self.data, at + 6)? == 2,
                "unsupported WIN_CERTIFICATE revision/type"
            );
            let next = len
                .checked_add(7)
                .and_then(|len| at.checked_add(len & !7))
                .ok_or_else(|| anyhow::anyhow!("invalid certificate padding"))?;
            ensure!(
                next <= self.cert_end && self.data[at + len..next].iter().all(|b| *b == 0),
                "invalid certificate padding"
            );
            result.push(&self.data[at + 8..at + len]);
            at = next;
        }
        ensure!(!result.is_empty(), "empty certificate table");
        Ok(result)
    }
}

impl PeTrait for Pe<'_> {
    fn data(&self) -> &[u8] {
        self.data
    }

    fn num_sections(&self) -> usize {
        self.sections.len()
    }

    fn section_data_range(&self, index: usize) -> Result<Range<usize>, PeOffsetError> {
        let (start, len) = self
            .sections
            .get(index.checked_sub(1).ok_or(PeOffsetError)?)
            .ok_or(PeOffsetError)?;
        let end = start.checked_add(*len).ok_or(PeOffsetError)?;
        Ok(*start..end)
    }

    fn certificate_table_range(&self) -> Result<Option<Range<usize>>, PeOffsetError> {
        Ok(Some(self.cert_start..self.cert_end))
    }

    fn offsets(&self) -> Result<PeOffsets, PeOffsetError> {
        Ok(PeOffsets {
            check_sum: self.checksum,
            after_check_sum: self.checksum + 4,
            security_data_dir: self.directory,
            after_security_data_dir: self.directory + 8,
            after_header: self.headers_end,
        })
    }
}
