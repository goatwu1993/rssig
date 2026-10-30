use crate::domain::{ErrorCode, Stage, VerificationError};
use anyhow::{Result, ensure};

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
    pub(crate) page_size: usize,
}

fn u16_at(data: &[u8], at: usize) -> Result<usize> {
    let b = data
        .get(at..at + 2)
        .ok_or_else(|| anyhow::anyhow!("truncated PE header"))?;
    Ok(u16::from_le_bytes(b.try_into()?) as usize)
}
fn u32_at(data: &[u8], at: usize) -> Result<usize> {
    let b = data
        .get(at..at + 4)
        .ok_or_else(|| anyhow::anyhow!("truncated PE header"))?;
    Ok(u32::from_le_bytes(b.try_into()?) as usize)
}

impl<'a> Pe<'a> {
    /// Parse PE headers and signed-image ranges without hashing or cryptography.
    pub fn parse(data: &'a [u8]) -> std::result::Result<Self, VerificationError> {
        Self::parse_inner(data)
            .map_err(|e| VerificationError::from_internal(e, ErrorCode::InvalidPe, Stage::Pe))
    }

    /// Original immutable bytes, including the certificate table.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Extract embedded CMS DER objects, permitting only zero WIN_CERTIFICATE padding.
    /// CMS contents and signatures remain unverified; use `SignedData::parse` to inspect them.
    pub fn signatures(&self) -> std::result::Result<Vec<&'a [u8]>, VerificationError> {
        self.signatures_inner().map_err(|e| {
            VerificationError::from_internal(
                e,
                ErrorCode::InvalidCertificateTable,
                Stage::CertificateTable,
            )
        })
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
            pe >= 64 && data.get(pe..pe + 4) == Some(b"PE\0\0"),
            "invalid PE signature"
        );
        let section_count = u16_at(data, pe + 6)?;
        let opt_len = u16_at(data, pe + 20)?;
        let opt = pe + 24;
        let (dirs, num_dirs) = match u16_at(data, opt)? {
            0x10b => (opt + 96, opt + 92),
            0x20b => (opt + 112, opt + 108),
            _ => anyhow::bail!("unsupported optional header magic"),
        };
        let directory = dirs + 32;
        ensure!(
            directory + 8 <= opt + opt_len && opt + opt_len <= data.len(),
            "truncated optional header"
        );
        ensure!(u32_at(data, num_dirs)? >= 5, "PE has no security directory");
        let headers_end = u32_at(data, opt + 60)?;
        let section_table = opt + opt_len;
        ensure!(
            section_table + section_count * 40 <= headers_end && headers_end <= data.len(),
            "invalid SizeOfHeaders"
        );
        let cert_start = u32_at(data, directory)?;
        let cert_size = u32_at(data, directory + 4)?;
        if cert_start == 0 || cert_size == 0 {
            return Err(VerificationError::new(
                ErrorCode::Unsigned,
                Stage::Pe,
                "PE has no embedded signature",
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
        let machine = u16_at(data, pe + 4)?;
        let page_size = if [0x200, 0x184, 0x284].contains(&machine) {
            8192
        } else {
            4096
        };
        Ok(Self {
            data,
            checksum: opt + 64,
            directory,
            cert_start,
            cert_end,
            headers_end,
            sections,
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
            let next = at + ((len + 7) & !7);
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
