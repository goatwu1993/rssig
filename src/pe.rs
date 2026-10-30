//! Hashing lives on the verification side of the PE parsing boundary.
use crate::crypto::Hash;
pub(crate) use crate::parse::Pe;
use anyhow::{Result, ensure};

impl Pe<'_> {
    pub(crate) fn digest(&self, algorithm: Hash) -> Result<Vec<u8>> {
        let mut content = Vec::with_capacity(self.cert_start);
        content.extend_from_slice(&self.data[..self.checksum]);
        content.extend_from_slice(&self.data[self.checksum + 4..self.directory]);
        content.extend_from_slice(&self.data[self.directory + 8..self.cert_start]);
        Ok(algorithm.digest(&content))
    }

    pub(crate) fn page_hashes(&self, hash: Hash) -> Result<Vec<u8>> {
        ensure!(
            self.headers_end <= self.page_size,
            "PE headers exceed page size"
        );
        let mut header = Vec::new();
        header.extend_from_slice(&self.data[..self.checksum]);
        header.extend_from_slice(&self.data[self.checksum + 4..self.directory]);
        header.extend_from_slice(&self.data[self.directory + 8..self.headers_end]);
        header.resize(self.page_size - 12, 0);
        let mut result = 0u32.to_le_bytes().to_vec();
        result.extend(hash.digest(&header));
        let mut end = 0;
        for &(start, size) in &self.sections {
            for offset in (start..start + size).step_by(self.page_size) {
                let count = (start + size - offset).min(self.page_size);
                let mut page = self.data[offset..offset + count].to_vec();
                page.resize(self.page_size, 0);
                result.extend((offset as u32).to_le_bytes());
                result.extend(hash.digest(&page));
            }
            end = start + size;
        }
        result.extend((end as u32).to_le_bytes());
        result.extend(vec![0; hash.digest(&[]).len()]);
        Ok(result)
    }
}
