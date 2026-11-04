//! Hashing lives on the verification side of the PE parsing boundary.
use crate::crypto::Hash;
pub(crate) use crate::parse::Pe;
use anyhow::{Result, ensure};

// Adapt the verifier's runtime-selected RustCrypto hasher to the public sink.
struct DigestSink<'a>(&'a mut dyn digest::DynDigest);
impl digest::Update for DigestSink<'_> {
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

impl Pe<'_> {
    pub(crate) fn digest(&self, algorithm: Hash) -> Result<Vec<u8>> {
        let mut digest = algorithm.hasher();
        crate::parse::authenticode_digest(self, &mut DigestSink(digest.as_mut()))?;
        Ok(digest.finalize().to_vec())
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
