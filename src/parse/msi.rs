//! MSI/MSP Authenticode hashing. Ordering and metadata layout follow the read-only
//! jsign MSIFile/MSIStreamName and relic authenticode/msiverify references.
use super::{Error, ErrorKind};
use anyhow::{Context, Result, ensure};
use digest::Update;
use std::{
    io::{Cursor, Read},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const MAGIC: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const SIGNATURE: &str = "\u{5}DigitalSignature";
const EXTENDED: &str = "\u{5}MsiDigitalSignatureEx";
const MAX_DEPTH: usize = 64;
const MAX_ENTRIES: usize = 100_000;

/// Untrusted MSI/MSP structure backed by the optional `msi` (`std`/CFB) adapter.
///
/// Borrows the immutable container; extracted signature streams are owned.
/// Hash input can be streamed repeatedly. No digest comparison or trust is performed.
pub struct Msi<'a> {
    file: cfb::CompoundFile<Cursor<&'a [u8]>>,
    data: &'a [u8],
    extended: Option<Vec<u8>>,
    signature: Vec<u8>,
}
fn name_bytes(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn decoded(name: &str) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
    let mut result = String::new();
    for c in name.chars() {
        let x = c as u32;
        if (0x3800..0x4800).contains(&x) {
            let n = x - 0x3800;
            result.push(ALPHABET[(n & 63) as usize] as char);
            result.push(ALPHABET[(n >> 6) as usize] as char);
        } else if (0x4800..0x4840).contains(&x) {
            result.push(ALPHABET[(x - 0x4800) as usize] as char);
        } else {
            result.push(c);
        }
    }
    result
}
fn ticks(time: SystemTime) -> Result<[u8; 8]> {
    const EPOCH: u64 = 116444736000000000;
    let value = match time.duration_since(UNIX_EPOCH) {
        Ok(d) => EPOCH.checked_add(u64::try_from(d.as_nanos() / 100)?),
        Err(e) => EPOCH.checked_sub(u64::try_from(e.duration().as_nanos() / 100)?),
    }
    .context("MSI metadata timestamp overflow")?;
    Ok(value.to_le_bytes())
}
impl<'a> Msi<'a> {
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::parse_inner(bytes)
            .map_err(|e| Error::new(ErrorKind::InvalidMsi, e.context("MSI container")))
    }
    fn parse_inner(bytes: &'a [u8]) -> Result<Self> {
        ensure!(bytes.starts_with(MAGIC), "invalid MSI magic");
        let file = cfb::CompoundFile::open_strict(Cursor::new(bytes))?;
        let sector_size = match file.version() {
            cfb::Version::V3 => 512,
            cfb::Version::V4 => 4096,
        };
        ensure!(
            bytes.len().is_multiple_of(sector_size),
            "MSI container length is not sector aligned"
        );
        let mut result = Self {
            file,
            data: bytes,
            extended: None,
            signature: vec![],
        };
        let mut count = 0;
        let mut total = 0u64;
        result.validate(Path::new("/"), 0, &mut count, &mut total)?;
        let entry = result.file.entry(format!("/{SIGNATURE}"));
        if entry.is_err() {
            return Err(Error::new(
                ErrorKind::UnsignedMsi,
                anyhow::anyhow!("no embedded MSI signature"),
            )
            .into());
        }
        result.signature = result.stream(Path::new(&format!("/{SIGNATURE}")))?;
        if result.file.exists(format!("/{EXTENDED}")) {
            // Validate presence separately from length: an empty Ex stream is
            // malformed evidence, never permission to downgrade to legacy hashing.
            let entry = result.file.entry(format!("/{EXTENDED}"))?;
            ensure!(
                entry.len() <= 64,
                "MSI extended digest stream exceeds supported digest size"
            );
            result.extended = Some(result.stream(entry.path())?);
        }
        Ok(result)
    }
    fn validate(
        &self,
        path: &Path,
        depth: usize,
        count: &mut usize,
        total: &mut u64,
    ) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "MSI storage nesting limit exceeded");
        for entry in self.file.read_storage(path)? {
            *count += 1;
            ensure!(*count <= MAX_ENTRIES, "MSI entry limit exceeded");
            let name = decoded(entry.name());
            if name.eq_ignore_ascii_case(SIGNATURE) || name.eq_ignore_ascii_case(EXTENDED) {
                ensure!(
                    depth == 0
                        && entry.is_stream()
                        && entry.name() == name
                        && (name == SIGNATURE || name == EXTENDED),
                    "ambiguous or misplaced MSI signature stream"
                );
            }
            if entry.is_storage() {
                self.validate(entry.path(), depth + 1, count, total)?;
            } else {
                ensure!(
                    entry.len() <= self.data.len() as u64,
                    "MSI stream length exceeds container size"
                );
                *total = total
                    .checked_add(entry.len())
                    .context("MSI stream size overflow")?;
                ensure!(
                    *total <= self.data.len() as u64,
                    "MSI total stream size exceeds container size"
                );
            }
        }
        Ok(())
    }
    fn stream(&mut self, path: &Path) -> Result<Vec<u8>> {
        let length = self.file.entry(path)?.len();
        ensure!(
            length <= self.data.len() as u64,
            "MSI stream exceeds container size"
        );
        let mut data = Vec::new();
        self.file
            .open_stream(path)?
            .take(length + 1)
            .read_to_end(&mut data)?;
        ensure!(data.len() as u64 == length, "truncated MSI stream");
        Ok(data)
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
    /// The original immutable CFB container.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Stored extended metadata digest. `Some(&[])` preserves malformed empty evidence.
    pub fn extended_digest(&self) -> Option<&[u8]> {
        self.extended.as_deref()
    }

    /// Stream canonical extended metadata, excluding both signature streams.
    pub fn update_metadata(&mut self, digest: &mut impl Update) -> core::result::Result<(), Error> {
        self.update(true, digest)
    }

    /// Stream canonical content and storage CLSIDs, excluding both signature streams.
    /// For extended signing, the caller must first feed the computed metadata digest.
    pub fn update_content(&mut self, digest: &mut impl Update) -> core::result::Result<(), Error> {
        self.update(false, digest)
    }

    fn update(
        &mut self,
        metadata: bool,
        digest: &mut impl Update,
    ) -> core::result::Result<(), Error> {
        self.feed(self.file.root_entry(), metadata, digest)
            .map_err(|e| Error::new(ErrorKind::InvalidMsi, e.context("MSI stream hashing")))
    }
    fn feed(&mut self, entry: cfb::Entry, metadata: bool, digest: &mut impl Update) -> Result<()> {
        if metadata {
            if !entry.is_root() {
                digest.update(&name_bytes(entry.name()));
            }
            if entry.is_storage() {
                digest.update(&entry.clsid().to_bytes_le());
            }
            if entry.is_stream() {
                digest.update(
                    &u32::try_from(entry.len())
                        .context("MSI streams larger than 4 GiB are unsupported")?
                        .to_le_bytes(),
                );
            }
            digest.update(&entry.state_bits().to_le_bytes());
            if !entry.is_root() {
                digest.update(&ticks(entry.created())?);
                digest.update(&ticks(entry.modified())?);
            }
        }
        if entry.is_storage() {
            let mut children: Vec<_> = self.file.read_storage(entry.path())?.collect();
            children.sort_by_cached_key(|e| name_bytes(e.name()));
            for child in children {
                if child.name() == SIGNATURE || child.name() == EXTENDED {
                    continue;
                }
                self.feed(child, metadata, digest)?;
            }
            if !metadata {
                digest.update(&entry.clsid().to_bytes_le());
            }
        } else if !metadata {
            let mut stream = self.file.open_stream(entry.path())?;
            let mut remaining = entry.len();
            let mut buffer = [0; 16384];
            while remaining > 0 {
                let n = usize::try_from(remaining.min(buffer.len() as u64))?;
                stream.read_exact(&mut buffer[..n])?;
                digest.update(&buffer[..n]);
                remaining -= n as u64;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entry_budget_is_enforced_before_walking_streams() {
        let bytes = include_bytes!("../../tests/fixtures/msi-good-pe64.msi");
        let msi = Msi::parse(bytes).unwrap();
        let mut count = MAX_ENTRIES;
        let mut total = 0;
        assert!(
            msi.validate(Path::new("/"), 0, &mut count, &mut total)
                .unwrap_err()
                .to_string()
                .contains("MSI entry limit")
        );
    }
    #[test]
    fn metadata_filetime_preserves_zero_and_subsecond_ticks() {
        assert_eq!(
            ticks(UNIX_EPOCH).unwrap(),
            116444736000000000u64.to_le_bytes()
        );
        let zero = UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(11644473600))
            .unwrap();
        assert_eq!(ticks(zero).unwrap(), [0; 8]);
        assert_eq!(
            ticks(UNIX_EPOCH + std::time::Duration::from_nanos(100)).unwrap(),
            116444736000000001u64.to_le_bytes()
        );
    }
}
