//! Bounded ZIP reader for signed packages. Never extracts paths to disk.
use crate::domain::{ErrorCode, Stage, VerificationError};
use anyhow::{Result, ensure};
use flate2::{Decompress, FlushDecompress, Status};
use std::collections::BTreeSet;
const MAX_FILE: usize = 64 * 1024 * 1024;
const MAX_TOTAL: usize = 256 * 1024 * 1024;
pub(super) fn slice(b: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    b.get(
        at..at
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("ZIP offset overflow"))?,
    )
    .ok_or_else(|| anyhow::anyhow!("truncated ZIP field"))
}
fn u16v(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(b, at, 2)?.try_into()?))
}
fn u32v(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(slice(b, at, 4)?.try_into()?))
}
fn u64v(b: &[u8], at: usize) -> Result<usize> {
    Ok(usize::try_from(u64::from_le_bytes(
        slice(b, at, 8)?.try_into()?,
    ))?)
}
fn unsupported<T>(message: &str) -> Result<T> {
    Err(VerificationError::new(ErrorCode::UnsupportedAppx, Stage::Appx, message).into())
}
pub(super) fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.is_ascii()
        && !name.contains(['\\', ':', '%'])
        && !name.chars().any(char::is_control)
        && name.split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && !s.ends_with(['.', ' '])
                && !s.starts_with(' ')
        })
}
fn extra_values(extra: &[u8]) -> Result<Option<&[u8]>> {
    let mut at = 0;
    let mut zip64 = None;
    let mut ids = BTreeSet::new();
    while at < extra.len() {
        let id = u16v(extra, at)?;
        let len = usize::from(u16v(extra, at + 2)?);
        let data = slice(extra, at + 4, len)?;
        ensure!(ids.insert(id), "duplicate ZIP extra field");
        if id == 1 {
            zip64 = Some(data);
        }
        if id == 0x7075 || id == 0x6375 {
            return unsupported("alternate Unicode ZIP name metadata is unsupported");
        }
        at += 4 + len;
    }
    Ok(zip64)
}
#[derive(Debug)]
pub(super) struct Entry<'a> {
    pub name: String,
    pub offset: usize,
    pub lfh_size: usize,
    pub compressed: &'a [u8],
    pub size: usize,
    pub method: u16,
    pub crc: u32,
    central: &'a [u8],
}
impl Entry<'_> {
    pub fn read(&self, limit: usize) -> Result<Vec<u8>> {
        ensure!(
            self.size <= limit,
            "ZIP entry exceeds size limit: {}",
            self.name
        );
        let data = if self.method == 0 {
            ensure!(
                self.compressed.len() == self.size,
                "stored ZIP size mismatch"
            );
            self.compressed.to_vec()
        } else {
            let mut d = Decompress::new(false);
            let mut out = vec![0; self.size + 1];
            let status = d.decompress(self.compressed, &mut out, FlushDecompress::Finish)?;
            ensure!(
                status == Status::StreamEnd
                    && d.total_in() == self.compressed.len() as u64
                    && d.total_out() == self.size as u64,
                "invalid DEFLATE size, stream termination, or trailing compressed data"
            );
            out.truncate(self.size);
            out
        };
        ensure!(
            crc32fast::hash(&data) == self.crc,
            "ZIP CRC mismatch: {}",
            self.name
        );
        Ok(data)
    }
}
pub(super) struct Zip<'a> {
    pub entries: Vec<Entry<'a>>,
    footer: &'a [u8],
    zip64: bool,
}
impl<'a> Zip<'a> {
    pub fn parse(b: &'a [u8]) -> Result<Self> {
        ensure!(
            b.len() <= MAX_TOTAL && b.starts_with(b"PK\x03\x04"),
            "invalid or oversized ZIP package"
        );
        ensure!(b.len() >= 22, "truncated ZIP end record");
        let end = b.len() - 22;
        // Package comments and unsigned appended data are outside the supported profile.
        ensure!(
            slice(b, end, 4)? == b"PK\x05\x06" && u16v(b, end + 20)? == 0,
            "missing ZIP end record, comments, or trailing bytes"
        );
        let z64 = u32v(b, end + 16)? == u32::MAX;
        let (count, cd, size, footer_start) = if z64 {
            ensure!(end >= 76, "truncated ZIP64 footer");
            let loc = end - 20;
            ensure!(
                slice(b, loc, 4)? == b"PK\x06\x07"
                    && u32v(b, loc + 4)? == 0
                    && u32v(b, loc + 16)? == 1,
                "invalid or multidisk ZIP64 locator"
            );
            let off = u64v(b, loc + 8)?;
            ensure!(
                off.checked_add(56) == Some(loc),
                "unsupported ZIP64 footer layout"
            );
            ensure!(
                slice(b, off, 4)? == b"PK\x06\x06" && u64v(b, off + 4)? == 44,
                "invalid ZIP64 record"
            );
            ensure!(
                u32v(b, off + 16)? == 0 && u32v(b, off + 20)? == 0,
                "multidisk ZIP64 package"
            );
            ensure!(
                u64v(b, off + 24)? == u64v(b, off + 32)?,
                "inconsistent ZIP64 entry counts"
            );
            ensure!(
                [0, 65535].contains(&u16v(b, end + 4)?)
                    && [0, 65535].contains(&u16v(b, end + 6)?)
                    && u16v(b, end + 8)? == 65535
                    && u16v(b, end + 10)? == 65535
                    && u32v(b, end + 12)? == u32::MAX,
                "inconsistent ZIP64 sentinel fields"
            );
            (
                u64v(b, off + 32)?,
                u64v(b, off + 48)?,
                u64v(b, off + 40)?,
                off,
            )
        } else {
            if u16v(b, end + 4)? != 0 || u16v(b, end + 6)? != 0 {
                return unsupported("multidisk ZIP packages are unsupported");
            }
            ensure!(
                u16v(b, end + 8)? == u16v(b, end + 10)?,
                "inconsistent ZIP entry counts"
            );
            (
                usize::from(u16v(b, end + 10)?),
                u32v(b, end + 16)? as usize,
                u32v(b, end + 12)? as usize,
                end,
            )
        };
        ensure!(count > 0 && count <= 4096, "ZIP entry count limit");
        ensure!(
            cd.checked_add(size) == Some(footer_start),
            "ZIP central-directory bounds mismatch"
        );
        let mut entries = Vec::with_capacity(count);
        let mut names = BTreeSet::new();
        let mut at = cd;
        let mut total = 0usize;
        for _ in 0..count {
            let h = slice(b, at, 46)?;
            ensure!(&h[..4] == b"PK\x01\x02", "invalid ZIP directory entry");
            let flags = u16v(h, 8)?;
            let method = u16v(h, 10)?;
            if flags & !0x80e != 0 || ![0, 8].contains(&method) || u16v(h, 6)? > 45 {
                return unsupported("unsupported ZIP flags, method, or version");
            }
            let n = usize::from(u16v(h, 28)?);
            let x = usize::from(u16v(h, 30)?);
            let c = usize::from(u16v(h, 32)?);
            ensure!(c == 0, "ZIP entry comments are unsupported");
            let central = slice(b, at, 46 + n + x + c)?;
            let name = std::str::from_utf8(slice(central, 46, n)?)?.to_owned();
            ensure!(
                safe_name(&name) && names.insert(name.to_ascii_lowercase()),
                "unsafe or duplicate ZIP path"
            );
            let extra = extra_values(slice(central, 46 + n, x)?)?;
            let mut zi = 0;
            let mut resolve = |value: u32| -> Result<usize> {
                if value == u32::MAX {
                    let v = u64v(
                        extra.ok_or_else(|| anyhow::anyhow!("missing ZIP64 extra"))?,
                        zi,
                    )?;
                    zi += 8;
                    Ok(v)
                } else {
                    Ok(value as usize)
                }
            };
            let usize = resolve(u32v(h, 24)?)?;
            let compressed = resolve(u32v(h, 20)?)?;
            let offset = resolve(u32v(h, 42)?)?;
            ensure!(u16v(h, 34)? == 0, "ZIP entry belongs to another disk");
            if (u32v(h, 38)? >> 16) & 0xf000 == 0xa000 {
                return unsupported("symbolic-link ZIP entries are unsupported");
            }
            ensure!(usize <= MAX_FILE, "ZIP entry uncompressed size limit");
            total = total
                .checked_add(usize)
                .ok_or_else(|| anyhow::anyhow!("ZIP size overflow"))?;
            ensure!(total <= MAX_TOTAL, "ZIP total uncompressed size limit");
            ensure!(offset < cd, "ZIP local offset outside file records");
            let local = slice(b, offset, 30)?;
            ensure!(&local[..4] == b"PK\x03\x04", "invalid ZIP local header");
            ensure!(
                u16v(local, 6)? == flags && u16v(local, 8)? == method && u16v(local, 4)? <= 45,
                "ZIP local/directory flag, method, or version mismatch"
            );
            let ln = usize::from(u16v(local, 26)?);
            let lx = usize::from(u16v(local, 28)?);
            let lfh_size = 30 + ln + lx;
            ensure!(
                slice(b, offset + 30, ln)? == name.as_bytes(),
                "ZIP local/directory filename mismatch"
            );
            extra_values(slice(b, offset + 30 + ln, lx)?)?;
            let payload = slice(b, offset + lfh_size, compressed)?;
            let crc = u32v(h, 16)?;
            if flags & 8 == 0 {
                ensure!(
                    u32v(local, 14)? == crc
                        && u32v(local, 18)? as usize == compressed
                        && u32v(local, 22)? as usize == usize,
                    "ZIP local/directory size or CRC mismatch"
                );
            } else {
                ensure!(
                    [0, crc].contains(&u32v(local, 14)?)
                        && [0, compressed as u32].contains(&u32v(local, 18)?)
                        && [0, usize as u32].contains(&u32v(local, 22)?),
                    "invalid streaming ZIP local sizes"
                );
            }
            entries.push(Entry {
                name,
                offset,
                lfh_size,
                compressed: payload,
                size: usize,
                method,
                crc,
                central,
            });
            at += central.len();
        }
        ensure!(at == footer_start, "unparsed ZIP directory data");
        let mut next = 0;
        for (i, e) in entries.iter().enumerate() {
            ensure!(
                e.offset == next,
                "overlapping, reordered, or noncontiguous ZIP records"
            );
            let data_end = e.offset + e.lfh_size + e.compressed.len();
            let end = entries.get(i + 1).map_or(cd, |v| v.offset);
            ensure!(end >= data_end, "overlapping ZIP data");
            let descriptor = slice(b, data_end, end - data_end)?;
            let flags = u16v(e.central, 8)?;
            if flags & 8 == 0 {
                ensure!(descriptor.is_empty(), "unaccounted ZIP file-record bytes");
            } else {
                let start = if [16, 24].contains(&descriptor.len()) {
                    ensure!(
                        slice(descriptor, 0, 4)? == b"PK\x07\x08",
                        "invalid ZIP data descriptor signature"
                    );
                    4
                } else {
                    0
                };
                ensure!(
                    [12, 16, 20, 24].contains(&descriptor.len())
                        && u32v(descriptor, start)? == e.crc,
                    "invalid ZIP data descriptor"
                );
                if descriptor.len() - start == 12 {
                    ensure!(
                        u32v(descriptor, start + 4)? as usize == e.compressed.len()
                            && u32v(descriptor, start + 8)? as usize == e.size,
                        "ZIP descriptor size mismatch"
                    );
                } else {
                    ensure!(
                        u64v(descriptor, start + 4)? == e.compressed.len()
                            && u64v(descriptor, start + 12)? == e.size,
                        "ZIP64 descriptor size mismatch"
                    );
                }
            }
            next = end;
        }
        Ok(Self {
            entries,
            footer: &b[footer_start..],
            zip64: z64,
        })
    }
    pub fn get(&self, name: &str) -> Option<&Entry<'a>> {
        self.entries.iter().find(|e| e.name == name)
    }
    pub fn unsigned_directory(&self) -> Result<Vec<u8>> {
        let sig = self
            .entries
            .last()
            .ok_or_else(|| anyhow::anyhow!("empty ZIP package"))?;
        ensure!(
            sig.name == "AppxSignature.p7x",
            "APPX signature must be the final file record"
        );
        let mut out = Vec::new();
        for e in &self.entries[..self.entries.len() - 1] {
            out.extend(e.central);
        }
        let size = out.len();
        let mut footer = self.footer.to_vec();
        let n = self.entries.len() - 1;
        if self.zip64 {
            footer[24..32].copy_from_slice(&(n as u64).to_le_bytes());
            footer[32..40].copy_from_slice(&(n as u64).to_le_bytes());
            footer[40..48].copy_from_slice(&(size as u64).to_le_bytes());
            footer[48..56].copy_from_slice(&(sig.offset as u64).to_le_bytes());
            footer[64..72].copy_from_slice(&((sig.offset + size) as u64).to_le_bytes());
            footer[80..84].fill(0);
        } else {
            footer[8..10].copy_from_slice(&(n as u16).to_le_bytes());
            footer[10..12].copy_from_slice(&(n as u16).to_le_bytes());
            footer[12..16].copy_from_slice(&(size as u32).to_le_bytes());
            footer[16..20].copy_from_slice(&(sig.offset as u32).to_le_bytes());
        }
        out.extend(footer);
        Ok(out)
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
    fn all_truncated_prefixes_and_offset_overflows_are_rejected() {
        for name in [
            "good.msix",
            "good-appx-zip64.msix",
            "appx-independent-signtool.msix",
        ] {
            let b = fixture(name);
            for end in 0..b.len() {
                assert!(
                    Zip::parse(&b[..end]).is_err(),
                    "accepted {name} prefix {end}"
                );
            }
        }
        let good = fixture("good.msix");
        let footer = good.len() - 22;
        for field in [footer + 8, footer + 10, footer + 12, footer + 16] {
            let mut b = good.clone();
            b[field..field + 2].fill(255);
            assert!(Zip::parse(&b).is_err());
        }
        let cd = u32v(&good, footer + 16).unwrap() as usize;
        for field in [cd + 20, cd + 24, cd + 42] {
            let mut b = good.clone();
            b[field..field + 4].fill(255);
            assert!(Zip::parse(&b).is_err());
        }
        for name in [
            "../x", "/x", "a//b", "a\\b", "a:b", "a%20b", "a/./b", "a/../b", "x.", "x ", "a\0b",
        ] {
            assert!(!safe_name(name), "accepted {name:?}");
        }
    }
    #[test]
    fn strict_inflation_checks_crc_size_truncation_and_trailing_bytes() {
        let bytes = fixture("good-appx-deflate.msix");
        let zip = Zip::parse(&bytes).unwrap();
        let original = zip.get("data.bin").unwrap();
        assert_eq!(original.read(65536).unwrap(), b"test");
        let mut trailing = original.compressed.to_vec();
        trailing.push(0);
        for (data, size, crc) in [
            (&trailing[..], original.size, original.crc),
            (
                &original.compressed[..original.compressed.len() - 1],
                original.size,
                original.crc,
            ),
            (original.compressed, original.size + 1, original.crc),
            (original.compressed, original.size, original.crc ^ 1),
        ] {
            let entry = Entry {
                name: original.name.clone(),
                offset: original.offset,
                lfh_size: original.lfh_size,
                compressed: data,
                size,
                method: 8,
                crc,
                central: original.central,
            };
            assert!(entry.read(65536).is_err());
        }
        assert!(original.read(1).is_err());
        assert!(extra_values(&[1, 0, 255, 255]).is_err());
        assert!(extra_values(&[1, 0, 0, 0, 1, 0, 0, 0]).is_err());
    }
}
