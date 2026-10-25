//! Small, bounded DER reader for the legacy PKCS#7 Authenticode envelope.
use anyhow::{Result, bail, ensure};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Node<'a> {
    pub tag: u8,
    pub full: &'a [u8],
    pub body: &'a [u8],
}

pub(crate) fn take<'a>(input: &mut &'a [u8]) -> Result<Node<'a>> {
    let original = *input;
    ensure!(original.len() >= 2, "truncated DER header");
    let tag = original[0];
    ensure!(tag & 31 != 31, "high-tag-number DER is unsupported");
    let mut header = 2usize;
    let mut len = original[1] as usize;
    if len & 128 != 0 {
        let count = len & 127;
        ensure!(count > 0 && count <= 4, "invalid DER length");
        ensure!(
            original.len() >= 2 + count && original[2] != 0,
            "invalid DER length"
        );
        len = 0;
        for b in &original[2..2 + count] {
            len = (len << 8) | *b as usize;
        }
        ensure!(len >= 128, "noncanonical DER length");
        header += count;
    }
    let end = header
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("DER length overflow"))?;
    ensure!(end <= original.len(), "truncated DER value");
    *input = &original[end..];
    Ok(Node {
        tag,
        full: &original[..end],
        body: &original[header..end],
    })
}

pub(crate) fn one(input: &[u8], tag: u8) -> Result<Node<'_>> {
    let mut remaining = input;
    let node = take(&mut remaining)?;
    ensure!(remaining.is_empty(), "trailing DER data");
    node.expect(tag)
}

impl<'a> Node<'a> {
    pub fn expect(self, tag: u8) -> Result<Self> {
        ensure!(
            self.tag == tag,
            "expected DER tag {tag:#x}, got {:#x}",
            self.tag
        );
        Ok(self)
    }
    pub fn children(self) -> Result<Vec<Node<'a>>> {
        let mut bytes = self.body;
        let mut result = Vec::new();
        while !bytes.is_empty() {
            ensure!(result.len() < 16384, "too many DER elements");
            result.push(take(&mut bytes)?);
        }
        Ok(result)
    }
}

pub(crate) fn oid(node: Node<'_>, expected: &[u8]) -> bool {
    node.tag == 6 && node.body == expected
}

pub(crate) fn fields(node: Node<'_>, count: usize) -> Result<Vec<Node<'_>>> {
    let fields = node.children()?;
    if fields.len() != count {
        bail!("expected {count} DER fields, got {}", fields.len());
    }
    Ok(fields)
}
