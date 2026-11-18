//! Small, bounded DER reader for the legacy PKCS#7 Authenticode envelope.
use alloc::vec::Vec;
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
    ensure!(tag != 0, "end-of-contents is forbidden in DER");
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

/// The issuer Name of a certificate or CRL, as encoded in `der`, without
/// decoding the rest. `version_tag` is the optional leading version field's
/// tag (`0xa0` in a certificate, `0x02` in a CRL) and `index` the issuer's
/// position after it (2 in a certificate, 1 in a CRL).
#[cfg(feature = "crl-fetch")]
pub(crate) fn tbs_issuer(der: &[u8], version_tag: u8, index: usize) -> Option<&[u8]> {
    let fields = one(der, 0x30).ok()?.children().ok()?;
    let tbs = fields.first()?.expect(0x30).ok()?.children().ok()?;
    let at = index + usize::from(tbs.first().is_some_and(|f| f.tag == version_tag));
    Some(tbs.get(at)?.expect(0x30).ok()?.full)
}

#[cfg(all(test, feature = "crl-fetch"))]
mod tests {
    use super::tbs_issuer;
    use ::der::{Decode, Encode};
    use alloc::vec::Vec;

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        assert!(body.len() < 128);
        let mut out = alloc::vec![tag, body.len() as u8];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn reads_the_issuer_with_and_without_a_version() {
        let name = tlv(0x30, &tlv(0x31, &tlv(0x30, b"\x06\x03\x55\x04\x03")));
        let alg = tlv(0x30, &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2]));
        let wrap = |tbs: Vec<u8>| {
            tlv(
                0x30,
                &[tlv(0x30, &tbs), alg.clone(), tlv(0x03, &[0])].concat(),
            )
        };
        // A v1 CRL: signature, issuer.
        let v1 = wrap([alg.clone(), name.clone()].concat());
        assert_eq!(tbs_issuer(&v1, 0x02, 1), Some(name.as_slice()));
        // A v2 CRL: version INTEGER, signature, issuer.
        let v2 = wrap([tlv(0x02, &[1]), alg.clone(), name.clone()].concat());
        assert_eq!(tbs_issuer(&v2, 0x02, 1), Some(name.as_slice()));
        // A certificate: [0] version, serial, signature, issuer.
        let cert = wrap(
            [
                tlv(0xa0, &tlv(0x02, &[2])),
                tlv(0x02, &[7]),
                alg.clone(),
                name.clone(),
            ]
            .concat(),
        );
        assert_eq!(tbs_issuer(&cert, 0xa0, 2), Some(name.as_slice()));
        // Too few fields, a non-SEQUENCE issuer, truncation and trailing data.
        assert_eq!(tbs_issuer(&wrap(alg.clone()), 0x02, 1), None);
        assert_eq!(
            tbs_issuer(&wrap([alg.clone(), tlv(0x02, &[1])].concat()), 0x02, 1),
            None
        );
        assert_eq!(tbs_issuer(&v2[..v2.len() - 1], 0x02, 1), None);
        assert_eq!(tbs_issuer(&[v2.as_slice(), &[0]].concat(), 0x02, 1), None);
        assert_eq!(tbs_issuer(&[], 0x02, 1), None);
    }

    #[test]
    fn matches_the_decoded_issuer_of_committed_fixtures() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
        let crl = std::fs::read(alloc::format!("{dir}good.crl")).unwrap();
        let decoded = x509_cert::crl::CertificateList::from_der(&crl).unwrap();
        assert_eq!(
            tbs_issuer(&crl, 0x02, 1).unwrap(),
            decoded.tbs_cert_list.issuer.to_der().unwrap()
        );
        let cert = std::fs::read(alloc::format!("{dir}sec06-issuer.der")).unwrap();
        let decoded = x509_cert::Certificate::from_der(&cert).unwrap();
        assert_eq!(
            tbs_issuer(&cert, 0xa0, 2).unwrap(),
            decoded.tbs_certificate.issuer.to_der().unwrap()
        );
    }
}
