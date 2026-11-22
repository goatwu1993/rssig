//! RFC 5280 section 7.1 comparison of distinguished names, used to match a
//! CRL's issuer to a certificate's issuer.
//!
//! Two names match when they have the same RDNs in the same order, an RDN's
//! attributes match as a set, and two attributes match when their types are
//! equal and their values are equal after the RFC 4518 string preparation the
//! RFC requires for PrintableString and UTF8String values. rssig applies the
//! parts of it that decide equality in practice: lower-casing (each
//! character's Unicode lowercase mapping, not the full RFC 3454 case folding,
//! so `ß` and `ss` differ) and insignificant space handling. It applies no
//! Unicode normalization, map-to-nothing or prohibited-character step, so it
//! matches fewer names than the RFC; a
//! name it does not match is an unknown CRL issuer, never a trusted one, and
//! the CRL is authenticated by its signature either way. The string types
//! that OpenSSL and Bouncy Castle both read as text, and this stack can
//! decode, compare as text: PrintableString and UTF8String, BMPString
//! (UTF-16BE), TeletexString (as Latin-1) and VisibleString, with IA5String
//! (domainComponent, emailAddress), which RFC 5280 section 7.3 and PKCS #9
//! match case-insensitively. Any other string type, a malformed value, and a
//! PrintableString outside its character set compare by exact bytes.
use ::der::{Decode, Encode, Tag, Tagged};
use alloc::{string::String, vec::Vec};
use x509_cert::{
    attr::AttributeTypeAndValue,
    name::{Name, RelativeDistinguishedName},
};

/// A DER-encoded name and, when it decodes, its prepared form: each RDN in
/// order as the sorted keys of its attributes. Two names match when their
/// bytes are equal or their prepared forms are; a name that does not decode
/// matches only its own bytes. A value prepares its name only when it is
/// first compared with different bytes, and keeps the result, so its later
/// comparisons are equality checks. Separate values of one name prepare it
/// separately: a CRL's issuer when the prefilter reads it and again when the
/// CRL is loaded, and a certificate's issuer on each candidate path (CRL-T033).
#[derive(Clone, Debug)]
pub(crate) struct ComparableName {
    der: Vec<u8>,
    prepared: core::cell::OnceCell<Option<Vec<Vec<Key>>>>,
}

/// An attribute's type and its prepared value or exact encoding.
type Key = (Vec<u8>, Vec<u8>);

impl ComparableName {
    pub(crate) fn new(der: Vec<u8>) -> Self {
        Self {
            der,
            prepared: core::cell::OnceCell::new(),
        }
    }

    fn prepared(&self) -> Option<&Vec<Vec<Key>>> {
        self.prepared
            .get_or_init(|| {
                Name::from_der(&self.der).ok().and_then(|name| {
                    name.0
                        .iter()
                        .map(|rdn| {
                            let mut keys = keys(rdn)?;
                            keys.sort_unstable();
                            Some(keys)
                        })
                        .collect()
                })
            })
            .as_ref()
    }

    /// The name as DER, exactly as given.
    pub(crate) fn der(&self) -> &[u8] {
        &self.der
    }

    /// Whether the two are the same name under RFC 5280 section 7.1: an RDN's
    /// attributes compare as a multiset (sorted keys), RDNs in order.
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.der == other.der
            || self
                .prepared()
                .is_some_and(|prepared| Some(prepared) == other.prepared())
    }
}

fn keys(rdn: &RelativeDistinguishedName) -> Option<Vec<Key>> {
    rdn.0.iter().map(key).collect()
}

/// An attribute's type and value in a form that is equal exactly when the
/// attributes match: a prepared value is marked 0, an exact encoding 1, so the
/// two cannot collide.
fn key(attribute: &AttributeTypeAndValue) -> Option<Key> {
    let value = match prepared(&attribute.value) {
        Some(text) => [&[0][..], text.as_bytes()].concat(),
        None => [&[1][..], &attribute.value.to_der().ok()?].concat(),
    };
    Some((attribute.oid.as_bytes().to_vec(), value))
}

/// The text of a DirectoryString or IA5String value after lower-casing and
/// insignificant space handling; `None` for any other type or bytes that are
/// not valid text, which compare by exact bytes.
fn prepared(value: &::der::Any) -> Option<String> {
    let text: String = match value.tag() {
        Tag::Utf8String => core::str::from_utf8(value.value()).ok()?.into(),
        // A PrintableString outside its character set is malformed.
        Tag::PrintableString if value.value().iter().all(|b| printable(*b)) => {
            core::str::from_utf8(value.value()).ok()?.into()
        }
        Tag::Ia5String if value.value().is_ascii() => {
            core::str::from_utf8(value.value()).ok()?.into()
        }
        // A VisibleString is printable ASCII (X.680 section 41.4); both
        // references read it as text.
        Tag::VisibleString if value.value().iter().all(|b| (0x20..0x7f).contains(b)) => {
            core::str::from_utf8(value.value()).ok()?.into()
        }
        // RFC 4518 section 2.1: a BMPString is Unicode, UCS-2 in UTF-16BE
        // units. An odd length or a surrogate unit, which is no character of
        // UCS-2, is malformed.
        Tag::BmpString => {
            let bytes = value.value();
            if !bytes.len().is_multiple_of(2) {
                return None;
            }
            let (units, _) = bytes.as_chunks::<2>();
            units
                .iter()
                .map(|unit| char::from_u32(u32::from(u16::from_be_bytes(*unit))))
                .collect::<Option<String>>()?
        }
        // RFC 4518 section 2.1 leaves the TeletexString mapping "a local
        // matter"; OpenSSL and Bouncy Castle read each byte as Latin-1.
        Tag::TeletexString => value.value().iter().map(|b| char::from(*b)).collect(),
        _ => return None,
    };
    // RFC 4518 section 2.2 maps U+0009 to U+000D, U+0085 and every other
    // Separator (Zs, Zl, Zp) code point to a space, which is exactly what
    // `char::is_whitespace` accepts. Its map-to-nothing characters are not
    // dropped, so such a value matches fewer names than the RFC (CRL-041).
    let mut out = String::new();
    let mut gap = false;
    for c in text.chars() {
        if c.is_whitespace() {
            gap = true;
            continue;
        }
        if gap && !out.is_empty() {
            out.push(' ');
        }
        gap = false;
        out.extend(c.to_lowercase());
    }
    // RFC 4518 section 2.6.1 pads a value with one space at each end, doubles
    // inner runs of spaces, and makes a value of only spaces two spaces.
    // Trimming, single inner spaces and one space for an empty value give the
    // same equalities.
    if out.is_empty() {
        out.push(' ');
    }
    Some(out)
}

/// The PrintableString character set (X.680 section 41.4).
fn printable(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::ComparableName;
    use alloc::{string::String, vec, vec::Vec};

    #[test]
    fn a_prepared_name_compares_alike_every_time() {
        let root = ComparableName::new(name(&[&[(CN, UTF8, "rssig test root")]]));
        let printable = ComparableName::new(name(&[&[(CN, PRINTABLE, "RSSIG Test Root")]]));
        let other = ComparableName::new(name(&[&[(CN, UTF8, "another root")]]));
        let garbage = ComparableName::new(vec![0x30, 0x00, 0x00]);
        // Equal bytes need no preparation.
        assert!(root.matches(&root.clone()));
        assert!(root.prepared.get().is_none());
        // A first comparison with different bytes prepares both, once.
        assert!(root.matches(&printable));
        assert!(root.prepared.get().is_some_and(Option::is_some));
        assert!(printable.prepared.get().is_some_and(Option::is_some));
        // A name that does not decode keeps that result.
        assert!(!garbage.matches(&root));
        assert_eq!(garbage.prepared.get(), Some(&None));
        // The same value, compared repeatedly and in either order, after a
        // mismatch and after a name that does not decode.
        for _ in 0..2 {
            assert!(root.matches(&printable));
            assert!(printable.matches(&root));
            assert!(!root.matches(&other));
            assert!(!root.matches(&garbage));
            assert!(!garbage.matches(&root));
            assert!(garbage.matches(&garbage.clone()));
        }
        // A clone keeps the prepared form and still compares alike.
        let copy = root.clone();
        assert!(copy.matches(&printable));
        assert!(!copy.matches(&other));
        // Two names that do not decode never match unless their bytes do.
        assert!(!garbage.matches(&ComparableName::new(vec![0x30, 0x00, 0x01])));
    }

    fn names_match(a: &[u8], b: &[u8]) -> bool {
        ComparableName::new(a.to_vec()).matches(&ComparableName::new(b.to_vec()))
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        assert!(body.len() < 128);
        [&[tag, body.len() as u8][..], body].concat()
    }

    /// A name of one RDN per `(type, string tag, value)` group.
    fn name(rdns: &[&[(&[u8], u8, &str)]]) -> Vec<u8> {
        let rdns: Vec<Vec<u8>> = rdns
            .iter()
            .map(|attributes| {
                let attributes: Vec<u8> = attributes
                    .iter()
                    .flat_map(|(oid, tag, value)| {
                        tlv(0x30, &[tlv(6, oid), tlv(*tag, value.as_bytes())].concat())
                    })
                    .collect();
                tlv(0x31, &attributes)
            })
            .collect();
        tlv(0x30, &rdns.concat())
    }

    /// A name of one attribute whose value is the given bytes.
    fn name_bytes(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
        tlv(
            0x30,
            &tlv(0x31, &tlv(0x30, &[tlv(6, oid), tlv(tag, value)].concat())),
        )
    }

    /// One RDN of many attributes, with long-form lengths.
    fn big_name(attributes: &[(&[u8], u8, &str)]) -> Vec<u8> {
        fn long(tag: u8, body: &[u8]) -> Vec<u8> {
            let len = body.len();
            let mut out = vec![tag, 0x82, (len >> 8) as u8, len as u8];
            out.extend_from_slice(body);
            out
        }
        let body: Vec<u8> = attributes
            .iter()
            .flat_map(|(oid, tag, value)| {
                tlv(0x30, &[tlv(6, oid), tlv(*tag, value.as_bytes())].concat())
            })
            .collect();
        long(0x30, &long(0x31, &body))
    }

    const CN: &[u8] = &[0x55, 4, 3];
    const O: &[u8] = &[0x55, 4, 10];
    const UTF8: u8 = 0x0c;
    const PRINTABLE: u8 = 0x13;
    const TELETEX: u8 = 0x14;
    const VIDEOTEX: u8 = 0x15;
    const BMP: u8 = 0x1e;
    const VISIBLE: u8 = 0x1a;
    const NUMERIC: u8 = 0x12;
    const IA5: u8 = 0x16;
    const DC: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];

    #[test]
    fn names_match_as_rfc_5280_compares_them() {
        let root = name(&[&[(CN, UTF8, "rssig test root")]]);
        // The string type does not matter.
        assert!(names_match(
            &root,
            &name(&[&[(CN, PRINTABLE, "rssig test root")]])
        ));
        // Nor does case, nor leading, trailing or repeated white space.
        assert!(names_match(
            &root,
            &name(&[&[(CN, UTF8, "  RSSIG   Test  Root ")]])
        ));
        // Non-ASCII text folds too.
        assert!(names_match(
            &name(&[&[(CN, UTF8, "Zoë CA")]]),
            &name(&[&[(CN, UTF8, "ZOË ca")]])
        ));
        // IA5String (domainComponent) compares the same way, across tags.
        assert!(names_match(
            &name(&[&[(DC, IA5, "Example")]]),
            &name(&[&[(DC, UTF8, "example")]])
        ));
        // Different text, a different type or another RDN count does not.
        assert!(!names_match(
            &root,
            &name(&[&[(CN, UTF8, "rssig test roof")]])
        ));
        assert!(!names_match(
            &root,
            &name(&[&[(O, UTF8, "rssig test root")]])
        ));
        assert!(!names_match(
            &root,
            &name(&[&[(CN, UTF8, "rssig test root")], &[(O, UTF8, "x")]])
        ));
        // RDNs compare in order; the attributes of one RDN as a set.
        let first = name(&[&[(CN, UTF8, "a")], &[(O, UTF8, "b")]]);
        let swapped = name(&[&[(O, UTF8, "b")], &[(CN, UTF8, "a")]]);
        assert!(!names_match(&first, &swapped));
        let multi = name(&[&[(CN, UTF8, "a"), (O, UTF8, "b")]]);
        let multi_swapped = name(&[&[(O, PRINTABLE, "B"), (CN, PRINTABLE, "A")]]);
        assert!(names_match(&multi, &multi_swapped));
        // One attribute cannot match two.
        assert!(!names_match(
            &name(&[&[(CN, UTF8, "a"), (CN, UTF8, "a")]]),
            &name(&[&[(CN, UTF8, "a"), (CN, UTF8, "b")]])
        ));
        // A value of only spaces is one space, however many.
        assert!(names_match(
            &name(&[&[(CN, UTF8, "   ")]]),
            &name(&[&[(CN, PRINTABLE, " ")]])
        ));
        // A PrintableString with a character outside its set is malformed.
        assert!(!names_match(
            &name(&[&[(CN, PRINTABLE, "a@b")]]),
            &name(&[&[(CN, UTF8, "a@b")]])
        ));
        // A VisibleString is ASCII text; a byte outside 0x20-0x7e is malformed.
        let visible = |bytes: &[u8]| name_bytes(CN, VISIBLE, bytes);
        assert!(names_match(
            &visible(b"Root"),
            &name(&[&[(CN, UTF8, "root")]])
        ));
        assert!(!names_match(
            &visible(b"Ro\x07t"),
            &name(&[&[(CN, UTF8, "ro\x07t")]])
        ));
        // A string type that is not text to both references compares by exact
        // bytes: a NumericString (OpenSSL copies it as it is) and others.
        let numeric = name_bytes(CN, NUMERIC, b"12 34");
        assert!(names_match(&numeric, &numeric.clone()));
        assert!(!names_match(&numeric, &name(&[&[(CN, UTF8, "12 34")]])));
        let videotex = name(&[&[(CN, VIDEOTEX, "Root")]]);
        assert!(names_match(&videotex, &videotex.clone()));
        assert!(!names_match(&videotex, &name(&[&[(CN, UTF8, "root")]])));
        assert!(!names_match(&videotex, &name(&[&[(CN, VIDEOTEX, "root")]])));
        // A TeletexString is read as Latin-1, as OpenSSL and Bouncy Castle
        // read it: the same text, case and spacing as a UTF8String.
        let teletex = |bytes: &[u8]| name_bytes(CN, TELETEX, bytes);
        assert!(names_match(
            &teletex(b"Root"),
            &name(&[&[(CN, UTF8, "root")]])
        ));
        assert!(names_match(
            &teletex(b"Zo\xeb  CA"),
            &name(&[&[(CN, UTF8, "ZOË ca")]])
        ));
        // U+00A0 (byte 0xa0) is a space, and a different letter is another name.
        assert!(names_match(
            &teletex(b"a\xa0b"),
            &name(&[&[(CN, UTF8, "a b")]])
        ));
        assert!(!names_match(
            &teletex(b"Zo\xeb"),
            &name(&[&[(CN, UTF8, "zoe")]])
        ));
        // A BMPString is UTF-16BE.
        let bmp = |text: &str| {
            let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
            name_bytes(CN, BMP, &units)
        };
        assert!(names_match(&bmp("Root"), &name(&[&[(CN, UTF8, "root")]])));
        assert!(names_match(&bmp("ZOË"), &name(&[&[(CN, UTF8, "zoë")]])));
        assert!(!names_match(&bmp("Roof"), &name(&[&[(CN, UTF8, "root")]])));
        // Read literally: UTF-8 bytes in a TeletexString are Latin-1 text, and a
        // surrogate pair in a BMPString is two malformed units, so neither
        // matches the UTF8String it was meant to spell.
        assert!(!names_match(
            &teletex(b"\xc3\xa9"),
            &name(&[&[(CN, UTF8, "é")]])
        ));
        assert!(!names_match(
            &name_bytes(CN, BMP, &[0xd8, 0x3d, 0xde, 0x00]),
            &name(&[&[(CN, UTF8, "\u{1f600}")]])
        ));
        // A BMPString of an odd length, or with a surrogate code unit (which
        // is no character of UCS-2), is malformed and compares by exact bytes.
        assert!(!names_match(
            &name_bytes(CN, BMP, &[0, b'a', 0]),
            &name(&[&[(CN, UTF8, "a")]])
        ));
        let lone = name_bytes(CN, BMP, &[0xd8, 0x00]);
        assert!(names_match(&lone, &lone.clone()));
        assert!(!names_match(&lone, &name_bytes(CN, BMP, &[0xd8, 0x01])));
        // A large multi-valued RDN in reverse order still matches, prepared once
        // per attribute.
        let values: Vec<String> = (0..200).map(|i| alloc::format!("v{i}")).collect();
        let forward: Vec<(&[u8], u8, &str)> =
            values.iter().map(|v| (CN, UTF8, v.as_str())).collect();
        let reverse: Vec<(&[u8], u8, &str)> = values
            .iter()
            .rev()
            .map(|v| (CN, PRINTABLE, v.as_str()))
            .collect();
        assert!(names_match(&big_name(&forward), &big_name(&reverse)));
        // Bytes that are not names match only themselves.
        assert!(names_match(&[1, 2], &[1, 2]));
        assert!(!names_match(&[1, 2], &[1, 3]));
        assert!(!names_match(&root, &[0x30, 0x00, 0x00]));
    }
}
