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
//! Unicode normalization or prohibited-character check, so it matches fewer
//! names than the RFC; a
//! name it does not match is an unknown CRL issuer, never a trusted one, and
//! the CRL is authenticated by its signature either way. IA5String values
//! (domainComponent, emailAddress) compare the same way, as RFC 5280 section
//! 7.3 and PKCS #9 match them case-insensitively; any other string type, and
//! a PrintableString outside its character set, compares by exact bytes.
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

/// A PrintableString, UTF8String or IA5String value after lower-casing and
/// insignificant space handling; `None` for any other type or bytes that are
/// not valid text.
fn prepared(value: &::der::Any) -> Option<String> {
    let text = match value.tag() {
        Tag::Utf8String => core::str::from_utf8(value.value()).ok()?,
        // A PrintableString outside its character set is malformed and
        // compares by exact bytes.
        Tag::PrintableString if value.value().iter().all(|b| printable(*b)) => {
            core::str::from_utf8(value.value()).ok()?
        }
        Tag::Ia5String if value.value().is_ascii() => core::str::from_utf8(value.value()).ok()?,
        _ => return None,
    };
    // RFC 4518 section 2.2 maps U+0009 to U+000D, U+0085 and every other
    // Separator (Zs, Zl, Zp) code point to a space, which is exactly what
    // `char::is_whitespace` accepts. Its map-to-nothing characters are not
    // dropped, so such a value matches fewer names than the RFC (CRL-T012).
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
        // Another string type compares by exact bytes.
        let teletex = name(&[&[(CN, TELETEX, "Root")]]);
        assert!(names_match(&teletex, &teletex.clone()));
        assert!(!names_match(&teletex, &name(&[&[(CN, UTF8, "root")]])));
        assert!(!names_match(&teletex, &name(&[&[(CN, TELETEX, "root")]])));
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
