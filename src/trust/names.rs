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

/// Whether two DER-encoded names are the same name under RFC 5280 section
/// 7.1. Names that do not decode match only when their bytes are equal.
pub(crate) fn names_match(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    let (Ok(a), Ok(b)) = (Name::from_der(a), Name::from_der(b)) else {
        return false;
    };
    a.0.len() == b.0.len() && a.0.iter().zip(&b.0).all(|(x, y)| rdn_match(x, y))
}

/// Two RDNs match when their attributes are equal as multisets. Each
/// attribute is reduced once to a key (its type and its prepared value, or its
/// exact encoding when it has none) and the sorted keys are compared, so the
/// work grows with n log n in the attribute count, not with its square.
fn rdn_match(a: &RelativeDistinguishedName, b: &RelativeDistinguishedName) -> bool {
    if a.0.len() != b.0.len() {
        return false;
    }
    let (Some(mut a), Some(mut b)) = (keys(a), keys(b)) else {
        return false;
    };
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

fn keys(rdn: &RelativeDistinguishedName) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    rdn.0.iter().map(key).collect()
}

/// An attribute's type and value in a form that is equal exactly when the
/// attributes match: a prepared value is marked 0, an exact encoding 1, so the
/// two cannot collide.
fn key(attribute: &AttributeTypeAndValue) -> Option<(Vec<u8>, Vec<u8>)> {
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
    // dropped, so such a value matches fewer names than the RFC (SEC-26).
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
    use super::names_match;
    use alloc::{string::String, vec, vec::Vec};

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
