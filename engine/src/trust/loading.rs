//! Atomic trust input loading. Decoding and anchor extraction are not verification.
use super::{TrustLoadError, TrustLoadErrorCode as Code, TrustLoadErrorKind as Kind, TrustStore};
use alloc::{format, vec, vec::Vec};
use anyhow::ensure;
use der::Decode;
use rustls_pki_types::CertificateDer;
use x509_cert::{Certificate, crl::CertificateList};

impl TrustStore {
    /// Atomically load DER or a nonempty CERTIFICATE PEM bundle.
    /// Reject every undecodable/unsupported anchor; deduplicate exact DER bytes.
    /// Anchor extraction does not authenticate certificates or check root certificate fields.
    pub fn add_roots(&mut self, bytes: &[u8]) -> Result<(), TrustLoadError> {
        let pending = decode_input(bytes, Kind::Roots)?;
        for bytes in pending {
            let root = CertificateDer::from(bytes);
            if !self.roots.contains(&root) {
                self.roots.push(root);
            }
        }
        Ok(())
    }

    /// Atomically load DER or a nonempty X509 CRL PEM bundle, deduplicating exact DER.
    /// Loading checks syntax only, never signature, applicability or freshness.
    pub fn add_crl(&mut self, bytes: &[u8]) -> Result<(), TrustLoadError> {
        let pending = decode_input(bytes, Kind::Crl)?;
        for crl in pending {
            if !self.crls.contains(&crl) {
                self.crls.push(crl);
            }
        }
        Ok(())
    }

    /// Build a store from an operating-system root enumeration (the `rssig`
    /// application's `roots::system_roots`): the roots it returned and the
    /// errors it reported. Any error rejects the whole enumeration, partial
    /// results included, as `NativeEnumeration`. The cause lists each error's
    /// `Display` once and how many returned roots were discarded; the engine
    /// walks no `source()` chain, so an adapter passes errors whose `Display`
    /// states what it wants reported (rustls-native-certs' errors include
    /// their cause). Otherwise each root is validated as an anchor and
    /// reported by its one-based position in the OS store, and exact
    /// duplicates are kept once. No roots is an error: an empty or unusable
    /// system store never silently becomes integrity-only. The engine never
    /// enumerates roots itself.
    pub fn from_system_roots<I, R, E>(roots: I, errors: Vec<E>) -> Result<Self, TrustLoadError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u8]>,
        E: core::fmt::Display,
    {
        if !errors.is_empty() {
            use alloc::string::ToString;
            return Err(TrustLoadError::new(
                Kind::SystemRoots,
                Code::NativeEnumeration,
                None,
                Some(anyhow::Error::new(EnumerationErrors {
                    errors: errors.iter().map(ToString::to_string).collect(),
                    discarded: roots.into_iter().count(),
                })),
            ));
        }
        let mut store = Self::default();
        let mut seen = 0;
        for (index, root) in roots.into_iter().enumerate() {
            seen += 1;
            let root = root.as_ref();
            validate(root, Kind::SystemRoots, index + 1)?;
            let root = CertificateDer::from(root.to_vec());
            if !store.roots.contains(&root) {
                store.roots.push(root);
            }
        }
        if seen == 0 {
            return Err(TrustLoadError::new(
                Kind::SystemRoots,
                Code::EmptyInput,
                None,
                None,
            ));
        }
        Ok(store)
    }
}

/// The errors of a rejected OS root enumeration, each as its `Display`.
#[derive(Debug)]
struct EnumerationErrors {
    errors: Vec<alloc::string::String>,
    discarded: usize,
}

/// Lists every error once. It reports no `source()`: an adapter error may
/// already state its cause in `Display` (rustls-native-certs does, and returns
/// it from `source()` too), and walking the chain would print it twice.
impl core::fmt::Display for EnumerationErrors {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} native loading errors; {} returned certificates discarded",
            self.errors.len(),
            self.discarded
        )?;
        for error in &self.errors {
            write!(f, "; {error}")?;
        }
        Ok(())
    }
}

impl core::error::Error for EnumerationErrors {}

/// The issuer name (DER) of each CRL in a DER or PEM input that loads,
/// whether it is a full CRL (no issuingDistributionPoint and not a delta CRL,
/// deltaCRLIndicator, which webpki cannot use), and its DER.
#[cfg(feature = "retrieval")]
pub(crate) fn crl_issuers(bytes: &[u8]) -> Vec<(Vec<u8>, bool, Vec<u8>)> {
    decode_input(bytes, Kind::Crl)
        .unwrap_or_default()
        .iter()
        .filter_map(|der| CertificateList::from_der(der).ok().map(|list| (der, list)))
        .filter_map(|(der, list)| {
            let full = !list
                .tbs_cert_list
                .crl_extensions
                .iter()
                .flatten()
                .any(|e| matches!(e.extn_id.to_string().as_str(), "2.5.29.28" | "2.5.29.27"));
            ::der::Encode::to_der(&list.tbs_cert_list.issuer)
                .ok()
                .map(|issuer| (issuer, full, der.clone()))
        })
        .collect()
}

fn validate(bytes: &[u8], kind: Kind, index: usize) -> Result<(), TrustLoadError> {
    let parsed = match kind {
        Kind::Crl => CertificateList::from_der(bytes).map(|_| ()),
        _ => Certificate::from_der(bytes).map(|_| ()),
    };
    parsed.map_err(|e| {
        TrustLoadError::new(
            kind,
            Code::InvalidEncoding,
            Some(index),
            Some(crate::compat_error(e)),
        )
    })?;
    if kind != Kind::Crl {
        webpki::anchor_from_trusted_cert(&CertificateDer::from(bytes)).map_err(|e| {
            TrustLoadError::new(
                kind,
                Code::UnsupportedAnchor,
                Some(index),
                Some(anyhow::anyhow!("{e:?}")),
            )
        })?;
    }
    Ok(())
}

fn decode_input(bytes: &[u8], kind: Kind) -> Result<Vec<Vec<u8>>, TrustLoadError> {
    let mut rest = bytes.trim_ascii();
    if rest.is_empty() {
        return Err(TrustLoadError::new(kind, Code::EmptyInput, None, None));
    }
    if !rest.starts_with(b"-----BEGIN") {
        // DER must be exact; only PEM permits surrounding ASCII whitespace.
        validate(bytes, kind, 1)?;
        return Ok(vec![bytes.to_vec()]);
    }
    let label = if kind == Kind::Crl {
        "X509 CRL"
    } else {
        "CERTIFICATE"
    };
    let header = format!("-----BEGIN {label}-----");
    let footer = format!("-----END {label}-----");
    let mut pending = Vec::new();
    while !rest.is_empty() {
        let index = pending.len() + 1;
        let decoded = (|| -> anyhow::Result<_> {
            ensure!(
                rest.starts_with(header.as_bytes()),
                "expected {label} PEM label; unexpected data"
            );
            let end = rest
                .windows(footer.len())
                .position(|w| w == footer.as_bytes())
                .ok_or_else(|| anyhow::anyhow!("unterminated {label} PEM block"))?
                + footer.len();
            let (_, decoded) = der::pem::decode_vec(&rest[..end])
                .map_err(|e| anyhow::anyhow!("invalid {label} PEM: {e}"))?;
            rest = rest[end..].trim_ascii_start();
            Ok(decoded)
        })()
        .map_err(|e| TrustLoadError::new(kind, Code::InvalidEncoding, Some(index), Some(e)))?;
        validate(&decoded, kind, index)?;
        pending.push(decoded);
    }
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &[u8] = include_bytes!("../../../tests/fixtures/root.der");
    const CRL: &[u8] = include_bytes!("../../../tests/fixtures/good.crl");

    #[test]
    fn exact_duplicates_are_idempotent_but_distinct_anchors_remain() {
        let mut store = TrustStore::default();
        for _ in 0..2 {
            store.add_roots(ROOT).unwrap();
            store
                .add_roots(include_bytes!(
                    "../../../tests/fixtures/root-bundle-duplicate.pem"
                ))
                .unwrap();
            store.add_crl(CRL).unwrap();
            store
                .add_crl(include_bytes!(
                    "../../../tests/fixtures/crl-bundle-duplicate.pem"
                ))
                .unwrap();
        }
        assert_eq!(store.roots.len(), 1);
        assert_eq!(store.crls.len(), 1);
        assert_eq!(store.roots[0].as_ref(), ROOT);
        assert_eq!(store.crls[0], CRL);
        // Same subject/key with different name constraints must never be deduplicated.
        store
            .add_roots(include_bytes!(
                "../../../tests/fixtures/path-roots-alternative.pem"
            ))
            .unwrap();
        assert_eq!(store.roots.len(), 3);
    }

    #[test]
    fn pem_bounds_and_der_trailing_data_are_rejected_without_mutation() {
        let mut store = TrustStore::default();
        store.add_roots(ROOT).unwrap();
        store.add_crl(CRL).unwrap();
        for bytes in [
            b"-----BEGIN".as_slice(),
            b"-----BEGIN CERTIFICATE-----",
            b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----",
            b"-----BEGIN X509 CRL-----\n!\n-----END X509 CRL-----",
        ] {
            assert_eq!(
                store.add_roots(bytes).unwrap_err().code(),
                Code::InvalidEncoding
            );
            assert_eq!(
                store.add_crl(bytes).unwrap_err().code(),
                Code::InvalidEncoding
            );
        }
        for extra in [b"!".as_slice(), b"\n", b"\0", ROOT] {
            let bytes = [ROOT, extra].concat();
            assert_eq!(
                store.add_roots(&bytes).unwrap_err().code(),
                Code::InvalidEncoding
            );
            let bytes = [CRL, extra].concat();
            assert_eq!(
                store.add_crl(&bytes).unwrap_err().code(),
                Code::InvalidEncoding
            );
        }
        assert_eq!(store.roots.len(), 1);
        assert_eq!(store.crls.len(), 1);
    }

    /// No enumeration errors, with a concrete error type.
    #[cfg(feature = "std")]
    fn system_roots(roots: &[&[u8]]) -> Result<TrustStore, TrustLoadError> {
        TrustStore::from_system_roots(roots.to_vec(), Vec::<std::io::Error>::new())
    }

    #[test]
    #[cfg(feature = "std")]
    fn system_roots_empty_unsupported_malformed_and_duplicate_results() {
        let empty = system_roots(&[]).err().unwrap();
        assert_eq!(empty.kind(), Kind::SystemRoots);
        assert_eq!(empty.code(), Code::EmptyInput);
        assert_eq!(empty.entry_index(), None);
        for (bad, code) in [
            (
                include_bytes!("../../../tests/fixtures/root-unsupported.der").as_slice(),
                Code::UnsupportedAnchor,
            ),
            (b"\x30\x00".as_slice(), Code::InvalidEncoding),
        ] {
            let error = system_roots(&[ROOT, bad]).err().unwrap();
            assert_eq!(error.kind(), Kind::SystemRoots);
            assert_eq!(error.code(), code);
            assert_eq!(error.entry_index(), Some(2));
            // OS-store positions are not user trust input.
            assert!(
                format!("{error}").ends_with(" in system root store entry 2"),
                "{error}"
            );
        }
        let store = system_roots(&[ROOT, ROOT]).unwrap();
        assert_eq!(store.roots.len(), 1);
        assert_eq!(store.roots[0].as_ref(), ROOT);
        assert!(store.crls.is_empty());
    }

    /// Each error is listed by its `Display` alone: a `source()` it also
    /// returns is not walked, so a cause its `Display` states is not repeated
    /// and one it leaves out is the adapter's to render.
    #[test]
    #[cfg(feature = "std")]
    fn an_enumeration_error_is_listed_by_its_display_once() {
        #[derive(Debug)]
        struct Adapter(&'static str, std::io::Error);
        impl core::fmt::Display for Adapter {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.0)
            }
        }
        impl std::error::Error for Adapter {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.1)
            }
        }
        for display in [
            "reading roots: permission denied at 'store'",
            "cannot open keychain",
        ] {
            let errors = vec![Adapter(display, std::io::Error::other("permission denied"))];
            let error = TrustStore::from_system_roots(Vec::<Vec<u8>>::new(), errors)
                .err()
                .unwrap();
            let text = format!("{error:#}");
            assert_eq!(
                text,
                format!(
                    "system root enumeration failed: 1 native loading errors; 0 returned certificates discarded; {display}"
                )
            );
            crate::assert_causes_once(&error, &text);
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn a_partial_system_enumeration_is_rejected_whole() {
        for roots in [&[ROOT][..], &[][..]] {
            let errors = vec![
                std::io::Error::other("native fault 0"),
                std::io::Error::other("native fault 1"),
            ];
            let error = TrustStore::from_system_roots(roots.to_vec(), errors)
                .err()
                .unwrap();
            assert_eq!(error.kind(), Kind::SystemRoots);
            assert_eq!(error.code(), Code::NativeEnumeration);
            assert_eq!(error.entry_index(), None);
            assert_eq!(format!("{error}"), "system root enumeration failed");
            let text = format!("{error:#}");
            assert_eq!(
                text,
                format!(
                    "system root enumeration failed: 2 native loading errors; {} returned certificates discarded; native fault 0; native fault 1",
                    roots.len()
                )
            );
            crate::assert_causes_once(&error, &text);
        }
    }
}
