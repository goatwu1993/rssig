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

    #[deprecated(note = "use `add_roots`, which now returns `TrustLoadError`")]
    pub fn add_roots_typed(&mut self, bytes: &[u8]) -> Result<(), TrustLoadError> {
        self.add_roots(bytes)
    }

    #[deprecated(note = "use `add_crl`, which now returns `TrustLoadError`")]
    pub fn add_crl_typed(&mut self, bytes: &[u8]) -> Result<(), TrustLoadError> {
        self.add_crl(bytes)
    }

    /// Enumerate OS roots only; reject partial enumeration, empty or unusable stores.
    /// No native signature, path or revocation validation is called.
    #[cfg(feature = "system-roots")]
    pub fn from_system() -> Result<Self, TrustLoadError> {
        Self::from_native(rustls_native_certs::load_native_certs())
    }

    #[cfg(feature = "system-roots")]
    #[deprecated(note = "use `from_system`, which now returns `TrustLoadError`")]
    pub fn from_system_typed() -> Result<Self, TrustLoadError> {
        Self::from_system()
    }

    #[cfg(feature = "system-roots")]
    fn from_native(native: rustls_native_certs::CertificateResult) -> Result<Self, TrustLoadError> {
        if !native.errors.is_empty() {
            return Err(TrustLoadError::new(
                Kind::SystemRoots,
                Code::NativeEnumeration,
                None,
                Some(anyhow::Error::new(NativeErrors {
                    errors: native.errors,
                    discarded: native.certs.len(),
                })),
            ));
        }
        if native.certs.is_empty() {
            return Err(TrustLoadError::new(
                Kind::SystemRoots,
                Code::EmptyInput,
                None,
                None,
            ));
        }
        let mut store = Self::default();
        for (index, root) in native.certs.into_iter().enumerate() {
            validate(&root, Kind::SystemRoots, index + 1)?;
            if !store.roots.contains(&root) {
                store.roots.push(root);
            }
        }
        Ok(store)
    }
}

/// The issuer name (DER) of each CRL in a DER or PEM input that loads,
/// whether it is a full CRL (no issuingDistributionPoint and not a delta CRL,
/// deltaCRLIndicator, which webpki cannot use), and its DER.
#[cfg(feature = "crl-fetch")]
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

#[cfg(feature = "system-roots")]
#[derive(Debug)]
struct NativeErrors {
    errors: Vec<rustls_native_certs::Error>,
    discarded: usize,
}

/// Lists every native error. It reports no `source()`: returning one of the
/// listed errors would print it a second time.
#[cfg(feature = "system-roots")]
impl core::fmt::Display for NativeErrors {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} native loading errors; {} returned certificates discarded",
            self.errors.len(),
            self.discarded
        )?;
        // rustls-native-certs already writes its I/O cause into `Display` (and
        // also returns it from `source()`), so print each error exactly once.
        for error in &self.errors {
            write!(f, "; {error}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "system-roots")]
impl core::error::Error for NativeErrors {}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &[u8] = include_bytes!("../../tests/fixtures/root.der");
    const CRL: &[u8] = include_bytes!("../../tests/fixtures/good.crl");

    #[test]
    fn exact_duplicates_are_idempotent_but_distinct_anchors_remain() {
        let mut store = TrustStore::default();
        for _ in 0..2 {
            store.add_roots(ROOT).unwrap();
            store
                .add_roots(include_bytes!(
                    "../../tests/fixtures/root-bundle-duplicate.pem"
                ))
                .unwrap();
            store.add_crl(CRL).unwrap();
            store
                .add_crl(include_bytes!(
                    "../../tests/fixtures/crl-bundle-duplicate.pem"
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
                "../../tests/fixtures/path-roots-alternative.pem"
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

    #[cfg(feature = "system-roots")]
    fn native(certs: &[&[u8]], errors: usize) -> rustls_native_certs::CertificateResult {
        let mut result = rustls_native_certs::CertificateResult::default();
        result.certs = certs
            .iter()
            .map(|b| CertificateDer::from(b.to_vec()))
            .collect();
        for index in 0..errors {
            result.errors.push(rustls_native_certs::Error {
                context: "injected root enumeration failure",
                kind: rustls_native_certs::ErrorKind::Io {
                    inner: std::io::Error::other(format!("native fault {index}")),
                    path: "fixture-native-store".into(),
                },
            });
        }
        result
    }

    #[test]
    #[cfg(feature = "system-roots")]
    fn native_partial_and_total_failures_retain_diagnostics() {
        for certs in [&[ROOT][..], &[][..]] {
            let error = TrustStore::from_native(native(certs, 2)).err().unwrap();
            assert_eq!(error.kind(), Kind::SystemRoots);
            assert_eq!(error.code(), Code::NativeEnumeration);
            assert_eq!(error.entry_index(), None);
            assert_eq!(format!("{error}"), "system root enumeration failed");
            let text = format!("{error:#}");
            assert!(text.contains("2 native loading errors"), "{text}");
            assert!(
                text.contains(&format!("{} returned certificates discarded", certs.len())),
                "{text}"
            );
            for fragment in ["native fault 0", "native fault 1"] {
                assert_eq!(text.matches(fragment).count(), 1, "{text}");
            }
            assert_eq!(
                text.matches("injected root enumeration failure").count(),
                2,
                "{text}"
            );
            crate::assert_causes_once(&error, &text);
        }
    }

    #[test]
    #[cfg(feature = "system-roots")]
    fn native_empty_unsupported_malformed_and_duplicate_results() {
        let empty = TrustStore::from_native(native(&[], 0)).err().unwrap();
        assert_eq!(empty.kind(), Kind::SystemRoots);
        assert_eq!(empty.code(), Code::EmptyInput);
        assert_eq!(empty.entry_index(), None);
        for (bad, code) in [
            (
                include_bytes!("../../tests/fixtures/root-unsupported.der").as_slice(),
                Code::UnsupportedAnchor,
            ),
            (b"\x30\x00".as_slice(), Code::InvalidEncoding),
        ] {
            let error = TrustStore::from_native(native(&[ROOT, bad], 0))
                .err()
                .unwrap();
            assert_eq!(error.kind(), Kind::SystemRoots);
            assert_eq!(error.code(), code);
            assert_eq!(error.entry_index(), Some(2));
            // OS-store positions are not user trust input.
            assert!(
                error.to_string().ends_with(" in system root store entry 2"),
                "{error}"
            );
        }
        let store = TrustStore::from_native(native(&[ROOT, ROOT], 0)).unwrap();
        assert_eq!(store.roots.len(), 1);
        assert_eq!(store.roots[0].as_ref(), ROOT);
        assert!(store.crls.is_empty());
    }
}
