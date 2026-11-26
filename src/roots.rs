//! The default root source: the operating system's store, enumerated with
//! `rustls-native-certs`. The OS supplies root certificates only; it is never
//! asked to verify a signature, chain, timestamp or revocation status.
use rssig_engine::{TrustLoadError, TrustStore};

/// Enumerate the OS roots into a [`TrustStore`]. The engine rejects a partial
/// enumeration, an empty store or an unusable root: an error, never a smaller
/// store or integrity-only verification.
pub fn system_roots() -> Result<TrustStore, TrustLoadError> {
    from_native(rustls_native_certs::load_native_certs())
}

fn from_native(
    native: rustls_native_certs::CertificateResult,
) -> Result<TrustStore, TrustLoadError> {
    TrustStore::from_system_roots(native.certs, native.errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rssig_engine::{TrustLoadErrorCode as Code, TrustLoadErrorKind as Kind};

    const ROOT: &[u8] = include_bytes!("../tests/fixtures/root.der");

    /// Error formatting contract: `{}` is the summary, `source()` walks the
    /// causes, and `{:#}` is exactly the summary followed by each cause once.
    fn assert_causes_once(error: &dyn std::error::Error, alternate: &str) {
        let mut walked = error.to_string();
        let mut cause = error.source();
        while let Some(next) = cause {
            walked.push_str(&format!(": {next}"));
            cause = next.source();
        }
        assert_eq!(walked, alternate);
    }

    fn native(certs: &[&[u8]], errors: usize) -> rustls_native_certs::CertificateResult {
        let mut result = rustls_native_certs::CertificateResult::default();
        result.certs = certs.iter().map(|b| b.to_vec().into()).collect();
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

    // Pins the loader's error type: `anyhow` stays out of the public API.
    #[test]
    fn system_roots_returns_trust_load_error() {
        let _: fn() -> Result<TrustStore, TrustLoadError> = system_roots;
    }

    #[test]
    fn native_partial_and_total_failures_retain_diagnostics() {
        for certs in [&[ROOT][..], &[][..]] {
            let error = from_native(native(certs, 2)).err().unwrap();
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
            assert_causes_once(&error, &text);
        }
    }

    #[test]
    fn native_results_go_through_the_engines_anchor_checks() {
        let empty = from_native(native(&[], 0)).err().unwrap();
        assert_eq!(empty.kind(), Kind::SystemRoots);
        assert_eq!(empty.code(), Code::EmptyInput);
        let bad = from_native(native(&[ROOT, b"\x30\x00"], 0)).err().unwrap();
        assert_eq!(bad.code(), Code::InvalidEncoding);
        assert_eq!(bad.entry_index(), Some(2));
        let store = from_native(native(&[ROOT, ROOT], 0)).unwrap();
        assert_eq!(store.root_count(), 1);
        assert_eq!(store.crl_count(), 0);
    }
}
