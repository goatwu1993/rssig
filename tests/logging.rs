//! Injected diagnostic logging observes verification and never changes its result.
#![cfg(feature = "verify")]
use rssig::{
    TrustStore, VerifyOptions,
    domain::{ErrorCode, Stage},
    format::Format,
    log::{Level, Logger, Record},
    verify::Verifier,
};
use std::sync::Mutex;

const NOW: u64 = 1_800_000_000;
const GOOD: &[u8] = include_bytes!("fixtures/good-pe64.exe");
const BAD_DIGEST: &[u8] = include_bytes!("fixtures/bad-image-digest.exe");

/// Retains every record at or above `minimum`.
struct Capture {
    minimum: Level,
    records: Mutex<Vec<(Level, Stage, String)>>,
}
impl Capture {
    fn new(minimum: Level) -> Self {
        Self {
            minimum,
            records: Mutex::new(Vec::new()),
        }
    }
    fn records(&self) -> Vec<(Level, Stage, String)> {
        self.records.lock().unwrap().clone()
    }
    fn has(&self, level: Level, stage: Stage, fragment: &str) -> bool {
        self.records()
            .iter()
            .any(|(l, s, message)| *l == level && *s == stage && message.contains(fragment))
    }
}
impl Logger for Capture {
    fn enabled(&self, level: Level) -> bool {
        level >= self.minimum
    }
    fn log(&self, record: &Record<'_>) {
        assert!(record.level >= self.minimum, "disabled level was delivered");
        self.records
            .lock()
            .unwrap()
            .push((record.level, record.stage, record.message.to_string()));
    }
}

fn trusted_store() -> TrustStore {
    let mut store = TrustStore::default();
    store
        .add_roots(include_bytes!("fixtures/root.der"))
        .unwrap();
    store.add_crl(include_bytes!("fixtures/good.crl")).unwrap();
    store
}

#[test]
fn logger_observes_success_without_changing_the_report() {
    let options = VerifyOptions::integrity_only(NOW);
    let capture = Capture::new(Level::Debug);
    let logged = Verifier::new(&options)
        .with_logger(&capture)
        .verify(GOOD)
        .unwrap();
    let plain = rssig::verify(GOOD, &options).unwrap();
    assert_eq!(
        serde_json::to_value(&logged).unwrap(),
        serde_json::to_value(&plain).unwrap()
    );
    assert!(capture.has(Level::Debug, Stage::Input, "pe_authenticode"));
    assert!(capture.has(Level::Debug, Stage::Cms, "signer(s)"));
    assert!(capture.has(
        Level::Info,
        Stage::Cms,
        &logged.signatures[0].certificate_sha256
    ));
    // Integrity-only is an explicitly weakened policy and is called out.
    assert!(capture.has(Level::Warn, Stage::Configuration, "integrity-only"));
    assert!(
        !capture
            .records()
            .iter()
            .any(|(_, stage, _)| *stage == Stage::CertificateChain)
    );
}

#[test]
fn logger_reports_trusted_path_without_policy_warnings() {
    let store = trusted_store();
    let options = VerifyOptions::trusted(&store, NOW);
    let capture = Capture::new(Level::Debug);
    let report = Verifier::new(&options)
        .with_logger(&capture)
        .verify_as(GOOD, Format::Pe)
        .unwrap();
    assert!(report.signatures[0].chain_trusted);
    assert!(capture.has(Level::Debug, Stage::CertificateChain, "certificate path"));
    assert!(
        !capture
            .records()
            .iter()
            .any(|(level, _, _)| *level == Level::Warn)
    );
}

#[test]
fn logger_reports_weakened_policies() {
    let store = trusted_store();
    let mut options = VerifyOptions::trusted_with_revocation(
        &store,
        NOW,
        rssig::verify::RevocationPolicy::Disabled,
    );
    options.allow_sha1 = true;
    let capture = Capture::new(Level::Warn);
    Verifier::new(&options)
        .with_logger(&capture)
        .verify(GOOD)
        .unwrap();
    assert!(capture.has(Level::Warn, Stage::Configuration, "revocation"));
    assert!(capture.has(Level::Warn, Stage::Configuration, "SHA-1"));
    assert_eq!(capture.records().len(), 2);
}

#[test]
fn logger_observes_failure_without_changing_the_error() {
    let options = VerifyOptions::integrity_only(NOW);
    let capture = Capture::new(Level::Debug);
    let logged = Verifier::new(&options)
        .with_logger(&capture)
        .verify_with_hint(BAD_DIGEST, Some("input.exe"))
        .unwrap_err();
    let plain =
        rssig::verify::verify_with_hint(BAD_DIGEST, Some("input.exe"), &options).unwrap_err();
    assert_eq!(logged.code, ErrorCode::ImageDigestMismatch);
    assert_eq!(
        serde_json::to_value(&logged).unwrap(),
        serde_json::to_value(&plain).unwrap()
    );
    assert!(capture.has(Level::Warn, logged.stage, &logged.message));
    // No signer is announced for a file whose digest does not match.
    assert!(
        !capture
            .records()
            .iter()
            .any(|(level, _, _)| *level == Level::Info)
    );
}

#[test]
fn unsupported_input_fails_identically_with_a_logger() {
    let options = VerifyOptions::integrity_only(NOW);
    let capture = Capture::new(Level::Debug);
    let logged = Verifier::new(&options)
        .with_logger(&capture)
        .verify(b"not a signed container")
        .unwrap_err();
    let plain = rssig::verify(b"not a signed container", &options).unwrap_err();
    assert_eq!(
        serde_json::to_value(&logged).unwrap(),
        serde_json::to_value(&plain).unwrap()
    );
    assert!(capture.has(Level::Warn, logged.stage, "verification failed"));
}

#[test]
fn disabled_levels_are_never_delivered() {
    struct Off;
    impl Logger for Off {
        fn enabled(&self, _: Level) -> bool {
            false
        }
        fn log(&self, _: &Record<'_>) {
            panic!("a disabled logger received a record");
        }
    }
    let options = VerifyOptions::integrity_only(NOW);
    Verifier::new(&options)
        .with_logger(&Off)
        .verify(GOOD)
        .unwrap();
    Verifier::new(&options)
        .with_logger(&Off)
        .verify(BAD_DIGEST)
        .unwrap_err();

    let info = Capture::new(Level::Info);
    Verifier::new(&options)
        .with_logger(&info)
        .verify(GOOD)
        .unwrap();
    assert!(!info.records().is_empty());
}

#[test]
fn verifier_without_logger_matches_free_functions() {
    let options = VerifyOptions::integrity_only(NOW);
    assert_eq!(
        serde_json::to_value(Verifier::new(&options).verify(GOOD).unwrap()).unwrap(),
        serde_json::to_value(rssig::verify(GOOD, &options).unwrap()).unwrap()
    );
    assert_eq!(
        serde_json::to_value(Verifier::new(&options).verify(BAD_DIGEST).unwrap_err()).unwrap(),
        serde_json::to_value(rssig::verify(BAD_DIGEST, &options).unwrap_err()).unwrap()
    );
}

#[test]
fn logging_keeps_verification_shareable_across_threads() {
    fn shareable<T: Send + Sync>(_: &T) {}
    let options = VerifyOptions::integrity_only(NOW);
    let capture = Capture::new(Level::Info);
    let verifier = Verifier::new(&options).with_logger(&capture);
    shareable(&verifier);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| verifier.verify(GOOD).unwrap());
        }
    });
    assert_eq!(
        capture
            .records()
            .iter()
            .filter(|(level, _, _)| *level == Level::Info)
            .count(),
        2
    );
}
