//! Verification through `Verifier` with an injected logger that formats every
//! record, under the offline integrity-only policy of the other verify targets.
//! Properties: formatting diagnostics for arbitrary input never panics, and a
//! logger never changes the outcome reached without one.
#![no_main]

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicUsize, Ordering};
use libfuzzer_sys::fuzz_target;
use rssig_engine::log::{Logger, Record};
use rssig_engine::verify::{Verifier, VerifyOptions, verify};

/// Fixed validation time (2027-01-15T07:59:59Z), matching the pinned test clock.
const NOW: u64 = 1_799_999_999;

/// Formats each message without retaining it, so the sink stays bounded.
struct Count(AtomicUsize);
impl Write for &Count {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0.fetch_add(text.len(), Ordering::Relaxed);
        Ok(())
    }
}
impl Logger for Count {
    fn log(&self, record: &Record<'_>) {
        let mut sink = self;
        let _ = write!(
            sink,
            "{:?} {:?} {}",
            record.level, record.stage, record.message
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut options = VerifyOptions::integrity_only(NOW);
    for allow_sha1 in [false, true] {
        options.allow_sha1 = allow_sha1;
        let count = Count(AtomicUsize::new(0));
        let logged = Verifier::new(&options).with_logger(&count).verify(data);
        let plain = verify(data, &options);
        match (logged, plain) {
            (Ok(_), Ok(_)) => {}
            (Err(logged), Err(plain)) => assert_eq!(logged.code, plain.code),
            _ => panic!("a logger changed the verification outcome"),
        }
        // Integrity-only policy is always announced, so some record was formatted.
        assert!(count.0.load(Ordering::Relaxed) > 0);
    }
});
