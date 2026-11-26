//! Complete verification of magic-detected binary containers under a fixed,
//! offline policy: integrity-only (no roots, no CRLs, no clock, no network).
//! Property: every input yields a bundle or a typed error within the
//! verifier's own budgets; never a panic, hang or unbounded allocation.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig_engine::format::Format;
use rssig_engine::verify::{VerifyOptions, verify_as};

/// Fixed validation time (2027-01-15T07:59:59Z), matching the pinned test clock.
const NOW: u64 = 1_799_999_999;

fuzz_target!(|data: &[u8]| {
    let formats: &[Format] = if data.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        &[Format::Msi]
    } else if data.starts_with(b"PK\x03\x04") {
        &[Format::Appx]
    } else if data.starts_with(b"MZ") {
        &[Format::Pe]
    } else {
        // CAB and NAVX each reject the other's magic immediately.
        &[Format::Cab, Format::Navx]
    };
    let mut options = VerifyOptions::integrity_only(NOW);
    // Legacy SHA-1 content digests take a separate policy branch.
    for allow_sha1 in [false, true] {
        options.allow_sha1 = allow_sha1;
        for format in formats {
            let _ = verify_as(data, *format, &options);
        }
    }
});
