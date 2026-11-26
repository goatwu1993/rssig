//! Complete integrity-only verification of the text formats. Each input is
//! offered to every text verifier so no format depends on a filename hint.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig_engine::format::Format;
use rssig_engine::parse::WshKind;
use rssig_engine::verify::{VerifyOptions, verify, verify_as};

/// Fixed validation time (2027-01-15T07:59:59Z), matching the pinned test clock.
const NOW: u64 = 1_799_999_999;

fuzz_target!(|data: &[u8]| {
    let options = VerifyOptions::integrity_only(NOW);
    for format in [
        Format::Powershell,
        Format::PowershellXml,
        Format::Wsh(WshKind::VbScript),
        Format::Wsh(WshKind::JScript),
        Format::Wsh(WshKind::Wsf),
        Format::Rdp,
    ] {
        let _ = verify_as(data, format, &options);
    }
    // Marker-based detection without a filename hint.
    let _ = verify(data, &options);
});
