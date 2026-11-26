//! The engine's inspection reports (`inspect::{pe, cms, cab, navx}`) on
//! arbitrary bytes. Inspection projects untrusted parser values into owned
//! reports without verifying them, so it must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig_engine::inspect;

fuzz_target!(|data: &[u8]| {
    let _ = inspect::pe(data);
    let _ = inspect::cms(data);
    let _ = inspect::cab(data);
    let _ = inspect::navx(data);
});
