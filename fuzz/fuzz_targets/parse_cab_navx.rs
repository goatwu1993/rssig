//! CAB and NAVX container framing and their signature/digest ranges.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig_engine::parse::{Cab, Navx, SignedData};

fuzz_target!(|data: &[u8]| {
    if let Ok(cab) = Cab::parse(data) {
        let _ = cab.authenticode_chunks();
        let _ = SignedData::parse(cab.signature());
    }
    if let Ok(navx) = Navx::parse(data) {
        let _ = navx.authenticode_chunks();
        let _ = SignedData::parse(navx.signature());
    }
});
