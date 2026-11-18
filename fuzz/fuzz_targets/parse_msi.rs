//! MSI/MSP compound-file directory walking and canonical digest streaming.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig::parse::{Msi, SignedData};
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    let Ok(mut msi) = Msi::parse(data) else {
        return;
    };
    let _ = SignedData::parse(msi.signature());
    let _ = msi.extended_digest();
    let mut digest = Sha256::new();
    let _ = msi.update_metadata(&mut digest);
    let _ = msi.update_content(&mut digest);
});
