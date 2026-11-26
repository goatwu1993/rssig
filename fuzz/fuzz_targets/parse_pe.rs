//! PE header, section and certificate-table layout, then each embedded CMS blob.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig_engine::parse::{InspectionBudget, Pe, SignedData, authenticode_digest};
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    let Ok(pe) = Pe::parse(data) else { return };
    let _ = pe.authenticode_chunks();
    let mut digest = Sha256::new();
    let _ = authenticode_digest(&pe, &mut digest);
    let mut budget = InspectionBudget::default();
    if let Ok(signatures) = pe.signatures() {
        for signature in signatures {
            let _ = SignedData::parse(signature);
            let _ = SignedData::inspect(signature, &mut budget);
        }
    }
});
