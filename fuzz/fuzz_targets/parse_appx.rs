//! AppX/MSIX ZIP records, DEFLATE parts, content types, block maps and manifests.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig::parse::{Appx, BlockMap, SignedData};

/// Per-part decode limit: far above any seed, far below the fuzzer's memory limit.
const PART_LIMIT: usize = 1 << 20;

fn block_map(bytes: &[u8]) {
    let Ok(map) = BlockMap::parse(bytes) else {
        return;
    };
    let _ = map.hash_method();
    for file in map.files() {
        let _ = file.name();
        let _ = file.size();
        let _ = file.local_header_size();
        if let Ok(blocks) = file.blocks() {
            for block in blocks {
                let _ = block.hash();
                let _ = block.compressed_size();
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // The block map is also reachable as a standalone XML document.
    block_map(data);
    let Ok(appx) = Appx::parse(data) else { return };
    let _ = SignedData::parse(appx.signature());
    let _ = appx.is_bundle();
    let _ = appx.bundle_packages();
    let _ = appx.digest_inputs();
    let _ = appx.code_integrity_catalog();
    let _ = appx.identity();
    let _ = appx.resource_package();
    let _ = appx.content_types();
    if let Ok(bytes) = appx.block_map_bytes() {
        block_map(&bytes);
    }
    for part in appx.parts() {
        let _ = part.read(PART_LIMIT);
    }
});
