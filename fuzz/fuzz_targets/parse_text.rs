//! Text-encoded formats: PowerShell, PowerShell XML, WSH scripts and signed RDP.
//! Every parser sees every input, so encoding detection and signature-block
//! framing are exercised regardless of which format a seed came from.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig_engine::parse::{Powershell, Rdp, SignedData, Wsh, WshKind};
use sha2::{Digest, Sha256};

fn powershell(parsed: Result<Powershell<'_>, rssig_engine::parse::Error>) {
    let Ok(script) = parsed else { return };
    let _ = script.authenticode_bytes();
    script.update_digest(&mut Sha256::new());
    let _ = SignedData::parse(script.signature());
}

fuzz_target!(|data: &[u8]| {
    powershell(Powershell::parse(data));
    powershell(Powershell::parse_xml(data));
    let _ = Wsh::detect(data);
    for kind in [WshKind::VbScript, WshKind::JScript, WshKind::Wsf] {
        if let Ok(script) = Wsh::parse(data, kind) {
            let _ = script.insertion_position();
            let _ = script.authenticode_bytes();
            script.update_digest(&mut Sha256::new());
            let _ = SignedData::parse(script.signature());
        }
    }
    if let Ok(rdp) = Rdp::parse(data) {
        let _ = rdp.canonical_bytes();
        let _ = rdp.signscope();
        let _ = SignedData::parse(rdp.signature());
    }
});
