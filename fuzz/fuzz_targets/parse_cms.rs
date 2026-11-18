//! DER, CMS envelope, signer, attribute, timestamp-token and time decoding.
//! Property: arbitrary bytes return a value or a typed error; never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig::parse::{
    AlgorithmIdentifier, Attributes, InspectionBudget, ParsedTime, SignedData, SignerInfo, TstInfo,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(cms) = SignedData::parse(data) {
        let _ = cms.content_type();
        let _ = cms.content();
        for choice in cms.certificate_choices() {
            let _ = choice.x509();
        }
        for signer in cms.signer_infos() {
            if let Ok(signer) = SignerInfo::parse(signer) {
                let _ = signer.identifier();
                for attributes in [signer.signed_attributes(), signer.unsigned_attributes()]
                    .into_iter()
                    .flatten()
                {
                    for attribute in attributes.attributes() {
                        let _ = attribute.oid();
                        let _ = attribute.values();
                    }
                }
            }
        }
    }
    // One default budget per input, as the parse CLI uses.
    let _ = SignedData::inspect(data, &mut InspectionBudget::default());
    let _ = SignerInfo::parse(data);
    let _ = Attributes::parse(data);
    let _ = AlgorithmIdentifier::parse(data);
    let _ = TstInfo::parse(data);
    let _ = ParsedTime::parse(data);
});
