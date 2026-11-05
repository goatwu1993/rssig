//! Deterministic inspection-only envelopes; no cryptographic assertions.
use super::*;
pub(super) fn write(dir: &std::path::Path) {
    write_long_oid(dir);
    let alg = seq(&[oid(&[96, 134, 72, 1, 101, 3, 4, 2, 1]), vec![5, 0]]);
    let sigalg = seq(&[oid(&[42, 3, 5]), seq(&[])]);
    let attr = seq(&[oid(&[42, 3, 4]), tlv(0x31, &tlv(4, b"opaque"))]);
    let unsigned = seq(&[
        oid(&[42, 3, 6]),
        tlv(0x31, &[tlv(4, b"x"), vec![5, 0]].concat()),
    ]);
    for bad in [false, true] {
        let signer = |ski: bool, bad: bool| {
            seq(&[
                vec![2, 1, if ski { 3 } else { 1 }],
                if ski {
                    tlv(0x80, b"key-id")
                } else {
                    seq(&[seq(&[]), vec![2, 1, 1]])
                },
                alg.clone(),
                tlv(0xa0, &attr),
                sigalg.clone(),
                tlv(if bad { 5 } else { 4 }, b"sig"),
                tlv(0xa1, &unsigned),
            ])
        };
        let cms = seq(&[
            oid(cms::SIGNED_DATA),
            tlv(
                0xa0,
                &seq(&[
                    vec![2, 1, 3],
                    tlv(0x31, &alg),
                    seq(&[oid(&[42, 3, 7]), tlv(0xa0, &tlv(4, b"hello"))]),
                    tlv(0x31, &[signer(false, bad), signer(true, false)].concat()),
                ]),
            ),
        ]);
        let name = if bad {
            "parse-signer-bad-signature-tag.der"
        } else {
            "parse-signer-views.der"
        };
        std::fs::write(dir.join(name), cms).unwrap();
    }
}

// Preserve the original authenticated attributes and signature while extending
// only unsigned metadata. This isolates unknown-OID handling from cryptography.
fn write_long_oid(dir: &std::path::Path) {
    let source = std::fs::read(dir.join("good-pe64.exe")).unwrap();
    let pe_offset = u32::from_le_bytes(source[60..64].try_into().unwrap()) as usize;
    let directory = pe_offset + 24 + 112 + 32;
    let offset = u32::from_le_bytes(source[directory..directory + 4].try_into().unwrap()) as usize;
    let mut rest = &source[offset + 8..];
    let outer = der::take(&mut rest).unwrap().children().unwrap();
    let mut sd = der::one(outer[1].body, 0x30).unwrap().children().unwrap();
    let si = sd.last().unwrap().children().unwrap()[0]
        .children()
        .unwrap();
    for bad in [false, true] {
        let mut id = vec![1; 41];
        id[0] = if bad { 0x80 } else { 42 };
        let mut signer: Vec<_> = si.iter().map(|n| n.full.to_vec()).collect();
        signer.push(tlv(0xa1, &attr(&id, vec![5, 0])));
        let signer_set = tlv(0x31, &seq(&signer));
        sd.pop();
        let mut fields: Vec<_> = sd.iter().map(|n| n.full.to_vec()).collect();
        fields.push(signer_set);
        let cms = seq(&[outer[0].full.to_vec(), tlv(0xa0, &seq(&fields))]);
        let mut table = ((8 + cms.len()) as u32).to_le_bytes().to_vec();
        table.extend([0, 2, 2, 0]);
        table.extend(cms);
        table.resize((table.len() + 7) & !7, 0);
        let mut bytes = source[..offset].to_vec();
        bytes[directory + 4..directory + 8].copy_from_slice(&(table.len() as u32).to_le_bytes());
        bytes.extend(table);
        let name = if bad {
            "bad-long-attribute-oid.exe"
        } else {
            "good-long-attribute-oid.exe"
        };
        std::fs::write(dir.join(name), bytes).unwrap();
        // Restore the signer-set node for the next independent mutation.
        sd = der::one(outer[1].body, 0x30).unwrap().children().unwrap();
    }
}
