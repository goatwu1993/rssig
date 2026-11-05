//! Deterministic inspection-only envelopes; no cryptographic assertions.
use super::*;
pub(super) fn write(dir: &std::path::Path) {
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
