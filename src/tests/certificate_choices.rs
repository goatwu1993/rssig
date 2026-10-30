//! Reproduce optional CertificateChoices without redistributing Microsoft binaries.
use super::*;

fn fields(bytes: &[u8]) -> Vec<Vec<u8>> {
    der::one(bytes, 0x30)
        .unwrap()
        .children()
        .unwrap()
        .iter()
        .map(|n| n.full.to_vec())
        .collect()
}

fn change_signed_data(bytes: &[u8], edit: impl FnOnce(&mut Vec<Vec<u8>>)) -> Vec<u8> {
    let mut outer = fields(bytes);
    let mut sd = fields(der::one(&outer[1], 0xa0).unwrap().body);
    edit(&mut sd);
    outer[1] = tlv(0xa0, &seq(&sd));
    seq(&outer)
}

fn add_choice(sd: &mut [Vec<u8>], choice: &[u8], remove_signer: bool) {
    let certs = der::one(&sd[3], 0xa0).unwrap().children().unwrap();
    let mut bytes: Vec<u8> = certs
        .iter()
        .filter(|n| !remove_signer || n.full != tsa_identity().cert.to_der().unwrap())
        .flat_map(|n| n.full.iter().copied())
        .collect();
    bytes.extend(choice);
    sd[3] = tlv(0xa0, &bytes);
}

pub(super) fn write(dir: &std::path::Path) {
    // RFC 5652 section 12.2, with public deterministic test keys. This
    // attribute certificate is transported only, never a trust candidate.
    let id = identity();
    let names = tlv(0xa4, &id.cert.tbs_certificate.subject.to_der().unwrap());
    let alg = id.cert.signature_algorithm.to_der().unwrap();
    let info = seq(&[
        tlv(0xa1, &names),
        seq(&[names]),
        alg.clone(),
        vec![2, 1, 42],
        seq(&[
            tm(NOW - 100).to_der().unwrap(),
            tm(NOW + 100).to_der().unwrap(),
        ]),
        seq(&[attr(&[42, 3, 4], tlv(0x0c, b"test-only attribute"))]),
    ]);
    let signature: Signature = id.root_key.sign(&info);
    let choice = tlv(
        0xa1,
        &[
            info,
            alg,
            BitString::from_bytes(signature.to_der().as_bytes())
                .unwrap()
                .to_der()
                .unwrap(),
        ]
        .concat(),
    );
    std::fs::write(dir.join("attribute-certificate-v1.der"), &choice).unwrap();
    for fault in [
        "good",
        "der",
        "tag",
        "signature",
        "no-signer",
        "fractional",
        "fractional-future",
        "fractional-expired",
        "fractional-noncanonical",
    ] {
        let pe = std::fs::read(dir.join("good-rfc3161.exe")).unwrap();
        let parsed = pe::Pe::parse(&pe).unwrap();
        let cms = change_signed_data(parsed.certificates().unwrap()[0], |sd| {
            if fault == "no-signer" {
                add_choice(sd, &[], true);
            }
            let si = der::one(&sd[4], 0x31).unwrap().body;
            let mut signer = fields(si);
            let mut attribute = fields(der::one(&signer[6], 0xa1).unwrap().body);
            let token = der::one(&attribute[1], 0x31).unwrap().body;
            let token = change_signed_data(token, |token| {
                let mut choice = choice.clone();
                if fault == "der" {
                    choice[2] = 0xff;
                }
                if fault == "tag" {
                    choice[0] = 0xa4;
                }
                add_choice(token, &choice, fault == "no-signer");
                if fault.starts_with("fractional") {
                    let time = match fault {
                        "fractional-future" => NOW,
                        "fractional-expired" => NOW + 10000,
                        _ => NOW - 1,
                    };
                    let mut ci = fields(&token[2]);
                    let octets = der::one(der::one(&ci[1], 0xa0).unwrap().body, 4).unwrap();
                    let mut info = fields(octets.body);
                    let encoded = tm(time).to_der().unwrap();
                    let mut text = der::one(&encoded, 0x18).unwrap().body[..14].to_vec();
                    text.extend(if fault == "fractional-noncanonical" {
                        b".50Z".as_slice()
                    } else {
                        b".5Z".as_slice()
                    });
                    info[4] = tlv(0x18, &text);
                    let info = seq(&info);
                    ci[1] = tlv(0xa0, &tlv(4, &info));
                    token[2] = seq(&ci);
                    token[4] = tlv(
                        0x31,
                        &signer_info(&tsa_identity(), &info, Some(cms::TST_INFO), vec![], vec![]),
                    );
                }
                if fault == "signature" {
                    let mut si = fields(der::one(&token[4], 0x31).unwrap().body);
                    *si[5].last_mut().unwrap() ^= 1;
                    token[4] = tlv(0x31, &seq(&si));
                }
            });
            attribute[1] = tlv(0x31, &token);
            signer[6] = tlv(0xa1, &seq(&attribute));
            sd[4] = tlv(0x31, &seq(&signer));
        });
        let name = if fault == "good" {
            "good-rfc3161-certificate-choice.exe".into()
        } else if fault == "fractional" {
            "good-rfc3161-fractional.exe".into()
        } else if fault.starts_with("fractional-") {
            format!("bad-rfc3161-{fault}.exe")
        } else {
            format!("bad-rfc3161-certificate-choice-{fault}.exe")
        };
        std::fs::write(dir.join(name), attach(base_pe(true), &cms, true)).unwrap();
    }
    let pe = std::fs::read(dir.join("good-pe64.exe")).unwrap();
    let parsed = pe::Pe::parse(&pe).unwrap();
    let cms = change_signed_data(parsed.certificates().unwrap()[0], |sd| {
        add_choice(sd, &choice, false)
    });
    std::fs::write(
        dir.join("good-pe-certificate-choice.exe"),
        attach(base_pe(true), &cms, true),
    )
    .unwrap();
}

#[test]
#[ignore = "regenerates certificate-choice fixtures; review binaries and update manifest"]
fn regenerate_certificate_choice_fixtures() {
    write(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"));
}
