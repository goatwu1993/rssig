//! Test-only script recipes; never execute fixture scripts.
use super::*;
use base64ct::{Base64, Encoding};

pub(super) const BODY: &str = "# rssig test-only\r\n# café 😀\r\n";
const UUID: &[u8] = &[
    0x1f, 0xcc, 0x3b, 0x60, 0x59, 0x4b, 0x08, 0x4e, 0xb7, 0x24, 0xd2, 0xc6, 0x29, 0x7e, 0xf3, 0x51,
];
fn algorithm(hash: crypto::Hash) -> Vec<u8> {
    match hash {
        crypto::Hash::Sha1 => seq(&[oid(&[43, 14, 3, 2, 26]), vec![5, 0]]),
        _ => {
            let suffix = match hash {
                crypto::Hash::Sha256 => 1,
                crypto::Hash::Sha384 => 2,
                crypto::Hash::Sha512 => 3,
                _ => unreachable!(),
            };
            seq(&[oid(&[96, 134, 72, 1, 101, 3, 4, 2, suffix]), vec![5, 0]])
        }
    }
}
fn content(body: &str, hash: crypto::Hash, fault: Option<&str>) -> Vec<u8> {
    let input: Vec<u8> = body.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut sip = vec![
        vec![2, 3, 1, 0, 0],
        tlv(4, UUID),
        vec![2, 1, 0],
        vec![2, 1, 0],
        vec![2, 1, 0],
        vec![2, 1, 0],
        vec![2, 1, 0],
    ];
    match fault {
        Some("version") => sip[0] = vec![2, 1, 1],
        Some("uuid") => sip[1] = tlv(4, &[0; 16]),
        Some("reserved") => sip[2] = vec![2, 1, 1],
        _ => {}
    }
    let sip_oid = if fault == Some("type") {
        oid(&[43, 6, 1, 4, 1, 130, 55, 2, 1, 15])
    } else {
        oid(&[43, 6, 1, 4, 1, 130, 55, 2, 1, 30])
    };
    seq(&[
        seq(&[sip_oid, seq(&sip)]),
        seq(&[algorithm(hash), tlv(4, &hash.digest(&input))]),
    ])
}
fn cms_for(body: &str, hash: crypto::Hash, fault: Option<&str>) -> Vec<u8> {
    let content = content(body, hash, fault);
    let si = signer_info(
        identity(),
        der::one(&content, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    signed_data(identity(), content, cms::INDIRECT, si)
}
fn block(signature: &[u8]) -> String {
    let mut block = String::from("\r\n# SIG # Begin signature block\r\n");
    let b64 = Base64::encode_string(signature);
    for chunk in b64.as_bytes().chunks(64) {
        block.push_str("# ");
        block.push_str(std::str::from_utf8(chunk).unwrap());
        block.push_str("\r\n");
    }
    block.push_str("# SIG # End signature block\r\n");
    block
}
pub(super) fn write(dir: &std::path::Path) {
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    let signature = cms_for(BODY, crypto::Hash::Sha256, None);
    let good = format!("{BODY}{}", block(&signature));
    write("good-powershell.ps1", good.as_bytes());
    write(
        "bad-powershell-payload-no-crlf.ps1",
        good.replace(
            "\r\n# SIG # End signature block",
            "# SIG # End signature block",
        )
        .as_bytes(),
    );
    write(
        "powershell-binary-precedence.ps1",
        &std::fs::read(dir.join("good-pe64.exe")).unwrap(),
    );
    write("good-powershell.psm1", good.as_bytes());
    write("good-powershell.psd1", good.as_bytes());
    write("powershell-misnamed.bin", good.as_bytes());
    write(
        "bad-powershell-digest.ps1",
        good.replacen("test-only", "Test-only", 1).as_bytes(),
    );
    write(
        "bad-powershell-line-endings.ps1",
        good.replacen(BODY, &BODY.replace("\r\n", "\n"), 1)
            .as_bytes(),
    );
    let mut bad_sig = signature.clone();
    *bad_sig.last_mut().unwrap() ^= 1;
    write(
        "bad-powershell-cms-signature.ps1",
        format!("{BODY}{}", block(&bad_sig)).as_bytes(),
    );
    for (name, body) in [
        ("good-powershell-lf.ps1", BODY.replace("\r\n", "\n")),
        ("good-powershell-no-newline.ps1", "# test-only".into()),
        ("good-powershell-empty.ps1", String::new()),
    ] {
        write(
            name,
            format!(
                "{body}{}",
                block(&cms_for(&body, crypto::Hash::Sha256, None))
            )
            .as_bytes(),
        );
    }
    let bom_body = format!("\u{feff}{BODY}");
    let bom_good = format!(
        "{bom_body}{}",
        block(&cms_for(&bom_body, crypto::Hash::Sha256, None))
    );
    write("good-powershell-utf8-bom.ps1", bom_good.as_bytes());
    write(
        "good-powershell-utf16le.ps1",
        &bom_good
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    write(
        "good-powershell-utf16be.ps1",
        &bom_good
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>(),
    );
    write(
        "bad-powershell-missing-bom.ps1",
        bom_good.trim_start_matches('\u{feff}').as_bytes(),
    );
    for (name, hash) in [
        ("good-powershell-sha384.ps1", crypto::Hash::Sha384),
        ("good-powershell-sha512.ps1", crypto::Hash::Sha512),
        ("legacy-powershell-sha1.ps1", crypto::Hash::Sha1),
    ] {
        write(
            name,
            format!("{BODY}{}", block(&cms_for(BODY, hash, None))).as_bytes(),
        );
    }
    for fault in ["version", "uuid", "reserved", "type"] {
        write(
            &format!("bad-powershell-sip-{fault}.ps1"),
            format!(
                "{BODY}{}",
                block(&cms_for(BODY, crypto::Hash::Sha256, Some(fault)))
            )
            .as_bytes(),
        );
    }
    for (name, source) in [
        ("good-powershell-nested.ps1", "good-nested.exe"),
        ("good-powershell-rfc3161.ps1", "good-rfc3161.exe"),
        (
            "good-powershell-countersignature.ps1",
            "good-countersignature.exe",
        ),
        (
            "bad-powershell-timestamp-imprint.ps1",
            "bad-timestamp-imprint.exe",
        ),
        ("bad-powershell-nested.ps1", "bad-nested-signature.exe"),
    ] {
        let pe_bytes = std::fs::read(dir.join(source)).unwrap();
        let pe = pe::Pe::parse(&pe_bytes).unwrap();
        let cms = msi_fixtures::convert_cms(
            pe.certificates().unwrap()[0],
            &content(BODY, crypto::Hash::Sha256, None),
        );
        write(name, format!("{BODY}{}", block(&cms)).as_bytes());
    }
    write("unsigned-powershell.ps1", BODY.as_bytes());
    write(
        "bad-powershell-duplicate.ps1",
        format!("{good}{}", block(&signature)).as_bytes(),
    );
    write(
        "bad-powershell-trailing.ps1",
        format!("{good}# appended\r\n").as_bytes(),
    );
    write(
        "bad-powershell-missing-end.ps1",
        good.replace("# SIG # End signature block\r\n", "")
            .as_bytes(),
    );
    write(
        "bad-powershell-missing-begin.ps1",
        good.replace("# SIG # Begin signature block\r\n", "")
            .as_bytes(),
    );
    write(
        "bad-powershell-marker-lf.ps1",
        good.replace("\r\n# SIG #", "\n# SIG #").as_bytes(),
    );
    write(
        "bad-powershell-base64.ps1",
        good.replacen("# MI", "# !I", 1).as_bytes(),
    );
    write(
        "bad-powershell-comment.ps1",
        good.replacen("# MI", "  MI", 1).as_bytes(),
    );
    write(
        "bad-powershell-empty-signature.ps1",
        format!("{BODY}{}", block(&[])).as_bytes(),
    );
    let mut cms_trailer = signature.clone();
    cms_trailer.push(0);
    write(
        "bad-powershell-cms-trailing.ps1",
        format!("{BODY}{}", block(&cms_trailer)).as_bytes(),
    );
    write(
        "bad-powershell-malformed-cms.ps1",
        format!("{BODY}{}", block(&[0, 0])).as_bytes(),
    );
    let mut utf8 = good.as_bytes().to_vec();
    utf8[0] = 255;
    write("bad-powershell-utf8.ps1", &utf8);
    let mut utf16: Vec<_> = bom_good.encode_utf16().flat_map(u16::to_le_bytes).collect();
    utf16.pop();
    write("bad-powershell-odd-utf16.ps1", &utf16);
    let mut utf16: Vec<_> = bom_good.encode_utf16().flat_map(u16::to_le_bytes).collect();
    utf16[2..4].copy_from_slice(&0xd800u16.to_le_bytes());
    write("bad-powershell-surrogate.ps1", &utf16);
    write(
        "bad-powershell-no-utf16-bom.ps1",
        &good
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
}
