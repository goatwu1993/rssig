//! Inert PowerShell XML text; never load or execute these fixtures.
use super::*;
use base64ct::{Base64, Encoding};
const BODY: &str = "<Types />\r\n";
fn block(cms: &[u8]) -> String {
    let encoded = Base64::encode_string(cms);
    let mut text = String::from("\r\n<!-- SIG # Begin signature block -->\r\n");
    for chunk in encoded.as_bytes().chunks(64) {
        text.push_str("<!-- ");
        text.push_str(std::str::from_utf8(chunk).unwrap());
        text.push_str(" -->\r\n");
    }
    text.push_str("<!-- SIG # End signature block -->\r\n");
    text
}
fn signed(body: &str, hash: crypto::Hash) -> String {
    format!(
        "{body}{}",
        block(&powershell_fixtures::cms_for(body, hash, None))
    )
}
pub(super) fn write(dir: &std::path::Path) {
    let write = |name: &str, b: &[u8]| std::fs::write(dir.join(name), b).unwrap();
    let hash = crypto::Hash::Sha256;
    let good = signed(BODY, hash);
    write("good-psxml.ps1xml", good.as_bytes());
    write("psxml-misnamed.bin", good.as_bytes());
    write(
        "bad-psxml-digest.ps1xml",
        good.replacen("Types", "TypeS", 1).as_bytes(),
    );
    write(
        "bad-psxml-line-endings.ps1xml",
        good.replacen(BODY, "<Types />\n", 1).as_bytes(),
    );
    write(
        "good-psxml-lf.ps1xml",
        signed("<Types />\n", hash).as_bytes(),
    );
    let ascii_bom = signed(&format!("\u{feff}{BODY}"), hash);
    write("good-psxml-ascii-bom.ps1xml", ascii_bom.as_bytes());
    write(
        "bad-psxml-missing-bom.ps1xml",
        ascii_bom.trim_start_matches('\u{feff}').as_bytes(),
    );
    let unicode = signed("\u{feff}<Types><!-- café 😀 --></Types>\r\n", hash);
    write("good-psxml-utf8-bom.ps1xml", unicode.as_bytes());
    write(
        "good-psxml-utf16le.ps1xml",
        &unicode
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    write(
        "good-psxml-utf16be.ps1xml",
        &unicode
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>(),
    );
    write(
        "bad-psxml-ambiguous-utf8.ps1xml",
        unicode.trim_start_matches('\u{feff}').as_bytes(),
    );
    write("unsigned.ps1xml", BODY.as_bytes());
    for (name, text) in [
        (
            "bad-psxml-duplicate.ps1xml",
            format!("{good}{}", &good[BODY.len()..]),
        ),
        (
            "bad-psxml-trailing.ps1xml",
            format!("{good}<!-- unsigned -->\r\n"),
        ),
        (
            "bad-psxml-missing-end.ps1xml",
            good.replace("<!-- SIG # End signature block -->\r\n", ""),
        ),
        (
            "bad-psxml-marker-lf.ps1xml",
            good.replace("\r\n<!-- SIG #", "\n<!-- SIG #"),
        ),
        (
            "bad-psxml-payload-no-crlf.ps1xml",
            good.replace("\r\n<!-- SIG # End", "<!-- SIG # End"),
        ),
        (
            "bad-psxml-comment-end.ps1xml",
            good.replacen(" -->\r\n<!-- SIG # End", "\r\n<!-- SIG # End", 1),
        ),
        (
            "bad-psxml-base64.ps1xml",
            good.replacen("<!-- MI", "<!-- !I", 1),
        ),
    ] {
        write(name, text.as_bytes());
    }
    for (name, h) in [
        ("good-psxml-sha384.ps1xml", crypto::Hash::Sha384),
        ("good-psxml-sha512.ps1xml", crypto::Hash::Sha512),
        ("legacy-psxml-sha1.ps1xml", crypto::Hash::Sha1),
    ] {
        write(name, signed(BODY, h).as_bytes());
    }
    let cms = powershell_fixtures::cms_for(BODY, hash, None);
    let mut bad = cms.clone();
    *bad.last_mut().unwrap() ^= 1;
    write(
        "bad-psxml-cms-signature.ps1xml",
        format!("{BODY}{}", block(&bad)).as_bytes(),
    );
    let mut bad = cms;
    bad.push(0);
    write(
        "bad-psxml-cms-trailing.ps1xml",
        format!("{BODY}{}", block(&bad)).as_bytes(),
    );
    write(
        "bad-psxml-sip.ps1xml",
        format!(
            "{BODY}{}",
            block(&powershell_fixtures::cms_for(BODY, hash, Some("type")))
        )
        .as_bytes(),
    );
    write(
        "bad-psxml-hash-style.ps1xml",
        format!(
            "{BODY}{}",
            powershell_fixtures::block(&powershell_fixtures::cms_for(BODY, hash, None))
        )
        .as_bytes(),
    );
    let mut b = good.as_bytes().to_vec();
    b[0] = 255;
    write("bad-psxml-encoding.ps1xml", &b);
    let mut b: Vec<_> = unicode.encode_utf16().flat_map(u16::to_le_bytes).collect();
    b.pop();
    write("bad-psxml-odd-utf16.ps1xml", &b);
    for (name, source) in [
        ("good-psxml-nested.ps1xml", "good-nested.exe"),
        ("good-psxml-rfc3161.ps1xml", "good-rfc3161.exe"),
        (
            "good-psxml-countersignature.ps1xml",
            "good-countersignature.exe",
        ),
        (
            "bad-psxml-timestamp-imprint.ps1xml",
            "bad-timestamp-imprint.exe",
        ),
    ] {
        let pe = std::fs::read(dir.join(source)).unwrap();
        let pe = pe::Pe::parse(&pe).unwrap();
        let cms = msi_fixtures::convert_cms(
            pe.certificates().unwrap()[0],
            &powershell_fixtures::content(BODY, hash, None),
        );
        write(name, format!("{BODY}{}", block(&cms)).as_bytes());
    }
}
