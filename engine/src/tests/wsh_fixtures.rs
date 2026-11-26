//! Independent WSH signature recipes using public deterministic test-only keys.
//! Fixtures contain comments, empty jobs, or an empty encoded-text envelope. Never execute them.
use super::*;
use base64ct::{Base64, Encoding};

#[derive(Clone, Copy)]
enum Style {
    Vb,
    Js,
    Wsf,
}
impl Style {
    fn ext(self) -> &'static str {
        match self {
            Self::Vb => "vbs",
            Self::Js => "js",
            Self::Wsf => "wsf",
        }
    }
    fn markers(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Vb => (
                "'' SIG '' Begin signature block",
                "'' SIG '' End signature block",
                "'' SIG '' ",
            ),
            Self::Js => (
                "// SIG // Begin signature block",
                "// SIG // End signature block",
                "// SIG // ",
            ),
            Self::Wsf => ("<signature>", "</signature>", "** SIG ** "),
        }
    }
    fn uuid(self) -> [u8; 16] {
        match self {
            Self::Vb => [
                0x4e, 0xf0, 0x29, 0x16, 0x99, 0x27, 0xb5, 0x4d, 0x8f, 0xe5, 0xac, 0xe1, 0x0f, 0x17,
                0xeb, 0xab,
            ],
            Self::Js => [
                0x10, 0xe0, 0xc9, 0x06, 0xce, 0x38, 0xd4, 0x11, 0xa2, 0xa3, 0, 0x10, 0x4b, 0xd3,
                0x50, 0x90,
            ],
            Self::Wsf => [
                0x70, 0x05, 0x61, 0x1a, 0xce, 0x38, 0xd4, 0x11, 0xa2, 0xa3, 0, 0x10, 0x4b, 0xd3,
                0x50, 0x90,
            ],
        }
    }
}
fn body(style: Style, unicode: bool) -> String {
    let text = if unicode {
        "rssig test-only café 😀"
    } else {
        "rssig test-only"
    };
    match style {
        Style::Vb => format!("' {text}\r\n"),
        Style::Js => format!("// {text}\r\n"),
        Style::Wsf => format!("<job id=\"rssig\"><!-- {text} --></job>\r\n"),
    }
}
fn position(body: &str, style: Style) -> usize {
    if matches!(style, Style::Wsf) {
        body.rfind("</job>").unwrap()
    } else {
        body.len()
    }
}
fn content(body: &str, style: Style, hash: crypto::Hash, fault: &str) -> Vec<u8> {
    let mut input: Vec<_> = body.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let pos = body[..position(body, style)].encode_utf16().count() as u32;
    if fault != "no-offset" {
        input.extend((pos + u32::from(fault == "offset")).to_le_bytes());
    }
    let mut sip = vec![
        vec![2, 1, 1],
        tlv(4, &style.uuid()),
        vec![2, 1, 0],
        vec![2, 1, 0],
        vec![2, 1, 0],
        vec![2, 1, 0],
        vec![2, 1, 0],
    ];
    match fault {
        "sip-version" => sip[0] = vec![2, 1, 2],
        "sip-uuid" => sip[1] = tlv(4, &[0; 16]),
        "sip-cross" => {
            sip[1] = tlv(
                4,
                &match style {
                    Style::Vb => Style::Js.uuid(),
                    _ => Style::Vb.uuid(),
                },
            )
        }
        "sip-reserved" => sip[2] = vec![2, 1, 1],
        _ => {}
    }
    let alg = if hash == crypto::Hash::Sha1 {
        seq(&[oid(&[43, 14, 3, 2, 26]), vec![5, 0]])
    } else {
        let end = match hash {
            crypto::Hash::Sha256 => 1,
            crypto::Hash::Sha384 => 2,
            crypto::Hash::Sha512 => 3,
            _ => unreachable!(),
        };
        seq(&[oid(&[96, 134, 72, 1, 101, 3, 4, 2, end]), vec![5, 0]])
    };
    let ty = if fault == "sip-type" {
        vec![43, 6, 1, 4, 1, 130, 55, 2, 1, 15]
    } else {
        vec![43, 6, 1, 4, 1, 130, 55, 2, 1, 30]
    };
    seq(&[
        seq(&[oid(&ty), seq(&sip)]),
        seq(&[alg, tlv(4, &hash.digest(&input))]),
    ])
}
fn signature(
    dir: &std::path::Path,
    body: &str,
    style: Style,
    hash: crypto::Hash,
    fault: &str,
) -> Vec<u8> {
    let content = content(body, style, hash, fault);
    let source = match fault {
        "nested" => Some("good-nested.exe"),
        "rfc3161" => Some("good-rfc3161.exe"),
        "countersignature" => Some("good-countersignature.exe"),
        "timestamp-imprint" => Some("bad-timestamp-imprint.exe"),
        "bad-nested" => Some("bad-nested-signature.exe"),
        _ => None,
    };
    let mut cms = if let Some(source) = source {
        let bytes = std::fs::read(dir.join(source)).unwrap();
        let pe = pe::Pe::parse(&bytes).unwrap();
        msi_fixtures::convert_cms(pe.certificates().unwrap()[0], &content)
    } else {
        let si = signer_info(
            identity(),
            der::one(&content, 0x30).unwrap().body,
            Some(cms::INDIRECT),
            vec![],
            vec![],
        );
        signed_data(identity(), content, cms::INDIRECT, si)
    };
    if fault == "cms-signature" {
        *cms.last_mut().unwrap() ^= 1;
    }
    if fault == "cms-trailing" {
        cms.push(0);
    }
    if fault == "malformed-cms" {
        cms = vec![0, 0];
    }
    cms
}
fn block(style: Style, cms: &[u8]) -> String {
    let (begin, end, prefix) = style.markers();
    let mut out = format!("\r\n{begin}\r\n");
    for chunk in Base64::encode_string(cms).as_bytes().chunks(64) {
        out.push_str(prefix);
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push_str("\r\n");
    }
    out.push_str(end);
    out.push_str("\r\n");
    out
}
fn signed(
    dir: &std::path::Path,
    body: &str,
    style: Style,
    hash: crypto::Hash,
    fault: &str,
) -> String {
    let at = position(body, style);
    format!(
        "{}{}{}",
        &body[..at],
        block(style, &signature(dir, body, style, hash, fault)),
        &body[at..]
    )
}
pub(super) fn write(dir: &std::path::Path) {
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    let h = crypto::Hash::Sha256;
    for style in [Style::Vb, Style::Js, Style::Wsf] {
        let ext = style.ext();
        let basic = body(style, false);
        let good = signed(dir, &basic, style, h, "");
        write(&format!("good-wsh.{ext}"), good.as_bytes());
        write(&format!("unsigned-wsh.{ext}"), basic.as_bytes());
        write(&format!("wsh-jsign-input.{ext}"), basic.as_bytes());
        write(
            &format!("bad-wsh-digest.{ext}"),
            good.replacen("test-only", "Test-only", 1).as_bytes(),
        );
        write(&format!("wsh-misnamed-{ext}.bin"), good.as_bytes());
        let unicode = signed(dir, &body(style, true), style, h, "");
        write(
            &format!("good-wsh-utf8-bom.{ext}"),
            format!("\u{feff}{unicode}").as_bytes(),
        );
        write(
            &format!("wsh-jsign-utf8-bom-input.{ext}"),
            format!("\u{feff}{}", body(style, true)).as_bytes(),
        );
        for (name, little) in [("utf16le", true), ("utf16be", false)] {
            let bytes: Vec<_> = format!("\u{feff}{unicode}")
                .encode_utf16()
                .flat_map(|u| {
                    if little {
                        u.to_le_bytes()
                    } else {
                        u.to_be_bytes()
                    }
                })
                .collect();
            write(&format!("good-wsh-{name}.{ext}"), &bytes);
        }
        for (name, hash) in [
            ("sha384", crypto::Hash::Sha384),
            ("sha512", crypto::Hash::Sha512),
            ("sha1", crypto::Hash::Sha1),
        ] {
            write(
                &format!("good-wsh-{name}.{ext}"),
                signed(dir, &basic, style, hash, "").as_bytes(),
            );
        }
        for fault in [
            "sip-type",
            "sip-version",
            "sip-uuid",
            "sip-cross",
            "sip-reserved",
            "offset",
            "no-offset",
            "cms-signature",
            "cms-trailing",
            "malformed-cms",
            "timestamp-imprint",
            "bad-nested",
        ] {
            write(
                &format!("bad-wsh-{fault}.{ext}"),
                signed(dir, &basic, style, h, fault).as_bytes(),
            );
        }
        let prefix = style.markers().2;
        let mut lines: Vec<String> = good.split("\r\n").map(str::to_owned).collect();
        let at = lines
            .iter()
            .position(|l| l.starts_with(&format!("{prefix}MI")))
            .unwrap();
        let next = lines.remove(at + 1);
        lines[at].push_str(&next[prefix.len()..]);
        write(
            &format!("bad-wsh-long-line.{ext}"),
            lines.join("\r\n").as_bytes(),
        );
        for fault in ["nested", "rfc3161", "countersignature"] {
            write(
                &format!("good-wsh-{fault}.{ext}"),
                signed(dir, &basic, style, h, fault).as_bytes(),
            );
        }
        let (begin, end, prefix) = style.markers();
        for (name, text) in [
            ("missing-begin", good.replacen(begin, "", 1)),
            ("missing-end", good.replacen(end, "", 1)),
            (
                "duplicate",
                format!(
                    "{good}{}",
                    block(style, &signature(dir, &basic, style, h, ""))
                ),
            ),
            (
                "marker-lf",
                good.replacen(&format!("\r\n{begin}\r\n"), &format!("\n{begin}\n"), 1),
            ),
            (
                "base64",
                good.replacen(&format!("{prefix}MI"), &format!("{prefix}!I"), 1),
            ),
            ("empty-signature", {
                let at = position(&basic, style);
                format!("{}{}{}", &basic[..at], block(style, &[]), &basic[at..])
            }),
        ] {
            write(&format!("bad-wsh-{name}.{ext}"), text.as_bytes());
        }
    }
    for (ext, style) in [("vbe", Style::Vb), ("jse", Style::Js)] {
        let empty = "#@~^AAAAAA==AAAAAA==^#~@\r\n";
        let good = signed(dir, empty, style, h, "");
        write(&format!("good-wsh.{ext}"), good.as_bytes());
        write(&format!("wsh-jsign-input.{ext}"), empty.as_bytes());
        write(
            &format!("bad-wsh-digest.{ext}"),
            good.replacen("AAAAAA==", "BAAAAA==", 1).as_bytes(),
        );
    }
    let vb = body(Style::Vb, false);
    let vb_good = signed(dir, &vb, Style::Vb, h, "");
    let js = body(Style::Js, false);
    let js_good = signed(dir, &js, Style::Js, h, "");
    write(
        "bad-wsh-trailing.vbs",
        format!("{vb_good}' appended\r\n").as_bytes(),
    );
    write(
        "bad-wsh-trailing.js",
        format!("{js_good}// appended\r\n").as_bytes(),
    );
    write("bad-wsh-wrong-style.js", vb_good.as_bytes());
    write(
        "bad-wsh-mixed.vbs",
        format!("{vb_good}{js_good}").as_bytes(),
    );
    for style in [Style::Vb, Style::Js] {
        let text = signed(dir, &body(style, true), style, h, "");
        write(
            &format!("bad-wsh-bomless-unicode.{}", style.ext()),
            text.as_bytes(),
        );
    }
    let wsf = body(Style::Wsf, false);
    let wsf_good = signed(dir, &wsf, Style::Wsf, h, "");
    write(
        "bad-wsh-cdata.wsf",
        format!("<job><script><![CDATA[{wsf_good}]]></script></job>").as_bytes(),
    );
    write(
        "good-wsh-bomless-unicode.wsf",
        signed(dir, &body(Style::Wsf, true), Style::Wsf, h, "").as_bytes(),
    );
    write(
        "bad-wsh-xml.wsf",
        wsf_good.replacen("<job", "<jobs", 1).as_bytes(),
    );
    write(
        "bad-wsh-dtd.wsf",
        format!("<!DOCTYPE job SYSTEM \"file:///rssig-must-not-read\">{wsf_good}").as_bytes(),
    );
    write(
        "bad-wsh-placement.wsf",
        format!(
            "{wsf}{}",
            block(Style::Wsf, &signature(dir, &wsf, Style::Wsf, h, ""))
        )
        .as_bytes(),
    );
    write(
        "bad-wsh-tail.wsf",
        wsf_good.replace("</job>\r\n", "</job>\n").as_bytes(),
    );
    write(
        "bad-wsh-attributes.wsf",
        wsf_good
            .replace("<signature>", "<signature id=\"x\">")
            .as_bytes(),
    );
    write(
        "bad-wsh-nested-job.wsf",
        signed(
            dir,
            "<job><job/><!-- rssig --></job>\r\n",
            Style::Wsf,
            h,
            "",
        )
        .as_bytes(),
    );
    write(
        "bad-wsh-multijob.wsf",
        signed(
            dir,
            "<package><job/><!-- rssig --><job></job></package>\r\n",
            Style::Wsf,
            h,
            "",
        )
        .as_bytes(),
    );
    let mut b = vb_good.as_bytes().to_vec();
    b.insert(0, 0);
    write("bad-wsh-nul.vbs", &b);
    let mut b: Vec<_> = format!("\u{feff}{vb_good}")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    b.pop();
    write("bad-wsh-odd-utf16.vbs", &b);
    let mut b: Vec<_> = format!("\u{feff}{js_good}")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    b[2..4].copy_from_slice(&0xd800u16.to_le_bytes());
    write("bad-wsh-surrogate.js", &b);
    let mut b = wsf_good.as_bytes().to_vec();
    b[0] = 255;
    write("bad-wsh-utf8.wsf", &b);
    write(
        "wsh-binary-precedence.js",
        &std::fs::read(dir.join("good-pe64.exe")).unwrap(),
    );
}
