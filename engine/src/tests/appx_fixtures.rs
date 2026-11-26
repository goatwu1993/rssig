//! Independent ZIP and APPX digest recipes using public test-only keys.
use super::*;
use base64ct::{Base64, Encoding};
use std::io::Write;
const CT: &str = "[Content_Types].xml";
const BM: &str = "AppxBlockMap.xml";
const SIG: &str = "AppxSignature.p7x";
const MANIFEST: &str = "AppxManifest.xml";
const BUNDLE_MANIFEST: &str = "AppxMetadata/AppxBundleManifest.xml";
const CI: &str = "AppxMetadata/CodeIntegrity.cat";
const CONTENT_TYPES: &str = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"bin\" ContentType=\"application/octet-stream\"/><Default Extension=\"xml\" ContentType=\"application/vnd.ms-appx.manifest+xml\"/><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/><Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/><Override PartName=\"/AppxMetadata/CodeIntegrity.cat\" ContentType=\"application/vnd.ms-pkiseccat\"/></Types>";
#[derive(Clone)]
struct Part {
    name: String,
    data: Vec<u8>,
    compressed: Vec<u8>,
    method: u16,
    sizes: Vec<usize>,
    bad_crc: bool,
}
fn part(name: &str, data: &[u8], deflate: bool) -> Part {
    let mut sizes = Vec::new();
    let compressed = if deflate {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        for block in data.chunks(65536) {
            let start = encoder.get_ref().len();
            encoder.write_all(block).unwrap();
            encoder.flush().unwrap();
            sizes.push(encoder.get_ref().len() - start);
        }
        encoder.finish().unwrap()
    } else {
        data.to_vec()
    };
    Part {
        name: name.into(),
        data: data.to_vec(),
        compressed,
        method: if deflate { 8 } else { 0 },
        sizes,
        bad_crc: false,
    }
}
fn word(b: &mut Vec<u8>, v: u16) {
    b.extend(v.to_le_bytes());
}
fn dword(b: &mut Vec<u8>, v: u32) {
    b.extend(v.to_le_bytes());
}
fn qword(b: &mut Vec<u8>, v: u64) {
    b.extend(v.to_le_bytes());
}
fn zip(parts: &[Part], zip64: bool, descriptor: bool) -> (Vec<u8>, usize) {
    let mut b = Vec::new();
    let mut records = Vec::new();
    for p in parts {
        let offset = b.len();
        let crc = crc32fast::hash(&p.data) ^ u32::from(p.bad_crc);
        let flags = if descriptor { 8 } else { 0 };
        dword(&mut b, 0x04034b50);
        word(&mut b, if zip64 { 45 } else { 20 });
        word(&mut b, flags);
        word(&mut b, p.method);
        b.extend([0; 4]);
        dword(&mut b, if descriptor { 0 } else { crc });
        dword(
            &mut b,
            if descriptor {
                0
            } else {
                p.compressed.len() as u32
            },
        );
        dword(&mut b, if descriptor { 0 } else { p.data.len() as u32 });
        word(&mut b, p.name.len() as u16);
        word(&mut b, 0);
        b.extend(p.name.as_bytes());
        b.extend(&p.compressed);
        if descriptor {
            dword(&mut b, 0x08074b50);
            dword(&mut b, crc);
            dword(&mut b, p.compressed.len() as u32);
            dword(&mut b, p.data.len() as u32);
        }
        let mut c = Vec::new();
        dword(&mut c, 0x02014b50);
        word(&mut c, 45);
        word(&mut c, if zip64 { 45 } else { 20 });
        word(&mut c, flags);
        word(&mut c, p.method);
        c.extend([0; 4]);
        dword(&mut c, crc);
        dword(&mut c, p.compressed.len() as u32);
        dword(&mut c, p.data.len() as u32);
        word(&mut c, p.name.len() as u16);
        c.extend([0; 12]);
        dword(&mut c, offset as u32);
        c.extend(p.name.as_bytes());
        records.extend(c);
    }
    let cd = b.len();
    b.extend(&records);
    if zip64 {
        let off = b.len();
        dword(&mut b, 0x06064b50);
        qword(&mut b, 44);
        word(&mut b, 45);
        word(&mut b, 45);
        b.extend([0; 8]);
        qword(&mut b, parts.len() as u64);
        qword(&mut b, parts.len() as u64);
        qword(&mut b, records.len() as u64);
        qword(&mut b, cd as u64);
        dword(&mut b, 0x07064b50);
        dword(&mut b, 0);
        qword(&mut b, off as u64);
        dword(&mut b, 1);
    }
    dword(&mut b, 0x06054b50);
    b.extend([0; 4]);
    word(&mut b, if zip64 { 65535 } else { parts.len() as u16 });
    word(&mut b, if zip64 { 65535 } else { parts.len() as u16 });
    dword(
        &mut b,
        if zip64 {
            u32::MAX
        } else {
            records.len() as u32
        },
    );
    dword(&mut b, if zip64 { u32::MAX } else { cd as u32 });
    word(&mut b, 0);
    (b, cd)
}
fn manifest(publisher: &str) -> String {
    format!(
        "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\"><Identity Name=\"rssig.test\" Publisher=\"{publisher}\" Version=\"1.0.0.0\" ProcessorArchitecture=\"neutral\"/></Package>"
    )
}
fn block_map(parts: &[Part], hash: crypto::Hash, bundle: bool) -> String {
    let method = match hash {
        crypto::Hash::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        crypto::Hash::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        crypto::Hash::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        _ => unreachable!(),
    };
    let mut s = format!(
        "<BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" HashMethod=\"{method}\">"
    );
    for p in parts {
        if [CT, BM, SIG, CI].contains(&p.name.as_str())
            || (bundle && [".appx", ".msix"].iter().any(|ext| p.name.ends_with(ext)))
        {
            continue;
        }
        s.push_str(&format!(
            "<File Name=\"{}\" Size=\"{}\" LfhSize=\"{}\">",
            p.name.replace('/', "\\"),
            p.data.len(),
            30 + p.name.len()
        ));
        for (i, b) in p.data.chunks(65536).enumerate() {
            s.push_str(&format!(
                "<Block Hash=\"{}\"{} />",
                Base64::encode_string(&hash.digest(b)),
                if p.method == 8 {
                    format!(" Size=\"{}\"", p.sizes[i])
                } else {
                    String::new()
                }
            ));
        }
        s.push_str("</File>");
    }
    s.push_str("</BlockMap>");
    s
}
fn content(hash: crypto::Hash, bundle: &[u8], is_bundle: bool) -> Vec<u8> {
    let suffix = match hash {
        crypto::Hash::Sha256 => 1,
        crypto::Hash::Sha384 => 2,
        crypto::Hash::Sha512 => 3,
        _ => unreachable!(),
    };
    seq(&[
        seq(&[
            oid(&[43, 6, 1, 4, 1, 130, 55, 2, 1, 30]),
            seq(&[
                vec![2, 4, 1, 1, 0, 0],
                tlv(
                    4,
                    if is_bundle {
                        &[
                            0xb3, 0x58, 0x5f, 0x0f, 0xde, 0xaa, 0x9a, 0x4b, 0xa4, 0x34, 0x95, 0x74,
                            0x2d, 0x92, 0xec, 0xeb,
                        ]
                    } else {
                        &[
                            0x4b, 0xdf, 0xc5, 0x0a, 7, 0xce, 0xe2, 0x4d, 0xb7, 0x6e, 0x23, 0xc8,
                            0x39, 0xa0, 0x9f, 0xd1,
                        ]
                    },
                ),
                vec![2, 1, 0],
                vec![2, 1, 0],
                vec![2, 1, 0],
                vec![2, 1, 0],
                vec![2, 1, 0],
            ]),
        ]),
        seq(&[
            seq(&[oid(&[96, 134, 72, 1, 101, 3, 4, 2, suffix]), vec![5, 0]]),
            tlv(4, bundle),
        ]),
    ])
}
fn parts(fault: &str, hash: crypto::Hash) -> Vec<Part> {
    let publisher = if fault == "publisher" {
        "CN=other publisher"
    } else if fault == "external" {
        "CN=rssig independent MSI test signer"
    } else {
        "CN=rssig test publisher"
    };
    let payload = if fault == "multi" {
        vec![0x61; 70001]
    } else if fault == "empty" {
        vec![]
    } else {
        b"test".to_vec()
    };
    let mut p = vec![
        part(
            "data.bin",
            &payload,
            fault == "deflate" || fault == "multi" || fault == "compressed-size",
        ),
        part(
            MANIFEST,
            manifest(publisher)
                .replace(
                    "rssig.test",
                    if fault == "other-name" {
                        "other.test"
                    } else {
                        "rssig.test"
                    },
                )
                .replace("ProcessorArchitecture=\"neutral\"", match fault { "x64" => "ProcessorArchitecture=\"x64\"", "arm64" => "ProcessorArchitecture=\"arm64\"", _ => "ProcessorArchitecture=\"neutral\"" })
                .replace("/></Package>", if ["resource", "resource-boolean"].contains(&fault) { " ResourceId=\"en-us\"/><Properties><ResourcePackage>true</ResourcePackage></Properties></Package>" } else { "/></Package>" })
                .replace("<ResourcePackage>true</ResourcePackage>", if fault == "resource-boolean" { "<ResourcePackage>true<!--split-->false</ResourcePackage>" } else { "<ResourcePackage>true</ResourcePackage>" })
                .as_bytes(),
            false,
        ),
    ];
    if fault == "catalog" {
        p.push(part(
            CI,
            b"opaque test catalog bytes, not an individually verified catalog",
            false,
        ));
    }
    if fault == "bundle" {
        p.push(part(
            "AppxMetadata/AppxBundleManifest.xml",
            b"<Bundle />",
            false,
        ));
    }
    let mut map = block_map(&p, hash, false);
    if fault == "compressed-size" {
        let block = map.find("<Block Hash=").unwrap();
        let start = block + map[block..].find(" Size=\"").unwrap() + 7;
        let end = start + map[start..].find('"').unwrap();
        let value: usize = map[start..end].parse().unwrap();
        map.replace_range(start..end, &(value + 1).to_string());
    }
    if fault == "block-hash" {
        let start = map.find("Hash=\"").unwrap() + 6;
        map.replace_range(
            start..start + 1,
            if &map[start..start + 1] == "A" {
                "B"
            } else {
                "A"
            },
        );
    }
    if fault == "block-missing" {
        let start = map.find("<File").unwrap();
        let end = map[start..].find("</File>").unwrap() + start + 7;
        map.replace_range(start..end, "");
    }
    if fault == "block-extra" {
        map = map.replace(
            "</BlockMap>",
            "<File Name=\"extra.bin\" Size=\"0\" LfhSize=\"39\"/></BlockMap>",
        );
    }
    if fault == "lfh" {
        map = map.replacen("LfhSize=\"38\"", "LfhSize=\"39\"", 1);
    }
    if fault == "dtd" {
        map = format!("<!DOCTYPE BlockMap [<!ENTITY x 'x'>]>{map}");
    }
    if fault == "namespace" {
        map = map.replace("appx/2010/blockmap", "appx/2099/blockmap");
    }
    if fault == "block-algorithm" {
        map = map.replace("xmlenc#sha256", "xmlenc#sha1");
    }
    p.push(part(BM, map.as_bytes(), false));
    let ct = if fault == "content-types" {
        CONTENT_TYPES.replace(
            "application/vnd.ms-appx.signature",
            "application/not-signature",
        )
    } else {
        CONTENT_TYPES.into()
    };
    p.push(part(CT, ct.as_bytes(), false));
    p
}
fn package(dir: &std::path::Path, fault: &str, hash: crypto::Hash) -> Vec<u8> {
    let mut p = parts(fault, hash);
    let z64 = fault == "zip64";
    let dd = fault == "descriptor";
    let (unsigned, cd) = zip(&p, z64, dd);
    let mut bundle = b"APPX".to_vec();
    for (tag, bytes) in [
        (b"AXPC", &unsigned[..cd]),
        (b"AXCD", &unsigned[cd..]),
        (
            b"AXCT",
            p.iter().find(|p| p.name == CT).unwrap().data.as_slice(),
        ),
        (
            b"AXBM",
            p.iter().find(|p| p.name == BM).unwrap().data.as_slice(),
        ),
    ] {
        bundle.extend(tag);
        bundle.extend(hash.digest(bytes));
    }
    if let Some(c) = p.iter().find(|p| p.name == CI) {
        bundle.extend(b"AXCI");
        bundle.extend(hash.digest(&c.data));
    }
    if fault.starts_with("digest-") {
        let index = match fault {
            "digest-AXPC" => 0,
            "digest-AXCD" => 1,
            "digest-AXCT" => 2,
            _ => 3,
        };
        bundle[8 + index * (4 + hash.digest(b"").len())] ^= 1;
    }
    let content = content(hash, &bundle, false);
    let mut cms = if ["nested", "rfc3161", "countersignature", "timestamp-imprint"].contains(&fault)
    {
        let name = match fault {
            "nested" => "good-nested.exe",
            "rfc3161" => "good-rfc3161.exe",
            "countersignature" => "good-countersignature.exe",
            _ => "bad-timestamp-imprint.exe",
        };
        let b = std::fs::read(dir.join(name)).unwrap();
        let pe = pe::Pe::parse(&b).unwrap();
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
    let mut sig = if fault == "pkcx" {
        b"BAD!".to_vec()
    } else {
        b"PKCX".to_vec()
    };
    sig.extend(cms);
    p.push(part(SIG, &sig, false));
    if fault == "signature-order" {
        let sig = p.pop().unwrap();
        p.insert(0, sig);
    }
    if fault == "duplicate" {
        p.insert(0, p[0].clone());
    }
    if fault == "path" {
        p[0].name = "../data.bin".into();
    }
    zip(&p, z64, dd).0
}

fn bundle(dir: &std::path::Path, fault: &str, hash: crypto::Hash) -> Vec<u8> {
    let mut child = match fault {
        "rfc3161" | "countersignature" => package(dir, fault, hash),
        "child-timestamp" => package(dir, "timestamp-imprint", hash),
        "child-signature" => package(dir, "cms-signature", hash),
        "child-unsigned" => zip(&parts("", hash), false, false).0,
        "external" | "different-signer" => {
            std::fs::read(dir.join("appx-independent-jsign.msix")).unwrap()
        }
        "nested-bundle" => bundle(dir, "", hash),
        "name" => package(dir, "other-name", hash),
        "resource" | "resource-id" | "resource-type" => package(dir, "resource", hash),
        "resource-boolean" => package(dir, "resource-boolean", hash),
        "architecture-default" | "multi" => package(dir, "x64", hash),
        _ => package(dir, "", hash),
    };
    if fault == "child-digest" {
        child[38] ^= 1;
    }
    let filename = if fault == "multi" {
        "x64.appx"
    } else {
        "neutral.appx"
    };
    let offset = 30 + filename.len() + usize::from(fault == "offset");
    let size = child.len() + usize::from(fault == "size");
    let publisher = if fault == "external" {
        "CN=rssig independent MSI test signer"
    } else if fault == "publisher" {
        "CN=other publisher"
    } else {
        "CN=rssig test publisher"
    };
    let architecture = if ["architecture", "multi"].contains(&fault) {
        "x64"
    } else {
        "neutral"
    };
    let version = if fault == "version" {
        "2.0.0.0"
    } else {
        "1.0.0.0"
    };
    let mut entry = format!(
        "<Package Type=\"application\" Version=\"{version}\" Architecture=\"{architecture}\" FileName=\"{filename}\" Offset=\"{offset}\" Size=\"{size}\"/>"
    );
    if ["resource", "resource-id", "resource-boolean"].contains(&fault) {
        entry = entry.replace(
            "Type=\"application\"",
            "Type=\"resource\" ResourceId=\"en-us\"",
        );
    }
    if fault == "resource-id" {
        entry = entry.replace("ResourceId=\"en-us\"", "ResourceId=\"fr-fr\"");
    }
    if fault == "architecture-default" {
        entry = entry.replace(" Architecture=\"neutral\"", "");
    }
    if fault == "package-child" {
        entry = entry.replace("/>", "><Unknown/></Package>");
    }
    if fault == "schema5" {
        entry = entry.replace("/>", "><Resources><Resource Language=\"en-us\"/></Resources><b4:Dependencies><b4:TargetDeviceFamily Name=\"Windows.Desktop\" MinVersion=\"10.0.17763.0\" MaxVersionTested=\"10.0.22000.1\"/></b4:Dependencies></Package>");
    }
    let mut entries = entry.clone();
    if fault == "duplicate" {
        entries.push_str(&entry);
    }
    if fault == "empty" {
        entries.clear();
    }
    if fault == "missing" {
        entries = entries.replace(filename, "missing.appx");
    }
    if fault == "stub" {
        entries = entries.replace("Type=", "IsStub=\"true\" Type=");
    }
    if fault == "flat" {
        entries = entries.replace(&format!("Offset=\"{offset}\""), "Offset=\"0\"");
    }
    let mut p = vec![part(filename, &child, fault == "compressed")];
    if fault == "child-crc" {
        p[0].bad_crc = true;
    }
    if fault == "orphan-other" {
        p.push(part("orphan.bin", b"extra", false));
    }
    if fault == "orphan" {
        p.push(part("orphan.appx", &child, false));
    }
    if fault == "multi" {
        let name = "arm64.msix";
        let second = package(dir, "arm64", hash);
        let offset = 30 + filename.len() + child.len() + 30 + name.len();
        entries.push_str(&format!("<Package Type=\"application\" Version=\"1.0.0.0\" Architecture=\"arm64\" FileName=\"{name}\" Offset=\"{offset}\" Size=\"{}\"/>",second.len()));
        p.push(part(name, &second, false));
    }
    let mut manifest = format!(
        "<Bundle xmlns=\"http://schemas.microsoft.com/appx/2013/bundle\" SchemaVersion=\"1.0\"><Identity Name=\"rssig.test\" Publisher=\"{publisher}\" Version=\"1.0.0.0\"/><Packages>{entries}</Packages></Bundle>"
    );
    if fault == "namespace" {
        manifest = manifest.replace("appx/2013/bundle", "appx/2099/bundle");
    }
    if fault == "unknown" {
        manifest = manifest.replace("</Bundle>", "<Unknown/></Bundle>");
    }
    if fault == "schema5" {
        manifest = manifest.replace("SchemaVersion=\"1.0\"", "SchemaVersion=\"5.0\" IgnorableNamespaces=\"b4\" xmlns:b4=\"http://schemas.microsoft.com/appx/2018/bundle\"");
    }
    p.push(part(BUNDLE_MANIFEST, manifest.as_bytes(), false));
    let mut map = block_map(&p, hash, true);
    if fault == "block-hash" {
        let at = map.find("Hash=\"").unwrap() + 6;
        map.replace_range(at..at + 1, if &map[at..at + 1] == "A" { "B" } else { "A" });
    }
    p.push(part(BM, map.as_bytes(), false));
    let mut ct = format!(
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"appx\" ContentType=\"application/vnd.ms-appx\"/><Default Extension=\"msix\" ContentType=\"application/vnd.ms-appx\"/><Default Extension=\"xml\" ContentType=\"application/vnd.ms-appx.manifest+xml\"/><Override PartName=\"/{BUNDLE_MANIFEST}\" ContentType=\"application/vnd.ms-appx.bundlemanifest+xml\"/><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/><Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/></Types>"
    );
    if fault == "content-types" {
        ct = ct.replace(
            "application/vnd.ms-appx.bundlemanifest+xml",
            "application/other",
        );
    }
    if fault == "package-ctype" {
        ct = ct.replace(
            "ContentType=\"application/vnd.ms-appx\"",
            "ContentType=\"application/other\"",
        );
    }
    if fault == "orphan-other" {
        ct = ct.replace(
            "</Types>",
            "<Default Extension=\"bin\" ContentType=\"application/octet-stream\"/></Types>",
        );
    }
    p.push(part(CT, ct.as_bytes(), false));
    let zip64 = fault == "zip64";
    let descriptor = fault == "descriptor";
    // Streaming descriptors add 16 bytes before the second file. The package
    // data offset itself remains unchanged for the one-package fixture.
    let (unsigned, cd) = zip(&p, zip64, descriptor);
    if fault == "external" {
        return unsigned;
    }
    let mut digest_bundle = b"APPX".to_vec();
    for (tag, bytes) in [
        (b"AXPC", &unsigned[..cd]),
        (b"AXCD", &unsigned[cd..]),
        (
            b"AXCT",
            p.iter().find(|p| p.name == CT).unwrap().data.as_slice(),
        ),
        (
            b"AXBM",
            p.iter().find(|p| p.name == BM).unwrap().data.as_slice(),
        ),
    ] {
        digest_bundle.extend(tag);
        digest_bundle.extend(hash.digest(bytes));
    }
    let signed_content = content(hash, &digest_bundle, fault != "sip");
    let si = signer_info(
        identity(),
        der::one(&signed_content, 0x30).unwrap().body,
        Some(cms::INDIRECT),
        vec![],
        vec![],
    );
    let cms = if ["rfc3161", "countersignature"].contains(&fault) {
        let name = if fault == "rfc3161" {
            "good-rfc3161.exe"
        } else {
            "good-countersignature.exe"
        };
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let pe = pe::Pe::parse(&bytes).unwrap();
        msi_fixtures::convert_cms(pe.certificates().unwrap()[0], &signed_content)
    } else {
        signed_data(identity(), signed_content, cms::INDIRECT, si)
    };
    let mut signature = b"PKCX".to_vec();
    signature.extend(cms);
    p.push(part(SIG, &signature, false));
    zip(&p, zip64, descriptor).0
}
pub(super) fn write(dir: &std::path::Path) {
    let write = |name: &str, b: &[u8]| std::fs::write(dir.join(name), b).unwrap();
    let good = package(dir, "", crypto::Hash::Sha256);
    write("good.msix", &good);
    write("good.appx", &good);
    write("good.appxbundle", &bundle(dir, "", crypto::Hash::Sha256));
    write("good.msixbundle", &bundle(dir, "", crypto::Hash::Sha256));
    for fault in [
        "multi",
        "zip64",
        "descriptor",
        "schema5",
        "resource",
        "rfc3161",
        "countersignature",
    ] {
        write(
            &format!("good-appxbundle-{fault}.msixbundle"),
            &bundle(dir, fault, crypto::Hash::Sha256),
        );
    }
    for fault in [
        "resource-boolean",
        "child-timestamp",
        "child-crc",
        "orphan-other",
        "resource-id",
        "resource-type",
        "architecture-default",
        "package-child",
        "package-ctype",
        "offset",
        "size",
        "duplicate",
        "missing",
        "orphan",
        "publisher",
        "architecture",
        "version",
        "name",
        "namespace",
        "unknown",
        "empty",
        "compressed",
        "child-digest",
        "child-signature",
        "child-unsigned",
        "different-signer",
        "nested-bundle",
        "block-hash",
        "content-types",
        "stub",
        "flat",
        "sip",
    ] {
        write(
            &format!("bad-appxbundle-{fault}.msixbundle"),
            &bundle(dir, fault, crypto::Hash::Sha256),
        );
    }
    write(
        "appxbundle-jsign-input.msixbundle",
        &bundle(dir, "external", crypto::Hash::Sha256),
    );
    for (name, hash) in [
        ("sha384", crypto::Hash::Sha384),
        ("sha512", crypto::Hash::Sha512),
    ] {
        write(
            &format!("good-appxbundle-{name}.msixbundle"),
            &bundle(dir, "", hash),
        );
    }
    write("appx-misnamed.bin", &good);
    for fault in [
        "zip64",
        "descriptor",
        "deflate",
        "multi",
        "empty",
        "catalog",
        "nested",
        "rfc3161",
        "countersignature",
    ] {
        write(
            &format!("good-appx-{fault}.msix"),
            &package(dir, fault, crypto::Hash::Sha256),
        );
    }
    for fault in [
        "publisher",
        "block-hash",
        "compressed-size",
        "block-missing",
        "block-extra",
        "lfh",
        "dtd",
        "namespace",
        "block-algorithm",
        "content-types",
        "bundle",
        "cms-signature",
        "cms-trailing",
        "pkcx",
        "signature-order",
        "duplicate",
        "path",
        "timestamp-imprint",
        "digest-AXPC",
        "digest-AXCD",
        "digest-AXCT",
        "digest-AXBM",
    ] {
        write(
            &format!("bad-appx-{fault}.msix"),
            &package(dir, fault, crypto::Hash::Sha256),
        );
    }
    for (name, h) in [
        ("good-appx-sha384.msix", crypto::Hash::Sha384),
        ("good-appx-sha512.msix", crypto::Hash::Sha512),
    ] {
        write(name, &package(dir, "", h));
    }
    let mut b = good.clone();
    b[38] ^= 1;
    write("bad-appx-payload.msix", &b);
    let mut b = good.clone();
    b.push(0);
    write("bad-appx-trailing.msix", &b);
    write("bad-appx-truncated.msix", &good[..100]);
    let p = parts("", crypto::Hash::Sha256);
    write("unsigned.msix", &zip(&p, false, false).0);
    write(
        "appx-jsign-input.msix",
        &zip(&parts("external", crypto::Hash::Sha256), false, false).0,
    );
}
