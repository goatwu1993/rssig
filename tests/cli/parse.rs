//! The parse command reports untrusted structure, independently of verification policy.
use rssig::{
    VerifyOptions, cli,
    domain::ErrorCode,
    parse::{Pe, SignedData},
};
use serde_json::Value;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}
fn invoke(files: &[&str], flags: &[&str]) -> (u8, Value) {
    let mut argv: Vec<OsString> = ["rssig", "parse"]
        .into_iter()
        .chain(flags.iter().copied())
        .map(Into::into)
        .collect();
    argv.extend(files.iter().map(|name| fixture(name).into_os_string()));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = cli::run_with_writers(argv, &mut stdout, &mut stderr).unwrap();
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    (
        exit,
        serde_json::from_slice(&stdout).expect("exactly one JSON document"),
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn parse_pe_reports_metadata_without_verifying_tampered_images_or_signatures() {
    for (name, error) in [
        ("good-pe64.exe", None),
        ("bad-image-digest.exe", Some(ErrorCode::ImageDigestMismatch)),
        ("bad-cms-signature.exe", Some(ErrorCode::InvalidSignature)),
    ] {
        let (exit, json) = invoke(&[name], &[]);
        assert_eq!(exit, 0);
        assert_eq!(json["command"], "parse");
        assert_eq!(json["ok"], true);
        let result = &json["results"][0];
        assert_eq!(result["file"], fixture(name).to_str().unwrap());
        assert_eq!(result["format"], "pe");
        assert_eq!(result["verification_performed"], false);
        assert_eq!(result["signatures"].as_array().unwrap().len(), 1);
        let cms = &result["signatures"][0];
        assert_eq!(cms["version_der"], "020101");
        assert_eq!(cms["content_type"], "1.3.6.1.4.1.311.2.1.4");
        assert_eq!(
            cms["digest_algorithms"],
            serde_json::json!([{"oid":"2.16.840.1.101.3.4.2.1", "der":"300d06096086480165030402010500", "parameters_der":"0500"}])
        );
        assert_eq!(cms["revocation_choices_der"], serde_json::json!([]));
        assert_eq!(cms["certificate_choices"].as_array().unwrap().len(), 2);
        assert_eq!(
            cms["certificate_choices"][0]["certificate"]["subject"]["common_names"],
            serde_json::json!(["rssig test publisher"])
        );
        for key in [
            "chain_trusted",
            "revocation_checked",
            "timestamp_verification",
            "trust",
            "image_digest",
        ] {
            assert!(cms.get(key).is_none(), "parse must not manufacture {key}");
        }
        assert!(result.get("validation_time").is_none());
        let bytes = std::fs::read(fixture(name)).unwrap();
        let pe = Pe::parse(&bytes).unwrap();
        let signatures = pe.signatures().unwrap();
        let parsed = SignedData::parse(signatures[0]).unwrap();
        assert_eq!(cms["content_der"], hex(parsed.content_der().unwrap()));
        assert_eq!(
            cms["signer_infos_der"],
            serde_json::json!(
                parsed
                    .signer_infos()
                    .iter()
                    .copied()
                    .map(hex)
                    .collect::<Vec<_>>()
            )
        );
        for (reported, certificate) in cms["certificate_choices"]
            .as_array()
            .unwrap()
            .iter()
            .zip(parsed.certificate_choices())
        {
            assert_eq!(reported["der"], hex(certificate.as_der()));
            assert_eq!(reported["tag"], certificate.tag());
        }
        let options = VerifyOptions {
            trust: None,
            check_revocation: false,
            allow_sha1: false,
            now: 1800000000,
        };
        assert_eq!(
            rssig::verify_pe(&bytes, &options).err().map(|e| e.code),
            error
        );
    }
}

#[test]
fn parse_preserves_unknown_algorithms_and_opaque_certificate_choices() {
    let (exit, json) = invoke(&["parse-unknown-digest.exe"], &[]);
    assert_eq!(exit, 0);
    assert_eq!(
        json["results"][0]["signatures"][0]["digest_algorithms"][0]["oid"],
        "2.16.840.1.101.3.4.2.127"
    );
    let good = std::fs::read(fixture("good-pe64.exe")).unwrap();
    let bad = std::fs::read(fixture("parse-unknown-digest.exe")).unwrap();
    let changes: Vec<_> = good.iter().zip(&bad).filter(|(a, b)| a != b).collect();
    assert_eq!(changes, [(&1, &127)]);
    let options = VerifyOptions {
        trust: None,
        check_revocation: false,
        allow_sha1: false,
        now: 1800000000,
    };
    assert_eq!(
        rssig::verify_pe(&bad, &options).unwrap_err().code,
        ErrorCode::UnsupportedAlgorithm
    );
    let (exit, json) = invoke(&["good-pe-certificate-choice.exe"], &[]);
    assert_eq!(exit, 0);
    let choices = json["results"][0]["signatures"][0]["certificate_choices"]
        .as_array()
        .unwrap();
    assert_eq!(choices.len(), 3);
    assert_eq!(
        choices[2],
        serde_json::json!({"tag":161, "der":hex(include_bytes!("../fixtures/attribute-certificate-v1.der")), "certificate":null})
    );
}

#[test]
fn parse_standalone_cms_matches_the_embedded_envelope_and_rejects_truncation() {
    let (exit, cms) = invoke(&["parse-attached-cms.der"], &["--format", "cms"]);
    assert_eq!(exit, 0);
    let (exit, pe) = invoke(&["good-pe64.exe"], &["--format", "pe"]);
    assert_eq!(exit, 0);
    assert_eq!(cms["results"][0]["format"], "cms");
    assert_eq!(
        cms["results"][0]["signatures"],
        pe["results"][0]["signatures"]
    );
    let bytes = std::fs::read(fixture("good-pe64.exe")).unwrap();
    assert_eq!(
        Pe::parse(&bytes).unwrap().signatures().unwrap()[0],
        include_bytes!("../fixtures/parse-attached-cms.der")
    );
    let good = include_bytes!("../fixtures/parse-attached-cms.der");
    assert_eq!(
        &good[..good.len() - 1],
        include_bytes!("../fixtures/parse-truncated-cms.der")
    );
    let (exit, bad) = invoke(&["parse-truncated-cms.der"], &["--format", "cms"]);
    assert_eq!(exit, 1);
    assert_eq!(bad["results"][0]["error"]["code"], "malformed_cms");
    assert_eq!(bad["results"][0]["error"]["stage"], "cms");
}

#[test]
fn parse_preserves_each_file_result_and_primary_problem() {
    let (exit, json) = invoke(
        &[
            "good-pe64.exe",
            "bad-truncated.exe",
            "missing-parse-input.exe",
            "unsigned.exe",
        ],
        &[],
    );
    assert_eq!(exit, 1);
    assert_eq!(json["ok"], false);
    assert_eq!(json["results"].as_array().unwrap().len(), 4);
    assert_eq!(json["results"][0]["ok"], true);
    for (i, code, stage) in [
        (1, "invalid_pe", "pe"),
        (2, "read_failed", "input"),
        (3, "unsigned", "pe"),
    ] {
        assert_eq!(json["results"][i]["error"]["code"], code);
        assert_eq!(json["results"][i]["error"]["stage"], stage);
    }
    assert_eq!(json["type"], json["results"][1]["error"]["type"]);
}

#[test]
fn parse_rejects_verification_flags_and_unknown_formats_as_plain_usage_errors() {
    for flag in [
        "--roots",
        "--crl",
        "--time",
        "--no-system-roots",
        "--no-revocation",
        "--integrity-only",
        "--allow-sha1",
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit =
            cli::run_with_writers(["rssig", "parse", flag, "unused"], &mut stdout, &mut stderr)
                .unwrap();
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("unexpected argument")
        );
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = cli::run_with_writers(
        ["rssig", "parse", "--format", "msi", "unused"],
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert!(String::from_utf8(stderr).unwrap().contains("invalid value"));
}

#[test]
fn parse_results_roundtrip_through_public_domain_types() {
    let (_, json) = invoke(
        &["good-pe-certificate-choice.exe", "bad-truncated.exe"],
        &[],
    );
    let report: rssig::domain::CommandReport<rssig::domain::ParseFileResult> =
        serde_json::from_value(json.clone()).unwrap();
    match &report.results[0] {
        rssig::domain::ParseFileResult::Success(success) => {
            assert!(!success.parse.verification_performed);
            assert!(
                success.parse.signatures[0].certificate_choices[2]
                    .certificate
                    .is_none()
            );
        }
        _ => panic!("expected inspection metadata"),
    }
    match &report.results[1] {
        rssig::domain::ParseFileResult::Failure(failure) => {
            assert_eq!(failure.error.code, ErrorCode::InvalidPe)
        }
        _ => panic!("expected typed parse error"),
    }
    assert_eq!(serde_json::to_value(report).unwrap(), json);
}

#[test]
fn parse_returns_writer_failures_without_panicking() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let args = [
        OsString::from("rssig"),
        "parse".into(),
        fixture("good-pe64.exe").into_os_string(),
    ];
    assert_eq!(
        cli::run(args, Broken).unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[test]
fn parse_rejects_maximum_pe_header_offset_with_a_typed_error() {
    let (exit, json) = invoke(&["bad-pe-header-offset.exe"], &[]);
    assert_eq!(exit, 1);
    let error = &json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_pe");
    assert_eq!(error["stage"], "pe");
    assert_eq!(error["message"], "invalid PE signature");
    assert_eq!(error["causes"], serde_json::json!(["invalid PE signature"]));
    let bytes = include_bytes!("../fixtures/bad-pe-header-offset.exe");
    let mut original = include_bytes!("../fixtures/good-pe64.exe").to_vec();
    original[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(bytes.as_slice(), original);

    let mut stdout = Vec::new();
    let path = fixture("bad-pe-header-offset.exe");
    let exit = cli::run(
        [
            "rssig",
            "verify",
            "--integrity-only",
            "--time",
            "1800000000",
            path.to_str().unwrap(),
        ],
        &mut stdout,
    )
    .unwrap();
    assert_eq!(exit, 1);
    let verified: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(verified["results"][0]["error"], *error);
}

#[test]
fn parse_rejects_forbidden_der_end_of_contents() {
    let (exit, json) = invoke(&["bad-cms-eoc-parameter.der"], &["--format", "cms"]);
    assert_eq!(exit, 1);
    assert_eq!(json["results"][0]["error"]["code"], "malformed_cms");
    assert_eq!(json["results"][0]["error"]["stage"], "cms");
}

#[test]
fn parse_cms_preserves_opaque_signers_for_structured_inspection() {
    for name in [
        "parse-signer-views.der",
        "parse-signer-bad-signature-tag.der",
    ] {
        let (exit, json) = invoke(&[name], &["--format", "cms"]);
        assert_eq!(exit, 0);
        assert_eq!(json["results"][0]["verification_performed"], false);
        let cms = &json["results"][0]["signatures"][0];
        assert_eq!(cms["content_type"], "1.2.3.7");
        assert_eq!(cms["content_der"], "040568656c6c6f");
        assert_eq!(cms["signer_infos_der"].as_array().unwrap().len(), 2);
        let _: rssig::domain::CommandReport<rssig::domain::ParseFileResult> =
            serde_json::from_value(json).unwrap();
    }
}

#[test]
fn verification_preserves_long_unknown_attribute_oids_and_rejects_bad_encoding() {
    use super::support::{TRUSTED, expect_failure, expect_success, run_fixture};
    expect_success(&run_fixture("good-long-attribute-oid.exe", TRUSTED));
    expect_failure(
        &run_fixture("bad-long-attribute-oid.exe", TRUSTED),
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("invalid CMS attribute OID"),
    );
}
