use rssig::{
    cli,
    domain::{CommandReport, FileResult, VerificationBundle},
};
use serde_json::Value;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

pub struct Output {
    pub exit_code: u8,
    pub json: Value,
    report: CommandReport<FileResult>,
}

impl Output {
    pub fn success(&self) -> &VerificationBundle {
        match &self.report.results[0] {
            FileResult::Success(result) => &result.verification,
            FileResult::Failure(failure) => {
                panic!("expected verification success: {}", failure.error)
            }
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

pub fn run_fixture(input: &str, arguments: &[&str]) -> Output {
    let mut args = vec![OsString::from("rssig")];
    args.extend(arguments.iter().map(|s| match s.strip_prefix("fixtures/") {
        Some(name) => fixture(name).into_os_string(),
        None => OsString::from(s),
    }));
    args.push(fixture(input).into_os_string());
    let mut stdout = Vec::new();
    let exit_code = cli::run(args, &mut stdout).unwrap();
    assert!(stdout.ends_with(b"\n"));
    let json: Value = serde_json::from_slice(&stdout).expect("exactly one JSON document");
    // The public domain types must deserialize every verification/argument result.
    let report: CommandReport<FileResult> = serde_json::from_value(json.clone()).unwrap();
    Output {
        exit_code,
        json,
        report,
    }
}

pub fn expect_command_error(input: &str, arguments: &[&str], fragment: &str) {
    let mut args = vec![OsString::from("rssig")];
    args.extend(arguments.iter().map(OsString::from));
    args.push(fixture(input).into_os_string());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        cli::run_with_writers(args, &mut stdout, &mut stderr).unwrap(),
        2
    );
    assert!(stdout.is_empty());
    assert!(serde_json::from_slice::<Value>(&stderr).is_err());
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.starts_with("error:"));
    assert!(text.contains(fragment));
}

pub fn expect_success(output: &Output) {
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.json["schema_version"], 1);
    assert_eq!(output.json["command"], "verify");
    assert_eq!(output.json["ok"], true);
    assert_eq!(output.json["results"].as_array().unwrap().len(), 1);
    assert_eq!(output.json["results"][0]["ok"], true);
    assert!(output.json.get("type").is_none());
    assert!(output.json.get("error").is_none());
}

pub fn expect_failure(
    output: &Output,
    exit: u8,
    code: &str,
    title: &str,
    stage: Option<&str>,
    fragment: Option<&str>,
) {
    assert_eq!(output.exit_code, exit);
    assert_eq!(output.json["schema_version"], 1);
    assert_eq!(
        output.json["command"],
        if code == "invalid_arguments" {
            "arguments"
        } else {
            "verify"
        }
    );
    assert_eq!(output.json["ok"], false);
    let error = if let Some(error) = output.json.get("error") {
        assert!(output.json["results"].as_array().unwrap().is_empty());
        error
    } else {
        assert_eq!(output.json["results"].as_array().unwrap().len(), 1);
        assert_eq!(output.json["results"][0]["ok"], false);
        &output.json["results"][0]["error"]
    };
    assert_eq!(error["code"], code);
    assert_eq!(error["title"], title);
    assert_eq!(
        error["type"],
        format!("https://github.com/goatwu1993/rssig/blob/main/docs/problems.md#{code}")
    );
    for field in ["type", "title", "detail"] {
        assert_eq!(output.json[field], error[field]);
    }
    assert_eq!(error["detail"], error["message"]);
    assert!(error["detail"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(error.get("status").is_none());
    assert!(output.json.get("status").is_none());
    if let Some(stage) = stage {
        assert_eq!(error["stage"], stage);
    }
    if let Some(fragment) = fragment {
        assert!(
            error["detail"].as_str().unwrap().contains(fragment),
            "expected {fragment:?}, got {}",
            error["detail"]
        );
    }
}
pub const TRUSTED_NO_REVOCATION: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--no-revocation",
    "--time",
    "1800000000",
];
pub const INTEGRITY: &[&str] = &["verify", "--integrity-only", "--time", "1800000000"];
pub const TRUSTED: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--crl",
    "fixtures/good.crl",
    "--time",
    "1800000000",
];
pub const AFTER_CERTIFICATE_EXPIRY: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--no-revocation",
    "--time",
    "1800020000",
];
pub const REVOKED: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--crl",
    "fixtures/revoked.crl",
    "--time",
    "1800000000",
];
pub const EXPIRED_CRL: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--crl",
    "fixtures/expired.crl",
    "--time",
    "1800000000",
];
pub const FORGED_CRL: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--crl",
    "fixtures/forged.crl",
    "--time",
    "1800000000",
];
pub const UNRELATED_ROOT: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/unrelated-root.der",
    "--no-revocation",
    "--time",
    "1800000000",
];
pub const MISSING_CRL_POLICY: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--time",
    "1800000000",
];
pub const INVALID_TIME: &[&str] = &["verify", "--integrity-only", "--time", "invalid"];
pub const INTERMEDIATE_CRLS: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--crl",
    "fixtures/good.crl",
    "--crl",
    "fixtures/good-intermediate.crl",
    "--time",
    "1800000000",
];
pub const FUTURE_CRL: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--crl",
    "fixtures/bad-crl-not-yet-valid.crl",
    "--time",
    "1800000000",
];
pub const ALLOW_SHA1_TRUSTED: &[&str] = &[
    "verify",
    "--no-system-roots",
    "--roots",
    "fixtures/root.der",
    "--crl",
    "fixtures/good.crl",
    "--time",
    "1800000000",
    "--allow-sha1",
];
pub const ALLOW_SHA1_INTEGRITY: &[&str] = &[
    "verify",
    "--integrity-only",
    "--time",
    "1800000000",
    "--allow-sha1",
];
